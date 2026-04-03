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

static int xsocket(int domain, int type, int protocol) {
