#ifndef _INCLUDES_H
#define _INCLUDES_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/sockios.h>

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#ifndef BOOL
#define BOOL int
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define LOCAL_ADDR (util_local_addr())
#define LOCAAL_ADDR(x) (((uint8_t *)&(x))[0])
#define LOCAAL_ADDR_1(x) (((uint8_t *)&(x))[1])
#define LOCAAL_ADDR_2(x) (((uint8_t *)&(x))[2])
#define LOCAAL_ADDR_3(x) (((uint8_t *)&(x))[3])
#define INET_ADDR(o1,o2,o3,o4) (htonl(((o1 << 24) | (o2 << 16) | (o3 << 8) | o4)))

#define STDIN 0
#define STDOUT 1
#define STDERR 2

#include "config.h"

#endif
