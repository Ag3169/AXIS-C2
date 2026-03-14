#ifndef _LOADER_INCLUDES_H
#define _LOADER_INCLUDES_H

/* ============================================================================
 * AXIS 2.0 Loader - Common Include Header
 * ============================================================================
 * Standard library includes for loader modules
 * Features: epoll-based event loop, pthread concurrency
 * Connection limit: 65536 concurrent telnet sessions
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>

#include "config.h"

/* Boolean types */
#ifndef BOOL
#define BOOL int
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#endif
