#ifndef _RESOLV_H
#define _RESOLV_H

#include "includes.h"

/* ============================================================================
 * DNS RESOLVER MODULE
 * ============================================================================
 * Resolves domain names to IP addresses
 * Uses Google DNS (8.8.8.8) for queries
 * Supports: A record lookup, domain-to-hostname conversion
 * ============================================================================ */

#define RESOLV_MAX_ENTRIES 4

struct resolv_entries {
    uint32_t addrs[RESOLV_MAX_ENTRIES];
    int count;
};

void resolv_domain_to_hostname(char *, char *);
struct resolv_entries *resolv_lookup(char *);
void resolv_entries_free(struct resolv_entries *);

#endif
