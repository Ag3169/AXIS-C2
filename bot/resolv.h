#ifndef _RESOLV_H
#define _RESOLV_H

#include "includes.h"

#define RESOLV_MAX_ENTRIES 4

struct resolv_entries {
    uint32_t addrs[RESOLV_MAX_ENTRIES];
    int count;
};

void resolv_domain_to_hostname(char *, char *);
struct resolv_entries *resolv_lookup(char *);
void resolv_entries_free(struct resolv_entries *);

#endif
