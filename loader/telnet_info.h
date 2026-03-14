#ifndef _LOADER_TELNET_INFO_H
#define _LOADER_TELNET_INFO_H

/* ============================================================================
 * TELNET INFO MODULE - Credential Storage
 * ============================================================================
 * Stores parsed telnet credentials
 * Fields: host, port, username, password, architecture
 * Parsed from: IP:PORT username:password [arch] format
 * ============================================================================ */

#include "includes.h"

struct telnet_info {
    char host[32];
    int port;
    char user[64];
    char pass[64];
    char arch[32];
};

struct telnet_info *telnet_info_parse(char *);
struct telnet_info *telnet_info_new(char *, int, char *, char *, char *);

#endif
