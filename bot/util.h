#ifndef _UTIL_H
#define _UTIL_H

#include "includes.h"

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================
 * String: strlen, strcmp, strncmp, strcpy, strcat, memcpy, zero
 * Number: atoi, itoa
 * Search: memsearch, stristr (case-insensitive)
 * Network: local_addr, fdgets, socket_and_bind
 * ============================================================================ */

/* String utilities */
int util_strlen(char *);
int util_strcmp(char *, char *);
int util_strncmp(char *, char *, int);
char *util_strcpy(char *, char *);
char *util_strcat(char *, char *);
void *util_memcpy(void *, void *, int);
void util_zero(void *, int);

/* Number conversion */
int util_atoi(char *);
char *util_itoa(int, char *);

/* Formatted output */
int util_sprintf(char *, const char *, ...);

/* Search functions */
int util_memsearch(char *, int, char *, int);
char *util_stristr(char *, int, char *);

/* Network utilities */
ipv4_t util_local_addr(void);
int util_fdgets(char *, int, int);

/* Socket utilities */
int util_socket_and_bind(char *bind_addr);

/* URL parsing - extracts domain, path, port from URL */
/* Returns: 0 = HTTP (port 80), 1 = HTTPS (port 443), -1 = error */
int util_parse_url(char *url, char *domain, int domain_max, char *path, int path_max, int *port);

#endif
