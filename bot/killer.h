#ifndef _KILLER_H
#define _KILLER_H

#include "includes.h"

/* ============================================================================
 * KILLER MODULE - Anti-Malware Protection
 * ============================================================================
 * Eliminates competing botnets by killing their processes
 * Targets: Mirai, Gafgit, Tsunami, and other IoT malware
 * Methods: Process name scanning, port monitoring, /proc analysis
 * ============================================================================ */

void killer_init(void);

#endif
