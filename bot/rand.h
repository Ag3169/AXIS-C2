#ifndef _RAND_H
#define _RAND_H

#include "includes.h"

/* ============================================================================
 * RANDOM NUMBER GENERATOR
 * ============================================================================
 * Custom PRNG using xorshift algorithm
 * Seeded from: time(), PID, PPID, clock()
 * Functions: rand_next(), rand_str(), rand_alpha_str()
 * ============================================================================ */

void rand_init(void);
uint32_t rand_next(void);
void rand_str(char *, int);
void rand_alpha_str(char *, int);

#endif
