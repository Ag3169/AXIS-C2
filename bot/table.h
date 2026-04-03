#ifndef _TABLE_H
#define _TABLE_H

#include "includes.h"

#define TABLE_KEY 0xdeadbeef

#define TABLE_CNC_DOMAIN        0
#define TABLE_CNC_PORT          1
#define TABLE_SCAN_CB_PORT      2
#define TABLE_EXEC_SUCCESS      3
#define TABLE_SCAN_SHELL        4
#define TABLE_SCAN_ENABLE       5
#define TABLE_SCAN_SYSTEM       6
#define TABLE_SCAN_CREDENTIALS  7
#define TABLE_SCAN_TOKEN        8
#define TABLE_KILLER_PROC       9
#define TABLE_KILLER_EXE        10
#define TABLE_KILLER_FD         11
#define TABLE_KILLER_TCP        12
#define TABLE_ATK_VSE           13
#define TABLE_ATK_DNS           14
#define TABLE_ATK_UDP           15
#define TABLE_MISC_RAND         16
#define TABLE_MISC_WATCHDOG     17
#define TABLE_MAX_KEYS          18

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t);
char *table_retrieve_val(int, int *);

#endif
