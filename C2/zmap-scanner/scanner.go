package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ZMapScanner - Fast single-packet scanner similar to ZMap
// Scans large IP ranges for open ports quickly
type ZMapScanner struct {
	workerCount int
	port        int
	results     chan ZMapResult
	running     bool
	mu          sync.Mutex
}

type ZMapResult struct {
	IP   string
	Port int
}

func NewZMapScanner(workers int, port int) *ZMapScanner {
	return &ZMapScanner{
		workerCount: workers,
		port:        port,
		results:     make(chan ZMapResult, 10000),
	}
}

func (s *ZMapScanner) Start() {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
	fmt.Printf("[ZMap] Scanner started on port %d with %d workers\n", s.port, s.workerCount)
}

func (s *ZMapScanner) Stop() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
	fmt.Println("[ZMap] Scanner stopped")
}

// ScanIPRange scans a range of IPs for the specified port
// Uses multiple workers for speed but respects rate limits
func (s *ZMapScanner) ScanIPRange(startIP, endIP string) {
	fmt.Printf("[ZMap] Scanning %s:%d to %s:%d\n", startIP, s.port, endIP, s.port)

	start := ipToInt(startIP)
	end := ipToInt(endIP)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.workerCount)

	for ip := start; ip <= end && s.isRunning(); ip++ {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(currentIP uint32) {
			defer wg.Done()
			defer func() { <-semaphore }()

			ipStr := intToIP(currentIP)
			if s.scanPort(ipStr, s.port) {
				s.results <- ZMapResult{IP: ipStr, Port: s.port}
			}

			// Rate limit to avoid overwhelming network
			time.Sleep(10 * time.Millisecond)
		}(ip)
	}

	wg.Wait()
	close(s.results)
	fmt.Println("[ZMap] Scan complete")
}

func (s *ZMapScanner) scanPort(ip string, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *ZMapScanner) GetResults() <-chan ZMapResult {
	return s.results
}

func (s *ZMapScanner) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
