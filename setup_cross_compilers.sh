#!/bin/bash
# ============================================================================
# AXIS 3.0 - Cross-Compiler Setup Script
# ============================================================================
# Automatically installs all required cross-compilers for building bots
# for 13 different architectures. Works on Ubuntu/Debian systems.
# ============================================================================

set -e

echo "=========================================="
echo "AXIS 3.0 Cross-Compiler Setup"
echo "=========================================="
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "[-] Cannot detect OS. Please install cross-compilers manually."
    exit 1
fi

echo "[*] Detected OS: $OS"
echo ""

# Install cross-compilers
echo "[*] Installing cross-compilers..."

case "$OS" in
    ubuntu|debian)
        sudo apt-get update
        sudo apt-get install -y \
            gcc-arm-linux-gnueabi \
            gcc-arm-linux-gnueabihf \
            gcc-mips-linux-gnu \
            gcc-mipsel-linux-gnu \
            gcc-i686-linux-gnu \
            gcc-x86-64-linux-gnu \
            gcc-powerpc-linux-gnu \
            gcc-sparc-linux-gnu \
            gcc-m68k-linux-gnu \
            gcc-sh4-linux-gnu \
            gcc-arc-linux-gnu \
            build-essential
        ;;
    fedora|centos|rhel)
        sudo dnf install -y \
            gcc-arm-linux-gnu \
            gcc-aarch64-linux-gnu \
            gcc-mips64-linux-gnuabi64 \
            gcc-powerpc64le-linux-gnu \
            gcc-i686-linux-gnu \
            gcc-x86_64-linux-gnu \
            @development-tools
        ;;
    arch)
        sudo pacman -Sy --noconfirm \
            arm-linux-gnueabi-gcc \
            arm-linux-gnueabihf-gcc \
            mips-linux-gnu-gcc \
            mipsel-linux-gnu-gcc \
            i686-linux-gnu-gcc \
            x86_64-linux-gnu-gcc \
            powerpc-linux-gnu-gcc \
            sparc-linux-gnu-gcc \
            m68k-linux-gnu-gcc \
            sh4-linux-gnu-gcc \
            base-devel
        ;;
    *)
        echo "[-] Unsupported OS: $OS"
        echo "    Please install cross-compilers manually for:"
        echo "    arm, armhf, mips, mipsel, x86, x86_64, ppc, sparc, m68k, sh4, arc"
        exit 1
        ;;
esac

echo ""
echo "[*] Verifying cross-compilers..."

declare -a CC_LIST=(
    "arm-linux-gnueabi-gcc"
    "arm-linux-gnueabihf-gcc"
    "mips-linux-gnu-gcc"
    "mipsel-linux-gnu-gcc"
    "i686-linux-gnu-gcc"
    "x86_64-linux-gnu-gcc"
    "powerpc-linux-gnu-gcc"
    "sparc-linux-gnu-gcc"
    "m68k-linux-gnu-gcc"
    "sh4-linux-gnu-gcc"
    "arc-linux-gnu-gcc"
)

ALL_OK=true
for cc in "${CC_LIST[@]}"; do
    if command -v "$cc" &> /dev/null; then
        echo "  [+] $cc OK"
    else
        echo "  [-] $cc MISSING"
        ALL_OK=false
    fi
done

echo ""
if $ALL_OK; then
    echo "[+] All cross-compilers installed successfully!"
    echo ""
    echo "You can now run: ./build.sh"
else
    echo "[-] Some compilers are missing. Try running:"
    echo "    sudo dpkg --add-architecture i386"
    echo "    sudo apt-get update"
    echo "    Then re-run this script."
fi
