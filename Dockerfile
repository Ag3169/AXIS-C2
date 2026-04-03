# ============================================================================
# AXIS 3.0 - Docker Build Environment
# ============================================================================
# Fully self-contained build environment with all 13 cross-compilers.
# Usage:
#   docker build -t axis3-builder .
#   docker run -v $(pwd):/workspace axis3-builder ./build.sh
# ============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GOROOT=/usr/local/go
ENV GOPATH=/root/go
ENV PATH=$GOROOT/bin:$GOPATH/bin:$PATH

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install all cross-compilers for 13 architectures
RUN apt-get update && apt-get install -y --no-install-recommends \
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
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN curl -fsSL https://go.dev/dl/go1.21.0.linux-amd64.tar.gz | tar -C /usr/local -xz

# Set up workspace
WORKDIR /workspace

# Default command
CMD ["./build.sh"]
