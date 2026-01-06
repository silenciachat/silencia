#!/bin/bash
# Test Silencia compilation across different Linux distributions

set -e

echo "========================================="
echo "Silencia Cross-Platform Compilation Test"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to test a distro
test_distro() {
    local distro=$1
    local image=$2
    local install_cmd=$3
    
    echo -e "${YELLOW}Testing: $distro${NC}"
    echo "----------------------------------------"
    
    docker run --rm -v "$(pwd):/silencia" -w /silencia "$image" bash -c "
        set -e
        echo '1. Installing build dependencies...'
        $install_cmd
        
        echo '2. Checking Rust version...'
        rustc --version || (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source \$HOME/.cargo/env && rustc --version)
        
        echo '3. Building Silencia...'
        cargo build --release --bin silencia 2>&1 | tail -20
        
        echo '4. Checking binary...'
        ls -lh target/release/silencia
        file target/release/silencia
        
        echo '5. Testing binary...'
        ./target/release/silencia --version || ./target/release/silencia --help | head -5
        
        echo '✓ Build successful!'
    " && echo -e "${GREEN}✓ $distro: PASSED${NC}" || echo -e "${RED}✗ $distro: FAILED${NC}"
    
    echo ""
}

# Test different distributions
echo "Testing compilation across Linux distributions..."
echo ""

# Ubuntu/Debian
test_distro "Ubuntu 22.04" "ubuntu:22.04" \
    "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl build-essential && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source \$HOME/.cargo/env"

# Fedora
test_distro "Fedora Latest" "fedora:latest" \
    "dnf install -y gcc make curl && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source \$HOME/.cargo/env"

# Alpine (musl-based)
test_distro "Alpine Linux" "alpine:latest" \
    "apk add --no-cache curl gcc musl-dev make && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source \$HOME/.cargo/env"

# Arch Linux
test_distro "Arch Linux" "archlinux:latest" \
    "pacman -Syu --noconfirm && pacman -S --noconfirm base-devel curl && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source \$HOME/.cargo/env"

# Use official Rust image (Debian-based)
echo -e "${YELLOW}Testing: Official Rust Image (Debian)${NC}"
echo "----------------------------------------"
docker run --rm -v "$(pwd):/silencia" -w /silencia rust:1.81-slim bash -c "
    apt-get update && apt-get install -y build-essential
    cargo build --release --bin silencia
    ./target/release/silencia --version || ./target/release/silencia --help | head -5
    echo '✓ Build successful!'
" && echo -e "${GREEN}✓ Rust:1.81-slim: PASSED${NC}" || echo -e "${RED}✗ Rust:1.81-slim: FAILED${NC}"

echo ""
echo "========================================="
echo "Test Summary"
echo "========================================="
echo "All tests completed. Check output above for results."
echo ""
echo "Dependencies required on all distros:"
echo "  - C compiler (gcc/clang)"
echo "  - make"
echo "  - Rust 1.75+"
echo ""
echo "No other system dependencies needed!"
