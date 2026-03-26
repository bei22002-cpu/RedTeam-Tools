#!/bin/bash
#
# Hat Program - Installation Script
# Installs common dependencies for the Red/Black/Blue Hat cybersecurity toolkit.
#
# Usage: sudo bash install.sh
#

set -e

RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
BOLD='\033[1m'
RESET='\033[0m'

print_info()  { echo -e "${GREEN}[+]${RESET} $1"; }
print_warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
print_error() { echo -e "${RED}[-]${RESET} $1"; }
print_status(){ echo -e "${BLUE}[*]${RESET} $1"; }

echo -e "${BOLD}"
echo "=============================================="
echo "  Hat Program - Dependency Installer"
echo "=============================================="
echo -e "${RESET}"

# Check for root
if [ "$EUID" -ne 0 ]; then
    print_warn "Not running as root. Some packages may fail to install."
    print_warn "Run with: sudo bash install.sh"
    echo ""
fi

# Detect package manager
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
    UPDATE_CMD="apt-get update -qq"
    INSTALL_CMD="apt-get install -y -qq"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
    UPDATE_CMD="yum check-update || true"
    INSTALL_CMD="yum install -y"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
    UPDATE_CMD="dnf check-update || true"
    INSTALL_CMD="dnf install -y"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
    UPDATE_CMD="pacman -Sy"
    INSTALL_CMD="pacman -S --noconfirm"
else
    print_error "No supported package manager found (apt, yum, dnf, pacman)."
    exit 1
fi

print_info "Detected package manager: $PKG_MGR"

# Check Python 3
if command -v python3 &>/dev/null; then
    PYTHON_VER=$(python3 --version 2>&1)
    print_info "Python found: $PYTHON_VER"
else
    print_error "Python 3 is required but not found."
    print_status "Installing Python 3..."
    $INSTALL_CMD python3
fi

# Update package lists
print_status "Updating package lists..."
$UPDATE_CMD 2>/dev/null

# ============================================
# Core networking tools
# ============================================
print_status "Installing core networking tools..."
CORE_TOOLS=(
    curl
    wget
    net-tools
    dnsutils
    whois
    traceroute
    openssl
    iproute2
    iputils-ping
)

for tool in "${CORE_TOOLS[@]}"; do
    if $INSTALL_CMD "$tool" 2>/dev/null; then
        print_info "Installed: $tool"
    else
        print_warn "Could not install: $tool (may already be installed or unavailable)"
    fi
done

# ============================================
# Security scanning tools
# ============================================
print_status "Installing security scanning tools..."
SCAN_TOOLS=(
    nmap
    tcpdump
    netcat-openbsd
)

for tool in "${SCAN_TOOLS[@]}"; do
    if $INSTALL_CMD "$tool" 2>/dev/null; then
        print_info "Installed: $tool"
    else
        print_warn "Could not install: $tool"
    fi
done

# ============================================
# Blue team / defensive tools
# ============================================
print_status "Installing defensive security tools..."
BLUE_TOOLS=(
    ufw
    fail2ban
    rkhunter
    chkrootkit
    clamav
    auditd
    lynis
)

for tool in "${BLUE_TOOLS[@]}"; do
    if $INSTALL_CMD "$tool" 2>/dev/null; then
        print_info "Installed: $tool"
    else
        print_warn "Could not install: $tool"
    fi
done

# ============================================
# Forensics / analysis tools
# ============================================
print_status "Installing forensics tools..."
FORENSIC_TOOLS=(
    binwalk
    foremost
    steghide
    libimage-exiftool-perl
    hexedit
)

for tool in "${FORENSIC_TOOLS[@]}"; do
    if $INSTALL_CMD "$tool" 2>/dev/null; then
        print_info "Installed: $tool"
    else
        print_warn "Could not install: $tool"
    fi
done

# ============================================
# Make hat_program.py executable
# ============================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/hat_program.py" ]; then
    chmod +x "$SCRIPT_DIR/hat_program.py"
    print_info "Made hat_program.py executable"
fi

# ============================================
# Summary
# ============================================
echo ""
echo -e "${BOLD}=============================================="
echo "  Installation Complete!"
echo "=============================================="
echo -e "${RESET}"
print_info "Run the program with:"
echo -e "    ${BOLD}python3 $SCRIPT_DIR/hat_program.py${RESET}"
echo ""
print_info "For full functionality, run as root:"
echo -e "    ${BOLD}sudo python3 $SCRIPT_DIR/hat_program.py${RESET}"
echo ""
print_warn "Remember: Only use these tools in authorized environments."
echo ""
