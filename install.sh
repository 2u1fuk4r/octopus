#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════╗
# ║                  8PUS INSTALLER                     ║
# ║            octopus.sh dependency setup              ║
# ╚══════════════════════════════════════════════════════╝

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()     { printf "%b\n" "${CYAN}[*]${NC} $*"; }
success() { printf "%b\n" "${GREEN}[✓]${NC} $*"; }
warn()    { printf "%b\n" "${YELLOW}[!]${NC} $*"; }
error()   { printf "%b\n" "${RED}[✗]${NC} $*"; }

# Root escalation
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo -e "${YELLOW}[!] Re-running with sudo...${NC}"
  exec sudo -E bash "$0" "$@"
fi

echo ""
echo "Installing dependencies for 8PUS..."
echo ""

# ---------------- System Packages ----------------
log "Installing system packages..."
apt update -y
apt install -y git curl wget python3 python3-pip build-essential

# ---------------- Go Check ----------------
if ! command -v go >/dev/null 2>&1; then
  log "Installing Golang..."
  apt install -y golang
else
  success "Go already installed"
fi

# Ensure GOPATH bin in PATH
if ! echo "$PATH" | grep -q "$HOME/go/bin"; then
  echo 'export PATH=$PATH:$HOME/go/bin' >> "$HOME/.bashrc"
  export PATH=$PATH:$HOME/go/bin
fi

# ---------------- Go Tools ----------------
install_go_tool() {
  local pkg="$1"
  local name="$2"

  if command -v "$name" >/dev/null 2>&1; then
    success "$name already installed"
  else
    log "Installing $name..."
    go install "$pkg@latest"
    success "$name installed"
  fi
}

install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "subfinder"
install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx" "httpx"
install_go_tool "github.com/lc/gau/v2/cmd/gau" "gau"
install_go_tool "github.com/tomnomnom/waybackurls" "waybackurls"
install_go_tool "github.com/projectdiscovery/katana/cmd/katana" "katana"
install_go_tool "github.com/hahwul/dalfox/v2" "dalfox"

# ---------------- Python Dependency ----------------
log "Installing Python Excel dependency..."
pip3 install --upgrade openpyxl

# ---------------- Final Check ----------------
echo ""
echo "Verifying installation..."
echo ""

tools=(subfinder assetfinder httpx gau waybackurls katana dalfox)

for t in "${tools[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    printf "%b\n" "${GREEN}[✓]${NC} $t"
  else
    printf "%b\n" "${RED}[✗]${NC} $t (missing)"
  fi
done

echo ""
success "8PUS installation completed."
echo ""
echo "You can now run:"
echo "  bash octopus.sh -d example.com"
echo ""
