#!/usr/bin/env bash
# NoirSec Setup Script
#
# IMPORTANT: On Windows, run this inside WSL (Windows Subsystem for Linux).
# nargo does not provide native Windows binaries — WSL is required.
# See: https://noir-lang.org/docs/getting_started/noir_installation
#
# Usage: bash scripts/setup.sh

set -e

echo "============================================"
echo " NoirSec Setup"
echo "============================================"
echo ""

# Check if running on Windows without WSL
if [[ "$(uname -s)" == *"MINGW"* ]] || [[ "$(uname -s)" == *"CYGWIN"* ]]; then
    echo "ERROR: Native Windows shell detected."
    echo "Please run this script inside WSL (Windows Subsystem for Linux)."
    echo "  1. Install WSL: wsl --install"
    echo "  2. Open WSL terminal"
    echo "  3. Navigate to this repo: cd /mnt/d/projects/noir-sec"
    echo "  4. Run: bash scripts/setup.sh"
    exit 1
fi

# Install noirup (Noir version manager)
echo "[1/3] Installing noirup..."
if command -v noirup &>/dev/null; then
    echo "  noirup already installed, skipping."
else
    curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
    # Source the updated profile
    if [ -f "$HOME/.bashrc" ]; then source "$HOME/.bashrc" 2>/dev/null || true; fi
    if [ -f "$HOME/.zshrc" ]; then source "$HOME/.zshrc" 2>/dev/null || true; fi
    export PATH="$HOME/.nargo/bin:$PATH"
fi

# Install latest stable nargo
echo ""
echo "[2/3] Installing latest nargo via noirup..."
noirup

# Verify installation
echo ""
echo "[3/3] Verifying installation..."
if command -v nargo &>/dev/null; then
    nargo --version
    echo ""
    echo "Setup complete!"
    echo ""
    echo "Next steps:"
    echo "  - Run 'bash scripts/verify_all.sh' to compile all circuits"
    echo "  - Browse vulnerabilities/ to explore challenges"
    echo "  - Run exploit scripts: bash vulnerabilities/.../exploit/exploit.sh"
else
    echo ""
    echo "WARNING: nargo not found in PATH after installation."
    echo "Try: export PATH=\"\$HOME/.nargo/bin:\$PATH\""
    echo "Then run: nargo --version"
fi
