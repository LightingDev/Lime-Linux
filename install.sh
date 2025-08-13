#!/bin/bash
set -e

echo "[*] Installing Lime TUI Desktop Environment..."

# Ensure Python3 exists
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Python3 is not installed. Please install it first."
    exit 1
fi

# Ensure pip exists
if ! command -v pip3 >/dev/null 2>&1; then
    echo "[*] Installing pip..."
    sudo apt-get update 2>/dev/null || true
    sudo apt-get install -y python3-pip 2>/dev/null || true
fi

# Install dependencies
pip3 install --upgrade textual pyfiglet

# Create /opt/lime and copy Lime.py
sudo mkdir -p /opt/lime
sudo cp Lime.py /opt/lime/Lime.py
sudo chmod +x /opt/lime/Lime.py

# Install lime-session launcher
sudo cp lime-session /usr/local/bin/lime-session
sudo chmod +x /usr/local/bin/lime-session

# Install .desktop session file
sudo cp Lime.desktop /usr/share/xsessions/Lime.desktop

echo "[+] Installation complete."
echo "You can now log out and select 'Lime' in your display manager."
