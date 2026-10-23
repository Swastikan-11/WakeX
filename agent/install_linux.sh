#!/usr/bin/env bash
# WakeX Linux Agent Installer (Ubuntu / Debian / Arch / Fedora)
set -e

echo "=================================================="
echo "         WakeX Linux Agent Installer              "
echo "=================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./install_linux.sh)"
  exit 1
fi

INSTALL_DIR="/opt/wakex-agent"
mkdir -p "$INSTALL_DIR"

echo "[+] Copying agent files to $INSTALL_DIR..."
cp wakex_agent.py "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/wakex_agent.py"

echo "[+] Installing systemd service..."
cp wakex-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable wakex-agent.service
systemctl restart wakex-agent.service

echo "[+] Generating initial pairing token..."
python3 "$INSTALL_DIR/wakex_agent.py" --pair

echo "[✓] WakeX Linux Agent installed and running 24/7!"
echo "    Check status with: systemctl status wakex-agent"
