#!/usr/bin/env bash

# Script to upgrade Linux - APT
# Update, Upgrade and Autoremove
# Requires SUDO passwd if script not run as SUDO.
# Looking for a fix to make script unattended but may require permission to  # restart some services during upgrade

set -euo pipefail

echo "===================================="
echo "Linux APT Upgrade Script"
echo "===================================="

# If not running as root, authenticate with sudo once.
if [[ $EUID -ne 0 ]]; then
    echo "Requesting administrator privileges..."
    sudo -v

    # Keep sudo alive while the script runs.
    while true; do
        sudo -n true
        sleep 60
        kill -0 "$$" || exit
    done 2>/dev/null &
    SUDO="sudo"
else
    SUDO=""
fi

echo
echo "[1/3] Updating package lists..."
$SUDO apt update

echo
echo "[2/3] Performing full system upgrade..."
$SUDO apt full-upgrade -y

echo
echo "[3/3] Removing unused packages..."
$SUDO apt autoremove -y

echo
echo "======================================"
echo "System upgrade completed successfully."
echo "======================================"
