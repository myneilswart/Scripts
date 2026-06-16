#!/bin/bash
# Extract wi-fi profiles and passwords for Linux
# Only tested in Linux VM

echo "Extracting wi-fi profiles and passwords..."

output=""

# Check for NetworkManager connections
if [ -d "/etc/NetworkManager/system-connections/" ]; then
    for file in /etc/NetworkManager/system-connections/*; do
        ssid=$(grep -m1 'ssid=' "$file" 2>/dev/null | cut -d= -f2)
        password=$(grep -m1 'psk=' "$file" 2>/dev/null | cut -d= -f2)
        if [ -n "$ssid" ]; then
            if [ -n "$password" ]; then
                output+="Profile: $ssid | Password: $password\n"
            else
                output+="Profile: $ssid | Password: Not available\n"
            fi
        fi
    done
else
    echo "NetworkManager connections folder not found. This script supports NetworkManager-based distros only."
    exit 1
fi

# Display and save output
echo -e "$output" | tee ~/Desktop/wifi.txt

echo ""
echo "Results have been saved to linux-wifi.txt on your Desktop!"