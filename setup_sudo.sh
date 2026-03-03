#!/bin/bash

# Setup passwordless sudo for scanning tools
echo "Setting up passwordless sudo for scanning tools..."

# Create sudoers file for scanning tools
sudo tee /etc/sudoers.d/iscan-tools > /dev/null << 'EOF'
# Allow teamwork user FULL ROOT ACCESS for all scanning operations
teamwork ALL=(ALL) NOPASSWD: ALL

# Specific scanning tools with full privileges
teamwork ALL=(ALL) NOPASSWD: /usr/bin/nmap
teamwork ALL=(ALL) NOPASSWD: /usr/bin/lynis
teamwork ALL=(ALL) NOPASSWD: /usr/bin/nikto
teamwork ALL=(ALL) NOPASSWD: /usr/bin/sslyze
teamwork ALL=(ALL) NOPASSWD: /usr/bin/whatweb
teamwork ALL=(ALL) NOPASSWD: /usr/sbin/nmap
teamwork ALL=(ALL) NOPASSWD: /usr/local/bin/nmap
teamwork ALL=(ALL) NOPASSWD: /usr/local/bin/lynis
teamwork ALL=(ALL) NOPASSWD: /usr/local/bin/testssl.sh
teamwork ALL=(ALL) NOPASSWD: /snap/bin/enum4linux

# Network and system access tools
teamwork ALL=(ALL) NOPASSWD: /usr/bin/ssh
teamwork ALL=(ALL) NOPASSWD: /usr/bin/scp
teamwork ALL=(ALL) NOPASSWD: /usr/bin/rsync
teamwork ALL=(ALL) NOPASSWD: /usr/bin/netstat
teamwork ALL=(ALL) NOPASSWD: /usr/bin/ss
teamwork ALL=(ALL) NOPASSWD: /usr/bin/lsof
teamwork ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
teamwork ALL=(ALL) NOPASSWD: /usr/bin/wireshark
teamwork ALL=(ALL) NOPASSWD: /usr/bin/tshark

# File system and process access
teamwork ALL=(ALL) NOPASSWD: /usr/bin/find
teamwork ALL=(ALL) NOPASSWD: /usr/bin/locate
teamwork ALL=(ALL) NOPASSWD: /usr/bin/ps
teamwork ALL=(ALL) NOPASSWD: /usr/bin/top
teamwork ALL=(ALL) NOPASSWD: /usr/bin/htop
teamwork ALL=(ALL) NOPASSWD: /usr/bin/iotop
teamwork ALL=(ALL) NOPASSWD: /usr/bin/mount
teamwork ALL=(ALL) NOPASSWD: /usr/bin/umount
EOF

# Set proper permissions
sudo chmod 440 /etc/sudoers.d/iscan-tools

# Verify sudoers syntax
sudo visudo -c

echo "Sudo configuration completed!"
echo "Testing nmap with sudo..."
sudo nmap --version | head -2

echo "Setup complete! Scanning tools now have passwordless sudo access."