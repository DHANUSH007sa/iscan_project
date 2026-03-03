# Raspberry Pi 5 Setup Guide

Complete guide to deploy iScan on Raspberry Pi 5 with Ubuntu Server.

## 📋 Prerequisites

### Hardware
- Raspberry Pi 5 (8GB or 16GB recommended)
- 64GB+ microSD card or SSD
- Power supply (27W+ recommended)
- Network connection (Ethernet preferred for stability)

### OS
- Ubuntu Server 24.04 LTS for ARM64 (official Pi 5 image)

## 🚀 Step 1: Initial Pi 5 Setup

### 1.1 Install Ubuntu Server on Pi 5

```bash
# Download Ubuntu Server for Raspberry Pi 5
# From: https://ubuntu.com/download/raspberry-pi
# Choose: 24.04 LTS for ARM64

# Flash to microSD using Raspberry Pi Imager:
# 1. Download Raspberry Pi Imager
# 2. Insert microSD card
# 3. Select Ubuntu Server 24.04 (ARM64)
# 4. Write to card
```

### 1.2 First Boot

```bash
# Insert microSD into Pi 5 and power on
# Wait 2-3 minutes for first boot setup
# Login with default credentials:
# username: ubuntu
# password: ubuntu

# Change password immediately
passwd

# Update system immediately
sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y
```

### 1.3 Configure Network (Optional but Recommended)

```bash
# If using static IP (recommended for server):
sudo nano /etc/netplan/99-netcfg.yaml

# Add this (modify for your network):
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
      addresses:
        - 192.168.1.100/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]

# Apply changes
sudo netplan apply

# Verify
ip addr show
```

---

## 📦 Step 2: Install Required Tools

### 2.1 System Package Manager Updates

```bash
# Update package manager
sudo apt update
sudo apt upgrade -y

# Install essential dev tools
sudo apt install -y \
  build-essential \
  git \
  curl \
  wget \
  sudo \
  nano \
  vim \
  htop
```

### 2.2 Install Python Tools

```bash
# Install Python and pip
sudo apt install -y \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev

# Verify installation
python3 --version
pip3 --version
```

### 2.3 Install Node.js (for Frontend)

```bash
# Install Node.js 20 LTS (required for npm)
sudo apt install -y nodejs npm

# Verify installation
node --version   # Should be v20+
npm --version    # Should be 10+

# Optional: Update npm to latest
sudo npm install -g npm@latest
```

### 2.4 Install Scanning Tools (Core Tools for Real Scans)

```bash
# CRITICAL: These tools are required for actual scanning
# In demo mode (PISHIELD_SIMULATE_SCANS=1), these are optional

# Nmap - Network mapping
sudo apt install -y nmap

# Nikto - Web server scanning
sudo apt install -y nikto

# SMBMap - Windows share enumeration
sudo apt install -y smbmap

# Enum4linux - SMB enumeration
sudo apt install -y enum4linux

# SSLyze - SSL/TLS analysis (Python)
sudo pip3 install sslyze

# CrackMapExec - Windows network tool
sudo pip3 install crackmapexec

# Verify installations
nmap --version
nikto -help | head -5
smbmap --help | head -5
enum4linux -h | head -5
sslyze --version
cme --version

# Optional: TestSSL.sh for comprehensive SSL testing
cd /opt
sudo git clone https://github.com/drwetter/testssl.sh.git
sudo chmod +x /opt/testssl.sh/testssl.sh
sudo ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
testssl.sh --version
```

### 2.5 Install Optional Tools (Recommended)

```bash
# GVM for vulnerability scanning (optional, heavier tool)
# sudo apt install -y openvas

# Metasploit (optional, requires additional setup)
# curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metacli.sh | bash

# Git configuration
git config --global user.name "Your Name"
git config --global user.email "your@email.com"
```

---

## 📂 Step 3: Create Project Directory Structure

### 3.1 Create Project Directory

```bash
# Create project directory
sudo mkdir -p /home/ubuntu/iscan_project
cd /home/ubuntu/iscan_project

# Make sure ubuntu user owns it
sudo chown -R ubuntu:ubuntu /home/ubuntu/iscan_project

# Create subdirectories
mkdir -p backend/{jobs,scans,venv}
mkdir -p frontend
mkdir -p logs
mkdir -p data/reports

# Create logs directory with proper permissions
sudo mkdir -p /var/log/iscan
sudo touch /var/log/iscan/app.log
sudo chown ubuntu:ubuntu /var/log/iscan -R
```

### 3.2 Clone iScan Repository

```bash
cd /home/ubuntu/iscan_project

# Clone from GitHub
git clone https://github.com/yourusername/iscan.git .

# Or if repo already exists, update it
git pull origin main

# Verify structure
ls -la
```

---

## ⚙️ Step 4: Backend Setup

### 4.1 Create Python Virtual Environment

```bash
cd /home/ubuntu/iscan_project/backend

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

### 4.2 Install Python Dependencies

```bash
# Ensure venv is activated
source /home/ubuntu/iscan_project/backend/venv/bin/activate

# Install requirements
pip install -r requirements.txt

# If using advanced features, also install:
pip install python-dotenv

# Verify Flask installation
python3 -c "import flask; print('Flask ready!')"
```

### 4.3 Configure Environment

```bash
cd /home/ubuntu/iscan_project

# Copy configuration template
cp .env.example .env.local

# Edit configuration for Pi environment
nano .env.local

# IMPORTANT: Set these values:
```

**Recommended .env.local for Pi 5:**
```env
# Backend Config
FLASK_ENV=production          # Use production for Pi
FLASK_DEBUG=0                 # Keep debug off in production
FLASK_PORT=5001               # Can change if port used

# Admin Setup (CHANGE THESE!)
ADMIN_EMAIL=admin@yourdomain.com     # Your email
ADMIN_PASSWORD=very_secure_password  # Strong password!

# Database location
DATABASE_PATH=/var/lib/iscan/auth.db  # Persistent location

# Scanner settings
PISHIELD_SIMULATE_SCANS=0     # 1 for demo, 0 for real scanning
ISCAN_FORCE_ROOT=0            # Set to 1 if running as root

# Frontend
VITE_API_URL=http://your-pi-ip:5001
NODE_ENV=production

# CORS
CORS_ORIGIN=http://your-pi-ip:8080
```

### 4.4 Create Persistent Data Directories

```bash
# Create data directory
sudo mkdir -p /var/lib/iscan
sudo chown ubuntu:ubuntu /var/lib/iscan

# Initialize database (will create on first run)
cd /home/ubuntu/iscan_project/backend
source venv/bin/activate
python3 app.py &  # Run briefly to initialize
sleep 5
pkill -f "python3 app.py"

# Move database to persistent location
mv /home/ubuntu/iscan_project/backend/auth.db /var/lib/iscan/auth.db
```

---

## 🎨 Step 5: Frontend Setup

### 5.1 Install Frontend Dependencies

```bash
cd /home/ubuntu/iscan_project

# Install npm packages
npm install

# This may take a few minutes on Pi 5
# Be patient - ARM64 builds take longer
```

### 5.2 Build Frontend

```bash
cd /home/ubuntu/iscan_project

# Build production frontend
npm run build

# Verify build succeeded
ls -la dist/

# Frontend is now in dist/ directory
```

---

## 🔐 Step 6: Firewall & Network Setup

### 6.1 Configure UFW Firewall

```bash
# Enable firewall
sudo ufw enable

# Allow SSH (critical!)
sudo ufw allow 22

# Allow iScan frontend
sudo ufw allow 8080

# Allow iScan backend API
sudo ufw allow 5001

# Allow HTTP/HTTPS (if using reverse proxy)
sudo ufw allow 80
sudo ufw allow 443

# View firewall status
sudo ufw status
```

### 6.2 Test Network Connectivity

```bash
# Find Pi's IP address
hostname -I

# Test from another machine
curl http://192.168.1.100:5001   # Adjust IP to yours
curl http://192.168.1.100:8080   # Frontend

# Should show backend/frontend responses
```

---

## 🚀 Step 7: Run iScan on Pi 5

### 7.1 Manual Start (Testing)

```bash
# Terminal 1: Start Backend
cd /home/ubuntu/iscan_project/backend
source venv/bin/activate
python3 app.py

# Should see:
# * Running on http://0.0.0.0:5001
```

```bash
# Terminal 2: Start Frontend (Development)
cd /home/ubuntu/iscan_project
npm run dev

# Should see:
# Local: http://localhost:8080
```

### 7.2 Production Mode with systemd

Create systemd service for backend:

```bash
# Create backend service
sudo nano /etc/systemd/system/iscan-backend.service
```

**Copy this content:**
```ini
[Unit]
Description=iScan Backend Service
After=network.target
Wants=iscan-frontend.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/iscan_project/backend
Environment="PATH=/home/ubuntu/iscan_project/backend/venv/bin"
Environment="PYTHONUNBUFFERED=1"
EnvironmentFile=/home/ubuntu/iscan_project/.env.local
ExecStart=/home/ubuntu/iscan_project/backend/venv/bin/python3 app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
# Create frontend service
sudo nano /etc/systemd/system/iscan-frontend.service
```

**Copy this content:**
```ini
[Unit]
Description=iScan Frontend Service
After=network.target
Wants=iscan-backend.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/iscan_project
ExecStart=/usr/bin/npm start -- --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment="PATH=/home/ubuntu/iscan_project/node_modules/.bin:$PATH"

[Install]
WantedBy=multi-user.target
```

### 7.3 Start Services

```bash
# Reload systemd daemon
sudo systemctl daemon-reload

# Enable services to start on boot
sudo systemctl enable iscan-backend
sudo systemctl enable iscan-frontend

# Start services
sudo systemctl start iscan-backend
sudo systemctl start iscan-frontend

# Check status
sudo systemctl status iscan-backend
sudo systemctl status iscan-frontend

# View logs
sudo journalctl -u iscan-backend -f     # Backend logs
sudo journalctl -u iscan-frontend -f    # Frontend logs
```

---

## 🌐 Step 8: Reverse Proxy Setup (Optional but Recommended)

### 8.1 Install Nginx

```bash
sudo apt install -y nginx

# Enable nginx
sudo systemctl enable nginx
sudo systemctl start nginx
```

### 8.2 Configure Nginx

```bash
# Create nginx config
sudo nano /etc/nginx/sites-available/iscan
```

**Copy this content:**
```nginx
# Redirect HTTP to HTTPS (optional, requires SSL cert)
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;  # Remove if not using HTTPS
}

# Main iScan server
server {
    listen 443 ssl;  # Remove "ssl" and change to 80 if not using HTTPS
    server_name your-pi-domain.local;  # Change to your domain

    # SSL Configuration (optional)
    # ssl_certificate /etc/ssl/certs/your-cert.crt;
    # ssl_certificate_key /etc/ssl/private/your-key.key;
    # ssl_protocols TLSv1.2 TLSv1.3;

    # Frontend proxy
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Backend API proxy
    location /api {
        proxy_pass http://localhost:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Enable nginx config
sudo ln -s /etc/nginx/sites-available/iscan /etc/nginx/sites-enabled/

# Test config
sudo nginx -t

# Restart nginx
sudo systemctl restart nginx
```

---

## 📊 Step 9: Performance Optimization for Pi 5

### 9.1 Enable 64-bit Kernel (if not already enabled)

```bash
# Check current kernel
uname -m  # Should show aarch64

# Already enabled on default Ubuntu ARM64
```

### 9.2 Increase File Descriptors for Scanning

```bash
# Edit limits
sudo nano /etc/security/limits.conf

# Add at end:
ubuntu soft nofile 65535
ubuntu hard nofile 65535
```

### 9.3 Optimize Flask for Pi

Edit `backend/app.py` to add:

```python
# For production on Pi, use single-threaded
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5001,
        debug=False,
        threaded=True,
        processes=1  # Limit processes on Pi
    )
```

### 9.4 Monitor Resources

```bash
# Install system monitor
sudo apt install -y htop iotop

# Monitor in real-time
htop  # CPU and memory
iotop # Disk I/O

# Check Pi 5 temperature
watch -n 1 "cat /sys/class/thermal/thermal_zone0/temp | awk '{print \$1/1000}' ; echo '°C'"
```

---

## 📋 Step 10: Verification Checklist

Run these commands to verify everything works:

```bash
# ✓ Python backend running
curl http://localhost:5001

# ✓ Frontend built
ls -la /home/ubuntu/iscan_project/dist

# ✓ Services active
sudo systemctl is-active iscan-backend
sudo systemctl is-active iscan-frontend

# ✓ Firewall allowing traffic
sudo ufw status

# ✓ Database exists
ls -la /var/lib/iscan/auth.db

# ✓ Network accessible from other machine
ping 192.168.1.100  # Your Pi IP
curl http://192.168.1.100:8080

# ✓ Scan tools installed
nmap --version
nikto -help | head -3
smbmap --help | head -3
enum4linux -h | head -3
```

---

## 🔄 Step 11: Start from Scratch Script (Automated)

Create this file for easy reinstalls: `setup_pi.sh`

```bash
#!/bin/bash
set -e

echo "=== iScan Pi 5 Setup ==="

# Update system
echo "Updating system..."
sudo apt update && sudo apt upgrade -y

# Install tools
echo "Installing tools..."
sudo apt install -y \
  build-essential git curl wget \
  python3 python3-pip python3-venv python3-dev \
  nodejs npm \
  nmap nikto smbmap enum4linux

# Install Python tools
echo "Installing Python scanning tools..."
sudo pip3 install sslyze crackmapexec python-dotenv

# Create project directory
echo "Setting up project structure..."
sudo mkdir -p /home/ubuntu/iscan_project
cd /home/ubuntu/iscan_project

# Backend setup
echo "Setting up backend..."
python3 -m venv backend/venv
source backend/venv/bin/activate
pip install -r requirements.txt

# Frontend setup
echo "Setting up frontend..."
npm install
npm run build

# Configuration
echo "Creating configuration..."
cp .env.example .env.local
echo "⚠️  Edit .env.local with your settings!"

# Data directory
echo "Creating data directories..."
sudo mkdir -p /var/lib/iscan
sudo chown ubuntu:ubuntu /var/lib/iscan

echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env.local with your settings"
echo "2. Start backend: cd backend && source venv/bin/activate && python3 app.py"
echo "3. Start frontend: npm run dev"
echo "4. Access at http://localhost:8080"
```

Run it:
```bash
chmod +x setup_pi.sh
./setup_pi.sh
```

---

## 🐛 Troubleshooting

### Backend won't start
```bash
# Check logs
sudo journalctl -u iscan-backend -n 50

# Check port in use
sudo lsof -i :5001

# Try manual run to see error
cd /home/ubuntu/iscan_project/backend
source venv/bin/activate
python3 app.py
```

### Frontend build fails
```bash
# Clear npm cache
npm cache clean --force
rm -rf node_modules package-lock.json
npm install

# Try build again
npm run build
```

### Scanning tools not found
```bash
# Verify installation
which nmap
which nikto
which smbmap

# Reinstall if missing
sudo apt install -y nmap nikto smbmap enum4linux
```

### Pi running hot
```bash
# Monitor temperature
watch -n 1 "cat /sys/class/thermal/thermal_zone0/temp | awk '{print \$1/1000}' ; echo '°C'"

# Ensure cooling is adequate
# Add heatsinks to Pi 5 chips
# Ensure proper ventilation
```

### Database locked
```bash
# Kill lingering processes
pkill -f "python3 app.py"

# Wait 5 seconds
sleep 5

# Restart service
sudo systemctl start iscan-backend
```

---

## 📱 Access iScan

Once everything is running:

**On Pi 5:**
- Frontend: http://localhost:8080
- Backend: http://localhost:5001

**From another machine (replace 192.168.1.100 with your Pi IP):**
- Frontend: http://192.168.1.100:8080
- Admin login: http://192.168.1.100:8080/admin
- Backend API: http://192.168.1.100:5001

---

## 🚢 Production Deployment Checklist

- [ ] Change ADMIN_PASSWORD to strong password
- [ ] Set FLASK_ENV=production
- [ ] Enable firewall (ufw)
- [ ] Set up systemd services
- [ ] Configure reverse proxy (nginx)
- [ ] Enable SSL/HTTPS certificate
- [ ] Enable database backups
- [ ] Monitor resource usage
- [ ] Set up log rotation
- [ ] Document admin access credentials

---

**Raspberry Pi 5 Setup Complete! 🎉**

Your iScan instance is ready for vulnerability scanning.
