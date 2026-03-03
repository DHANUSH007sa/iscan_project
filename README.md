# iScan - Network Vulnerability Scanner

A lightweight, agentless network vulnerability scanner for Windows systems, powered by Raspberry Pi 5 with Ubuntu Server.

## 🎯 Features

- **Network Discovery** - Automatic detection of Windows systems on your network
- **Multi-Scanner Framework** - Combine nmap, nikto, SSLyze, CrackMapExec, SMBMap and more
- **Vulnerability Detection** - Real CVE detection using Vulners database
- **Agentless Scanning** - Non-intrusive, no agents to install on target systems
- **Web Dashboard** - Beautiful React-based UI for managing and viewing scans
- **Report Generation** - Detailed JSON reports with actionable insights
- **Mock/Demo Mode** - Test the application without external scanning tools

## 📋 System Requirements

### Frontend
- Node.js 18+ 
- npm or yarn

### Backend  
- Python 3.10+
- External tools (optional, required for real scans):
  - nmap
  - nikto
  - smbmap
  - enum4linux
  - sslyze
  - testssl.sh
  - crackmapexec

### Recommended
- Raspberry Pi 5 with Ubuntu Server (production)
- Linux/Unix for development
- Windows with WSL2 for development on Windows

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/iscan.git
cd iscan
```

### 2. Configure Environment
```bash
# Copy environment template
cp .env.example .env.local

# Edit configuration (use text editor)
# nano .env.local  # Linux/Mac
# Or open .env.local in VS Code
```

Key settings in `.env.local`:
```env
ADMIN_EMAIL=admin@example.com          # Change this
ADMIN_PASSWORD=your_secure_password    # Change to strong password
PISHIELD_SIMULATE_SCANS=1              # Set to 1 for demo mode (no tools needed)
FLASK_ENV=development                  # Change to production for deployment
```

### 3. Install Dependencies

**Frontend:**
```bash
npm install
npm run dev
```
Access at: http://localhost:8080

**Backend:**
```bash
cd backend

# Create Python virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate        # Linux/Mac
# or
venv\Scripts\activate           # Windows

# Install Python packages
pip install -r requirements.txt

# Run the backend
python3 app.py
```
Available at: http://localhost:5001

### 4. Access the Application
1. Open http://localhost:8080 in your browser
2. Admin login: http://localhost:8080/admin
   - Email: Use value from ADMIN_EMAIL in .env.local
   - Password: Use value from ADMIN_PASSWORD in .env.local
3. Start scanning!

## 🧪 Demo/Test Mode

To run without external scanning tools installed:

```env
# In .env.local
PISHIELD_SIMULATE_SCANS=1
```

This generates realistic demo scan results. Perfect for testing the UI and reports.

## �️ Install Real Scanning Tools

To enable **real network scanning**, install the external tools using the automation script.

### Step 1: Run Installation Script

```bash
# From project root directory
python install_scanning_tools.py
```

**For specific OS (optional):**
```bash
python install_scanning_tools.py --os linux    # Force Linux tools
python install_scanning_tools.py --os windows  # Force Windows (WSL)
python install_scanning_tools.py --os macos    # Force macOS tools
```

### Step 2: Tool Installation Details

#### 🐧 **Linux/Ubuntu (Recommended)**
Tools are installed to system PATH via package managers:
```bash
# Tools installed via apt-get
/usr/bin/nmap              # Network scanning
/usr/bin/nikto             # Web server scanning
/usr/bin/enum4linux        # SMB enumeration
/usr/bin/smbmap            # SMB share mapping
/usr/bin/testssl.sh        # SSL/TLS testing
/usr/bin/sslyze            # SSL certificate analysis
/usr/local/bin/crackmapexec  # Credential testing
```

**Or manually install:**
```bash
sudo apt update
sudo apt install -y nmap nikto enum4linux
pip3 install smbmap sslyze crackmapexec
# Download testssl.sh from https://github.com/drwetter/testssl.sh
```

#### 🪟 **Windows (WSL2 Recommended)**
Install WSL2 + Ubuntu, then follow Linux instructions:

```powershell
# PowerShell (as admin)
wsl --install -d Ubuntu
```

Then run installation script from WSL terminal.

**Chocolatey Method (Limited tool support):**
```powershell
choco install nmap
```

#### 🍎 **macOS**
Tools installed via Homebrew:
```bash
# Install Homebrew if needed: https://brew.sh
brew install nmap nikto smbmap sslyze
pip3 install crackmapexec
```

### Step 3: Verify Installation

The script automatically verifies all tools:
```bash
✅ nmap      - Installed and accessible
✅ nikto     - Installed and accessible
✅ enum4linux - Installed and accessible
```

Manual verification:
```bash
which nmap
which nikto
nmap --version
```

### Step 4: Enable Real Scanning

Update `.env.local` to disable demo mode:

```env
# Before (demo mode - no tools needed)
PISHIELD_SIMULATE_SCANS=1

# After (real scanning enabled)
PISHIELD_SIMULATE_SCANS=0
```

Restart the backend for changes to take effect.

### 📍 Tool Paths Reference

The application can find tools in these locations (in order of preference):

| OS | Primary PATH | Fallback Location |
|---|---|---|
| Linux | `/usr/bin/` | System PATH |
| Ubuntu Pi 5 | `/usr/bin/` | `/home/ubuntu/iscan_venv/bin/` |
| WSL2 | `/usr/bin/` (Ubuntu) | System PATH |
| macOS | `/usr/local/bin/` | System PATH via Homebrew |

**Custom Paths:**
If tools are installed to custom locations, update in `.env.local`:
```env
# Optional: Override tool paths
NMAP_PATH=/custom/path/to/nmap
NIKTO_PATH=/custom/path/to/nikto
SMBMAP_PATH=/custom/path/to/smbmap
```

### 🚀 Quick Test Scan

After installation, test with a safe scan:

```bash
# Scan localhost 
# From web dashboard, scan IP: 127.0.0.1
# Or from command line:
nmap localhost
nikto -h localhost
```

### ⚙️ Raspberry Pi 5 Specific

For RPi 5 deployment, see [RASPBERRY_PI_SETUP.md](RASPBERRY_PI_SETUP.md) for:
- Exact installation paths
- systemd service configuration
- Performance optimizations
- Automated setup script

## �🔧 Configuration

All configuration is managed in `.env.local` (never committed):

```env
# Backend
FLASK_ENV=development              # development or production
FLASK_PORT=5001                    # Backend port
FLASK_DEBUG=0                       # Debug mode (0 or 1)

# Admin User
ADMIN_EMAIL=admin@example.com       # Admin login email
ADMIN_PASSWORD=demo_password        # Admin login password

# Database
DATABASE_PATH=./backend/auth.db     # User database location

# Scanning
PISHIELD_SIMULATE_SCANS=0            # Use fake data (0 or 1)
ISCAN_FORCE_ROOT=0                  # Force root mode (0 or 1)

# Frontend
VITE_API_URL=http://localhost:5001  # Backend address
NODE_ENV=development                # development or production
CORS_ORIGIN=http://localhost:8080   # Frontend URL for CORS
```

## 📖 Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute changes
- [Raspberry Pi 5 Setup](RASPBERRY_PI_SETUP.md) - **Complete Pi 5 deployment guide with tools, paths, and services**
- [Architecture Details](docs/ARCHITECTURE.md) - System design and structure

## ⚠️ Security Notice

**This is a security scanning tool. Please use responsibly:**

1. **Change Default Credentials**
   - Always set ADMIN_PASSWORD to a strong password in .env.local
   - Use a unique email address

2. **Network Restrictions**
   - Only scan networks you own or have explicit permission to scan
   - Use firewall rules to restrict access in production

3. **Data Protection**
   - Scan results may contain sensitive information
   - Restrict access to the dashboard
   - Use HTTPS in production

4. **Responsible Disclosure**
   - If you discover vulnerabilities in this tool, report privately
   - Do not publicly disclose security issues before patch release

## 🐛 Troubleshooting

### Backend won't start
```bash
# Check if port 5001 is in use
lsof -i :5001  # Linux/Mac

# Check Python installation
python3 --version

# Check virtual environment activated
which python  # Should show path to venv
```

### Frontend can't reach backend
```bash
# Check VITE_API_URL in .env.local
# Check if backend is running on port 5001
curl http://localhost:5001/
```

### Scans fail
```bash
# Check if external tools are installed
nmap --version
nikto -help

# Try demo mode
# Set PISHIELD_SIMULATE_SCANS=1 in .env.local
```

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Reporting issues
- Submitting pull requests
- Code standards
- Development setup

## 💬 Support

For issues and questions:
1. Check existing [GitHub Issues](https://github.com/yourusername/iscan/issues)
2. Review [CONTRIBUTING.md](CONTRIBUTING.md) for reporting guidelines
3. See [SECURITY.md](SECURITY.md) for security reporting

---

**Made with ❤️ for network security professionals**
