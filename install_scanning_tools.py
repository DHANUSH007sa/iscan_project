#!/usr/bin/env python3
"""
Automated scanning tools installer for iScan project.
Supports Windows (WSL/Git Bash), Linux, and macOS.

Usage:
    python install_scanning_tools.py          # Auto-detect OS
    python install_scanning_tools.py --os linux
    python install_scanning_tools.py --os windows
    python install_scanning_tools.py --os macos
"""

import os
import sys
import platform
import subprocess
import argparse
from pathlib import Path


class ToolInstaller:
    def __init__(self, os_type=None):
        self.os_type = os_type or self.detect_os()
        self.installed_tools = []
        self.failed_tools = []
        
    def detect_os(self):
        """Detect operating system"""
        system = platform.system()
        if system == "Windows":
            # Check if running in WSL or Git Bash
            if "Microsoft" in platform.release():
                return "wsl"
            return "windows"
        elif system == "Linux":
            return "linux"
        elif system == "Darwin":
            return "macos"
        else:
            return "linux"  # Default fallback
    
    def run_command(self, cmd, check=True):
        """Execute shell command safely"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=check
            )
            return result.returncode == 0, result.stdout
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            return False, str(e)
    
    def check_tool_installed(self, tool_name):
        """Check if tool is already installed"""
        success, _ = self.run_command(f"which {tool_name}", check=False)
        return success
    
    def install_windows(self):
        """Install tools on Windows (requires WSL or Git Bash with Linux environment)"""
        print("\n🪟 Windows Installation (WSL2 Recommended)")
        print("=" * 60)
        
        if "WSL" not in platform.release():
            print("\n⚠️  WSL2 not detected. For best results:")
            print("   1. Install WSL2: https://aka.ms/wsl2")
            print("   2. Install Ubuntu 22.04 from Microsoft Store")
            print("   3. Run this script from WSL2 terminal")
            print("\nProceeding with Git Bash/native Windows fallback...\n")
        
        # Use choco for Windows package manager if available
        success, _ = self.run_command("choco --version", check=False)
        
        if success:
            self._install_with_chocolatey()
        else:
            print("📦 Chocolatey not found. Install from: https://chocolatey.org/install")
            print("📦 Or use WSL2 with Ubuntu for easier installation\n")
            self._install_manual_windows()
    
    def _install_with_chocolatey(self):
        """Install tools using Chocolatey"""
        tools = {
            "nmap": "nmap",
            "nikto": "nikto",  # May need manual installation
            "python": "python3",
        }
        
        for tool, choco_name in tools.items():
            if self.check_tool_installed(tool):
                print(f"✅ {tool} already installed")
                self.installed_tools.append(tool)
                continue
            
            print(f"📦 Installing {tool}...")
            success, output = self.run_command(f"choco install {choco_name} -y", check=False)
            
            if success:
                print(f"✅ {tool} installed successfully")
                self.installed_tools.append(tool)
            else:
                print(f"❌ Failed to install {tool}")
                self.failed_tools.append(tool)
    
    def _install_manual_windows(self):
        """Manual installation instructions for Windows"""
        print("\n📥 Manual Installation for Windows:")
        print("-" * 60)
        print("1. Nmap: https://nmap.org/download.html")
        print("   - Download installer and run")
        print("   - Default path: C:\\Program Files (x86)\\Nmap")
        print("")
        print("2. Use WSL2 for Linux tools (recommended):")
        print("   - Open PowerShell as admin")
        print("   - Run: wsl --install -d Ubuntu")
        print("   - Then run this script from WSL terminal")
    
    def install_linux(self):
        """Install tools on Linux (Ubuntu/Debian)"""
        print("\n🐧 Linux Installation (Ubuntu/Debian)")
        print("=" * 60)
        
        # Update package manager
        print("\n🔄 Updating package lists...")
        self.run_command("sudo apt update", check=False)
        
        tools = {
            "nmap": "nmap",
            "nikto": "nikto",
            "enum4linux": "enum4linux",
            "smbmap": "smbmap",
            "testssl.sh": "testssl.sh",
            "sslyze": "sslyze",
            "crackmapexec": "crackmapexec",
        }
        
        for tool, package in tools.items():
            if self.check_tool_installed(tool):
                print(f"✅ {tool} already installed")
                self.installed_tools.append(tool)
                continue
            
            print(f"📦 Installing {tool}...")
            success, output = self.run_command(
                f"sudo apt install -y {package}",
                check=False
            )
            
            if success:
                print(f"✅ {tool} installed successfully")
                self.installed_tools.append(tool)
            else:
                # Try pip for Python packages
                if package in ["smbmap", "sslyze", "crackmapexec"]:
                    print(f"   Trying pip3 for {tool}...")
                    success, _ = self.run_command(
                        f"pip3 install {package}",
                        check=False
                    )
                    if success:
                        print(f"✅ {tool} installed via pip3")
                        self.installed_tools.append(tool)
                    else:
                        print(f"❌ Failed to install {tool}")
                        self.failed_tools.append(tool)
                else:
                    print(f"❌ Failed to install {tool}")
                    self.failed_tools.append(tool)
    
    def install_macos(self):
        """Install tools on macOS"""
        print("\n🍎 macOS Installation")
        print("=" * 60)
        
        # Check for Homebrew
        success, _ = self.run_command("brew --version", check=False)
        if not success:
            print("Homebrew not found. Install from: https://brew.sh")
            return
        
        tools = {
            "nmap": "nmap",
            "nikto": "nikto",
            "enum4linux": "enum4linux",
            "smbmap": "smbmap",
            "sslyze": "sslyze",
            "crackmapexec": "crackmapexec",
        }
        
        for tool, package in tools.items():
            if self.check_tool_installed(tool):
                print(f"✅ {tool} already installed")
                self.installed_tools.append(tool)
                continue
            
            print(f"📦 Installing {tool}...")
            success, _ = self.run_command(f"brew install {package}", check=False)
            
            if success:
                print(f"✅ {tool} installed successfully")
                self.installed_tools.append(tool)
            else:
                # Try pip for Python packages
                if tool in ["smbmap", "sslyze", "crackmapexec"]:
                    print(f"   Trying pip3 for {tool}...")
                    success, _ = self.run_command(f"pip3 install {package}", check=False)
                    if success:
                        print(f"✅ {tool} installed via pip3")
                        self.installed_tools.append(tool)
                    else:
                        self.failed_tools.append(tool)
                else:
                    self.failed_tools.append(tool)
    
    def verify_installation(self):
        """Verify all tools are accessible"""
        print("\n\n🔍 Verifying Installation")
        print("=" * 60)
        
        tools_to_check = [
            ("nmap", "nmap -v | head -1"),
            ("nikto", "nikto -Version"),
            ("enum4linux", "enum4linux -h | head -1"),
            ("smbmap", "smbmap --help | head -1"),
            ("testssl.sh", "testssl.sh --version"),
            ("sslyze", "sslyze --version"),
            ("crackmapexec", "crackmapexec --version"),
        ]
        
        verified = {}
        for tool, cmd in tools_to_check:
            success, output = self.run_command(cmd, check=False)
            if success:
                verified[tool] = "✅ Found"
                print(f"✅ {tool:20} - Installed and accessible")
            else:
                verified[tool] = "❌ Not found"
                print(f"❌ {tool:20} - Not found or not in PATH")
        
        return verified
    
    def print_summary(self, verified):
        """Print installation summary"""
        print("\n\n📊 Installation Summary")
        print("=" * 60)
        print(f"Successfully installed: {len(self.installed_tools)} tools")
        for tool in self.installed_tools:
            print(f"  ✅ {tool}")
        
        if self.failed_tools:
            print(f"\nFailed to install: {len(self.failed_tools)} tools")
            for tool in self.failed_tools:
                print(f"  ❌ {tool}")
        
        print("\n\n🎯 Next Steps")
        print("=" * 60)
        print("1. Update .env.local to ENABLE real scanning:")
        print("   PISHIELD_SIMULATE_SCANS=0")
        print("")
        print("2. Verify tools are in PATH:")
        print("   which nmap")
        print("   which nikto")
        print("")
        print("3. Start the application:")
        print("   npm run dev          # Frontend terminal")
        print("   python backend/app.py # Backend terminal (separate)")
        print("")
        print("4. Access at http://localhost:5173")
    
    def run(self):
        """Execute installation based on OS"""
        print(f"\n🚀 iScan Scanning Tools Installer")
        print(f"Detected OS: {self.os_type.upper()}")
        print("=" * 60)
        
        if self.os_type in ["linux", "wsl"]:
            self.install_linux()
        elif self.os_type == "windows":
            self.install_windows()
        elif self.os_type == "macos":
            self.install_macos()
        
        verified = self.verify_installation()
        self.print_summary(verified)


def main():
    parser = argparse.ArgumentParser(
        description="Install scanning tools for iScan project"
    )
    parser.add_argument(
        "--os",
        choices=["linux", "windows", "macos", "wsl"],
        help="Override OS detection"
    )
    
    args = parser.parse_args()
    
    installer = ToolInstaller(os_type=args.os)
    installer.run()


if __name__ == "__main__":
    main()
