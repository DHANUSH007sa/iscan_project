#!/usr/bin/env python3
import os
import re
import json
import uuid
import threading
import subprocess
import time
import sqlite3
import shutil
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables from .env.local (if using python-dotenv)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv optional, use system environment variables

# Check if we want to force root mode for full nmap capabilities
FORCE_ROOT_MODE = os.environ.get("ISCAN_FORCE_ROOT", "0") == "1"

# Directory setup - Use dynamic path calculation (works on any system)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Allow override via environment variable
BASE_DIR = os.environ.get("ISCAN_BASE_DIR", BASE_DIR)

# Vite build output (npm run build) goes to dist/ under project root
DIST_DIR = os.path.join(BASE_DIR, "dist")
JOBS_DIR = os.path.join(BASE_DIR, "backend", "jobs")
SCANS_DIR = os.path.join(BASE_DIR, "backend", "scans")
# Allow database path override via environment variable
AUTH_DB = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "backend", "auth.db"))
SIMULATION_MODE = os.environ.get("PISHIELD_SIMULATE_SCANS", "0") == "1"

# Scanner configuration
SCANNERS = {
    "nmap": {"name": "Nmap (Ping + Service)", "timeout": 120},
    "nikto": {"name": "Nikto", "timeout": 120},
    "nmap_vuln": {"name": "Nmap NSE Vulnerability", "timeout": 180},
    "nmap_vulners": {"name": "Nmap Vulners (CVE Detection)", "timeout": 120},
    "smbmap": {"name": "SMBMap (Windows Share Scanner)", "timeout": 60},
    "enum4linux": {"name": "Enum4linux (SMB Enumeration)", "timeout": 90},
    "wappalyzer": {"name": "WhatWeb (Web Tech)", "timeout": 45},
    "sslyze": {"name": "SSLyze", "timeout": 60},
    "testssl": {"name": "TestSSL (SSL/TLS Analysis)", "timeout": 120},
    "windows": {"name": "Windows Security", "timeout": 60},
    "crackmapexec": {"name": "CrackMapExec (Windows Network Scanner)", "timeout": 90}
}

# Serve static built frontend
app = Flask(__name__, static_folder=DIST_DIR, static_url_path="/")
CORS(app)  # Enable CORS for all routes

ip_regex = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
jobs_lock = threading.Lock()
jobs: Dict[str, Dict[str, Any]] = {}

# Global variable to track active scan
active_scan_lock = threading.Lock()
active_scan_job = None


def get_db_connection():
    conn = sqlite3.connect(AUTH_DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db():
    os.makedirs(os.path.dirname(AUTH_DB), exist_ok=True)
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                date_of_birth TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )
        conn.commit()
        
        # Add is_admin column if it doesn't exist (migration)
        try:
            conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
            conn.commit()
            print("✅ Added is_admin column to users table")
        except sqlite3.OperationalError as e:
            # Column already exists, ignore
            if "duplicate column name" not in str(e).lower():
                print(f"Note: {e}")
        
        # Create default admin user if not exists
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
        admin_password = os.environ.get("ADMIN_PASSWORD", "demo_password_change_in_production")
        
        cursor = conn.execute("SELECT id FROM users WHERE email = ?", (admin_email,))
        if not cursor.fetchone():
            admin_password_hash = generate_password_hash(admin_password)
            conn.execute(
                """
                INSERT INTO users (first_name, last_name, email, date_of_birth, password_hash, created_at, is_admin)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                ("Admin", "User", admin_email, "2000-01-01", admin_password_hash, time.time(), 1)
            )
            conn.commit()
            print(f"✅ Default admin user created (email: {admin_email})")
            print("   ⚠️  Change default password in .env.local for production!")
    finally:
        conn.close()


def load_existing_jobs():
    if not os.path.isdir(JOBS_DIR):
        return
    for entry in os.listdir(JOBS_DIR):
        if not entry.endswith(".json"):
            continue
        job_path = os.path.join(JOBS_DIR, entry)
        try:
            with open(job_path, "r") as fh:
                job = json.load(fh)
                if "id" in job:
                    jobs[job["id"]] = job
        except Exception:
            continue


def persist_job(job: Dict[str, Any]):
    os.makedirs(JOBS_DIR, exist_ok=True)
    job_path = os.path.join(JOBS_DIR, f"{job['id']}.json")
    with open(job_path, "w") as fh:
        json.dump(job, fh, indent=2)


def update_job(job_id: str, **fields):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return None
        job.update(fields)
        persist_job(job)
        return job


def run_scan_job(job_id: str, target_ip: str, scan_profile: str, scanners: list):
    """Run multiple scanners on target IP"""
    global active_scan_job
    
    # Wait for any active scan to complete before starting this one
    while True:
        with active_scan_lock:
            if active_scan_job is None:
                active_scan_job = job_id
                break
        # Wait a bit before checking again
        time.sleep(1)
    
    try:
        update_job(job_id, status="running", started_at=time.time(), progress=0)
        
        # Create scan directory for this IP
        scan_dir = os.path.join(SCANS_DIR, target_ip.replace(".", "_"))
        os.makedirs(scan_dir, exist_ok=True)
        
        # Limit stored reports to only 5 most recent ones
        limit_scan_reports()
        
        # Use ThreadPoolExecutor with increased parallelism for faster scanning
        results = {}
        errors = []
        
        # Map scanner names to their functions - Windows-focused
        scanner_functions = {
            "nmap": lambda: run_nmap_scan(target_ip, scan_profile, scan_dir),
            "nikto": lambda: run_nikto_scan(target_ip, scan_profile, scan_dir),
            "nmap_vuln": lambda: run_nmap_vuln_scan(target_ip, scan_profile, scan_dir),
            "nmap_vulners": lambda: run_nmap_vulners_scan(target_ip, scan_profile, scan_dir),
            "smbmap": lambda: run_smbmap_scan(target_ip, scan_profile, scan_dir),
            "enum4linux": lambda: run_enum4linux_scan(target_ip, scan_profile, scan_dir),
            "wappalyzer": lambda: run_wappalyzer_scan(target_ip, scan_profile, scan_dir),
            "sslyze": lambda: run_sslyze_scan(target_ip, scan_profile, scan_dir),
            "testssl": lambda: run_testssl_scan(target_ip, scan_profile, scan_dir),
            "windows": lambda: run_windows_scan(target_ip, scan_profile, scan_dir),
            "crackmapexec": lambda: run_crackmapexec_scan(target_ip, scan_profile, scan_dir)
        }
        
        # Increase max_workers for more parallelism on Pi 5 with 8GB RAM
        max_workers = min(8, len(scanners))  # Increased from 5 to 8 for better parallelism
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scanner tasks
            future_to_scanner = {
                executor.submit(scanner_functions[scanner]): scanner 
                for scanner in scanners if scanner in scanner_functions
            }
            
            # Collect results as they complete
            completed = 0
            total = len(future_to_scanner)
            
            for future in as_completed(future_to_scanner):
                scanner = future_to_scanner[future]
                try:
                    update_job(job_id, current_scanner=scanner)
                    result = future.result(timeout=SCANNERS.get(scanner, {}).get("timeout", 300))
                    results[scanner] = result
                except Exception as e:
                    errors.append(f"{scanner}: {str(e)}")
                    results[scanner] = {"scanner": scanner, "status": "error", "error": str(e)}
                
                completed += 1
                progress = int((completed / total) * 100)
                update_job(job_id, progress=progress)
        
        # Generate final consolidated report
        final_report = generate_final_report(target_ip, scan_profile, results, scan_dir)
        
        # Save results
        job_result = {
            "scanners": scanners,
            "results": results,
            "errors": errors,
            "scan_dir": scan_dir,
            "final_report": final_report
        }
        
        update_job(job_id, status="completed", finished_at=time.time(), **job_result)
        
    except Exception as e:
        update_job(job_id, status="error", error=str(e), finished_at=time.time())
    finally:
        # Release the active scan lock
        with active_scan_lock:
            if active_scan_job == job_id:
                active_scan_job = None


# ========== Scanner Functions ==========

def run_nmap_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """1) Nmap - Ping + Service + OS Detection - Optimized for Windows targets"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "nmap",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "open_ports": [22, 80, 443],
            "services": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.2"},
                {"port": 80, "service": "http", "version": "Apache 2.4.41"},
                {"port": 443, "service": "https", "version": "Apache 2.4.41"}
            ],
            "os_detection": "Linux 5.4.0",
            "vulnerabilities": []
        }
    else:
        # Configure nmap command based on scan profile - optimized for Windows
        if scan_profile == "small":
            # Small scan - Windows essential ports
            ports = "80,135,139,443,445,3389,5985"  # Windows-focused ports
            cmd = [
                "sudo", "nmap", "-sS", "-sV", "-O", "-Pn",  # Skip ping, use SYN scan
                "-p", ports,
                "-T4",  # Balanced timing
                "--max-retries", "1",
                "--host-timeout", "30s",  # Reduced timeout
                "--min-rate", "1000",
                "--privileged",
                "--osscan-guess",
                "--version-intensity", "5",  # Reduced intensity for speed
                target_ip,
                "-oX", "-"
            ]
        elif scan_profile == "medium":
            # Medium scan - comprehensive Windows scan
            ports = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3389,5985,5986"  # Windows + common ports
            cmd = [
                "sudo", "nmap", "-sS", "-sV", "-O", "-Pn",  # Skip ping for Windows
                "-p", ports,
                "-T4",
                "--max-retries", "2",
                "--host-timeout", "45s",  # Reasonable timeout
                "--min-rate", "500",
                "--privileged",
                "--osscan-guess",
                "--version-intensity", "7",
                "--script", "smb-os-discovery,smb-security-mode,smb-enum-shares",  # Windows-specific scripts
                target_ip,
                "-oX", "-"
            ]
        else:  # deep
            # Deep scan - comprehensive Windows analysis
            ports = "1-1000,3389,5985,5986"  # Top 1000 + Windows RDP/WinRM
            cmd = [
                "sudo", "nmap", "-sS", "-sV", "-O", "-Pn",
                "-p", ports,
                "-T3",  # Slower but more reliable
                "--max-retries", "3",
                "--host-timeout", "60s",  # Reasonable timeout for deep scan
                "--min-rate", "300",
                "--privileged",
                "--osscan-guess",
                "--version-intensity", "9",
                "--script", "smb-os-discovery,smb-security-mode,smb-enum-shares,smb-vuln-*,rdp-enum-encryption",  # Comprehensive Windows scripts
                target_ip,
                "-oX", "-"
            ]
        
        result = run_command(cmd, "nmap", timeout=90)  # Override timeout to 90 seconds
    
    # Save result
    result_file = os.path.join(scan_dir, "nmap_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_nikto_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """2) Nikto - Web Server Vulnerabilities"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "nikto",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "vulnerabilities": [
                {"severity": "medium", "issue": "Outdated Apache version", "cve": "CVE-2021-44790"},
                {"severity": "low", "issue": "Directory listing enabled", "path": "/uploads"},
                {"severity": "high", "issue": "Missing security headers", "headers": ["X-Frame-Options", "CSP"]}
            ]
        }
    else:
        # Configure nikto command based on scan profile
        if scan_profile == "small":
            # Small scan - basic web scan
            cmd = ["nikto", "-h", target_ip, "-Format", "xml", "-output", "-"]
        elif scan_profile == "medium":
            # Medium scan - more thorough web scan
            cmd = ["nikto", "-h", target_ip, "-Format", "xml", "-output", "-", "-Plugins", "all"]
        else:  # deep
            # Deep scan - full web scan
            cmd = ["nikto", "-h", target_ip, "-Format", "xml", "-output", "-", "-Plugins", "all", "-Tuning", "x"]
        
        result = run_command(cmd, "nikto")
    
    # Save result
    result_file = os.path.join(scan_dir, "nikto_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_nmap_vuln_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """8) Nmap NSE Vulnerability Scripts"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "nmap_vuln",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "vulnerabilities": [
                {"script": "smb-vuln-ms17-010", "state": "VULNERABLE", "risk": "CRITICAL"},
                {"script": "ssl-heartbleed", "state": "NOT VULNERABLE", "risk": "INFO"},
                {"script": "http-sql-injection", "state": "POSSIBLE", "risk": "HIGH"}
            ]
        }
    else:
        # Configure nmap vulnerability command based on scan profile
        if scan_profile == "small":
            # Small scan - basic vulnerability scripts for essential ports only
            cmd = [
                "nmap", "--script", "vuln",
                "-T5", "--host-timeout", "15s", "--max-retries", "0",
                "-p", "22,80,443",
                target_ip,
                "-oX", "-"
            ]
            result = run_command(cmd, "nmap_vuln")
        elif scan_profile == "medium":
            # Medium scan - more comprehensive vulnerability scripts
            cmd = [
                "sudo", "nmap", "--script", "vuln",
                "-T4", "--host-timeout", "45s", "--max-retries", "1",
                "-p", "22,80,443,25,110,143,993,995",
                target_ip,
                "-oX", "-"
            ]
            result = run_command(cmd, "nmap_vuln")
        else:  # deep
            # Deep scan - comprehensive vulnerability scripts with full access
            cmd = [
                "sudo", "nmap", "--script", "vuln,exploit,malware,discovery,intrusive,auth,brute,dos",
                "-T3", "--host-timeout", "120s", "--max-retries", "3",
                "-p", "1-10000",
                "--privileged",
                "--script-args", "unsafe=1",  # Enable unsafe/aggressive scripts
                "--version-intensity", "9",
                target_ip,
                "-oX", "-"
            ]
            result = run_command(cmd, "nmap_vuln")
    
    # Save result
    result_file = os.path.join(scan_dir, "nmap_vuln_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_nmap_vulners_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """7) Nmap Vulners - Real CVE Detection (OpenVAS Replacement) - Windows optimized"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "nmap_vulners",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "vulnerabilities": [
                {"cve": "CVE-2021-44790", "cvss": "7.5", "type": "HTTP", "description": "Apache HTTP Server vulnerability"},
                {"cve": "CVE-2017-0144", "cvss": "9.3", "type": "SMB", "description": "EternalBlue SMB vulnerability"},
                {"cve": "CVE-2014-0160", "cvss": "7.5", "type": "SSL", "description": "Heartbleed OpenSSL vulnerability"}
            ]
        }
    else:
        # Windows-focused vulnerability detection
        if scan_profile == "small":
            # Small scan - Windows essential ports with vulners
            cmd = ["sudo", "nmap", "-sV", "-Pn", "--script", "vulners,smb-vuln-*", 
                   "-p", "135,139,445,3389", target_ip, "-oX", "-"]
        elif scan_profile == "medium":
            # Medium scan - Windows comprehensive vulnerability scan
            cmd = ["sudo", "nmap", "-sS", "-sV", "-Pn", "--script", "vulners,smb-vuln-*,rdp-vuln-*", 
                   "-p", "80,135,139,443,445,3389,5985", "--version-intensity", "7", target_ip, "-oX", "-"]
        else:  # deep
            # Deep scan - Full Windows vulnerability assessment
            cmd = ["sudo", "nmap", "-sS", "-sV", "-Pn", "--script", "vulners,smb-vuln-*,rdp-vuln-*,http-vuln-*", 
                   "-p", "1-1000,3389,5985,5986", "--privileged", "--version-intensity", "9", 
                   "--script-args", "vulners.showall", target_ip, "-oX", "-"]
        
        result = run_command(cmd, "nmap_vulners", timeout=120)  # 2 minute timeout
    
    # Save result
    result_file = os.path.join(scan_dir, "nmap_vulners_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_smbmap_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """5) SMBMap - Windows Share Enumeration and Access Testing"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "smbmap",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "shares": [
                {"name": "C$", "permissions": "READ", "comment": "Default share"},
                {"name": "ADMIN$", "permissions": "NO ACCESS", "comment": "Remote Admin"},
                {"name": "TestShare", "permissions": "READ, WRITE", "comment": "Test share"}
            ],
            "vulnerabilities": [
                {"issue": "Writable Share Found", "severity": "medium", "share": "TestShare"}
            ]
        }
    else:
        # Configure smbmap command based on scan profile - Windows share enumeration
        # Use dynamic path to smbmap instead of hardcoded
        smbmap_path = os.path.join(BASE_DIR, "backend", "venv", "bin", "smbmap")
        if not os.path.exists(smbmap_path):
            smbmap_path = "smbmap"  # Fall back to system smbmap
        
        if scan_profile == "small":
            # Small scan - basic share enumeration
            cmd = ["sudo", smbmap_path, "-H", target_ip, "-u", "null", "-p", ""]
        elif scan_profile == "medium":
            # Medium scan - comprehensive share enumeration with guest access
            cmd = ["sudo", smbmap_path, "-H", target_ip, "-u", "guest", "-p", ""]
        else:  # deep
            # Deep scan - full share enumeration with multiple authentication attempts
            cmd = ["sudo", smbmap_path, "-H", target_ip, "-u", "guest", "-p", "", "-A", ".*"]
        
        result = run_command(cmd, "smbmap", timeout=90)
        
        # Parse SMBMap output for vulnerabilities
        if result.get("stdout"):
            stdout = result.get("stdout", "")
            vulnerabilities = []
            
            # Check for writable shares
            if "WRITE" in stdout:
                vulnerabilities.append({
                    "type": "Writable SMB Share",
                    "severity": "High",
                    "description": "Found SMB shares with write permissions",
                    "recommendation": "Restrict write access to necessary users only"
                })
            
            # Check for readable shares
            if "READ" in stdout:
                vulnerabilities.append({
                    "type": "Readable SMB Share",
                    "severity": "Medium", 
                    "description": "Found SMB shares accessible without authentication",
                    "recommendation": "Implement proper authentication for share access"
                })
            
            result["vulnerabilities"] = vulnerabilities
    
    # Save result
    result_file = os.path.join(scan_dir, "smbmap_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_enum4linux_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """6) Enum4linux - SMB Enumeration and Windows Domain Information"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "enum4linux",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "smb_info": {
                "workgroup": "WORKGROUP",
                "server_name": "WIN-SERVER",
                "os_version": "Windows 10 Pro"
            },
            "shares": [
                {"name": "C$", "type": "Disk", "comment": "Default share"},
                {"name": "ADMIN$", "type": "Disk", "comment": "Remote Admin"}
            ],
            "users": ["Administrator", "Guest", "user1"],
            "vulnerabilities": [
                {"issue": "SMBv1 Enabled", "severity": "high", "cve": "CVE-2017-0144"}
            ]
        }
    else:
        # Configure enum4linux command based on scan profile - optimized for Windows
        # Redirect stderr to suppress Perl warnings
        if scan_profile == "small":
            # Small scan - basic SMB enumeration with timeout
            cmd = f"timeout 60 /snap/bin/enum4linux -S -U {target_ip} 2>/dev/null"
        elif scan_profile == "medium":
            # Medium scan - comprehensive SMB enumeration
            cmd = f"timeout 90 /snap/bin/enum4linux -a -v {target_ip} 2>/dev/null"
        else:  # deep
            # Deep scan - full SMB enumeration with all options
            cmd = f"timeout 120 /snap/bin/enum4linux -a -v -d -o -M {target_ip} 2>/dev/null"
        
        # Run command with shell=True to handle stderr redirection
        start_time = time.time()
        try:
            proc_result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=150,
                text=True
            )
            duration = time.time() - start_time
            result = {
                "scanner": "enum4linux",
                "command": cmd,
                "return_code": proc_result.returncode,
                "stdout": proc_result.stdout,
                "stderr": "",  # Suppressed
                "timestamp": time.time(),
                "status": "success" if proc_result.returncode in [0, 1] else "warning",
                "duration": duration
            }
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            result = {
                "scanner": "enum4linux",
                "command": cmd,
                "status": "timeout",
                "error": "Command timed out",
                "timestamp": time.time(),
                "duration": duration
            }
        except Exception as e:
            duration = time.time() - start_time
            result = {
                "scanner": "enum4linux",
                "command": cmd,
                "status": "error",
                "error": str(e),
                "timestamp": time.time(),
                "duration": duration
            }
    
    # Save result
    result_file = os.path.join(scan_dir, "enum4linux_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_wappalyzer_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """3) WhatWeb - Web Technologies Detection"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "wappalyzer",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "technologies": [
                {"name": "Apache", "version": "2.4.41", "confidence": 100},
                {"name": "PHP", "version": "7.4.3", "confidence": 90},
                {"name": "WordPress", "version": "5.8.1", "confidence": 85}
            ]
        }
    else:
        # Configure wappalyzer command based on scan profile
        if scan_profile == "small":
            # Small scan - basic technology detection
            cmd = ["whatweb", "--color=never", "--log-json=-", target_ip]
        elif scan_profile == "medium":
            # Medium scan - more detailed technology detection
            cmd = ["whatweb", "--color=never", "--log-json=-", "--aggression=3", target_ip]
        else:  # deep
            # Deep scan - comprehensive technology detection
            cmd = ["whatweb", "--color=never", "--log-json=-", "--aggression=4", target_ip]
        
        result = run_command(cmd, "wappalyzer")
    
    # Save result
    result_file = os.path.join(scan_dir, "wappalyzer_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_sslyze_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """4) SSLyze - SSL/TLS Security Analysis"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "sslyze",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "certificates": [
                {"hostname": target_ip, "port": 443, "protocol": "TLSv1.2", "issues": []}
            ],
            "vulnerabilities": [
                {"name": "Heartbleed", "vulnerable": False},
                {"name": "CCS Injection", "vulnerable": False}
            ]
        }
    else:
        # Configure sslyze command based on scan profile
        if scan_profile == "small":
            # Small scan - basic SSL check
            cmd = ["sslyze", "--quiet", "--tlsv1_2", "--tlsv1_1", "--tlsv1", "--sslv3", f"{target_ip}:443"]
        elif scan_profile == "medium":
            # Medium scan - more comprehensive SSL check
            cmd = ["sslyze", "--quiet", "--tlsv1_2", "--tlsv1_1", "--tlsv1", "--sslv3", "--compression", "--heartbleed", f"{target_ip}:443"]
        else:  # deep
            # Deep scan - full SSL analysis
            cmd = ["sslyze", "--quiet", "--tlsv1_2", "--tlsv1_1", "--tlsv1", "--sslv3", "--compression", "--heartbleed", "--reneg", "--robot", f"{target_ip}:443"]
        
        result = run_command(cmd, "sslyze")
    
    # Save result
    result_file = os.path.join(scan_dir, "sslyze_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_testssl_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """9) TestSSL - Comprehensive SSL/TLS Security Analysis"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "testssl",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "ssl_info": {
                "protocols": ["TLSv1.2", "TLSv1.3"],
                "ciphers": ["AES256-GCM-SHA384", "CHACHA20-POLY1305"],
                "certificate_valid": True
            },
            "vulnerabilities": [
                {"test": "Heartbleed", "result": "NOT vulnerable", "severity": "info"},
                {"test": "CCS Injection", "result": "NOT vulnerable", "severity": "info"},
                {"test": "ROBOT", "result": "NOT vulnerable", "severity": "info"},
                {"test": "BREACH", "result": "potentially vulnerable", "severity": "medium"}
            ],
            "recommendations": [
                "Disable TLSv1.0 and TLSv1.1",
                "Enable HSTS headers"
            ]
        }
    else:
        # First check if SSL/TLS port (443) is open
        try:
            port_check = subprocess.run(
                ["timeout", "5", "nc", "-zv", target_ip, "443"],
                capture_output=True,
                timeout=10,
                text=True
            )
            port_open = port_check.returncode == 0
        except:
            port_open = False
        
        if not port_open:
            # Skip testssl if port 443 is not open
            result = {
                "scanner": "testssl",
                "timestamp": time.time(),
                "target": target_ip,
                "status": "success",
                "message": "Skipped - No SSL/TLS service detected on port 443",
                "duration": 0.1  # Small duration to indicate it was checked
            }
        else:
            # Configure testssl command based on scan profile - with timeout
            if scan_profile == "small":
                # Small scan - basic SSL/TLS check with timeout
                cmd = ["timeout", "60", "/usr/local/bin/testssl.sh", "--fast", "--jsonfile-pretty", "/dev/stdout", f"{target_ip}:443"]
            elif scan_profile == "medium":
                # Medium scan - standard SSL/TLS analysis with timeout
                cmd = ["timeout", "90", "/usr/local/bin/testssl.sh", "--standard", "--jsonfile-pretty", "/dev/stdout", f"{target_ip}:443"]
            else:  # deep
                # Deep scan - comprehensive SSL/TLS analysis with timeout
                cmd = ["timeout", "120", "/usr/local/bin/testssl.sh", "--full", "--jsonfile-pretty", "/dev/stdout", f"{target_ip}:443"]
            
            result = run_command(cmd, "testssl", timeout=150)  # Allow extra time for timeout command
    
    # Save result
    result_file = os.path.join(scan_dir, "testssl_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_windows_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """10) Windows Security Check - Enhanced for Windows targets"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "windows",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "smb_available": True,
            "shares": [
                {"name": "IPC$", "type": "IPC", "comment": "Remote IPC"},
                {"name": "C$", "type": "Disk", "comment": "Default share"}
            ],
            "security_findings": [
                {"check": "SMB Signing", "status": "DISABLED", "risk": "MEDIUM"},
                {"check": "Null Sessions", "status": "ENABLED", "risk": "HIGH"}
            ]
        }
    else:
        # Multi-step Windows security check
        start_time = time.time()
        result = {
            "scanner": "windows",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "success",
            "checks_performed": [],
            "vulnerabilities": [],
            "services_detected": []
        }
        
        # Check 1: SMB Share enumeration
        try:
            smb_cmd = ["timeout", "30", "smbclient", "-L", target_ip, "-N"]
            smb_result = run_command(smb_cmd, "windows_smb", timeout=45)
            result["checks_performed"].append("SMB Share Enumeration")
            
            if smb_result.get("status") == "success" and smb_result.get("stdout"):
                result["smb_shares"] = smb_result["stdout"]
                result["services_detected"].append("SMB File Sharing")
                
                # Check for anonymous access
                if "IPC$" in smb_result["stdout"] or "ADMIN$" in smb_result["stdout"]:
                    result["vulnerabilities"].append({
                        "type": "Anonymous SMB Access",
                        "severity": "Medium",
                        "description": "SMB shares accessible without authentication"
                    })
        except Exception as e:
            result["checks_performed"].append(f"SMB Check Failed: {str(e)}")
        
        # Check 2: RDP Detection
        try:
            rdp_cmd = ["timeout", "10", "nmap", "-p", "3389", "--script", "rdp-enum-encryption", target_ip]
            rdp_result = run_command(rdp_cmd, "windows_rdp", timeout=20)
            result["checks_performed"].append("RDP Detection")
            
            if rdp_result.get("status") == "success" and "open" in rdp_result.get("stdout", ""):
                result["services_detected"].append("Remote Desktop Protocol")
                result["vulnerabilities"].append({
                    "type": "RDP Service Exposed",
                    "severity": "Medium",
                    "description": "Remote Desktop Protocol is accessible from network"
                })
        except Exception as e:
            result["checks_performed"].append(f"RDP Check Failed: {str(e)}")
        
        # Check 3: Windows RPC Detection
        try:
            rpc_cmd = ["timeout", "10", "nmap", "-p", "135", target_ip]
            rpc_result = run_command(rpc_cmd, "windows_rpc", timeout=20)
            result["checks_performed"].append("RPC Detection")
            
            if rpc_result.get("status") == "success" and "open" in rpc_result.get("stdout", ""):
                result["services_detected"].append("Windows RPC")
                result["vulnerabilities"].append({
                    "type": "Windows RPC Exposed",
                    "severity": "Low",
                    "description": "Windows RPC endpoint mapper is accessible"
                })
        except Exception as e:
            result["checks_performed"].append(f"RPC Check Failed: {str(e)}")
        
        # Check 4: NetBIOS Detection
        try:
            netbios_cmd = ["timeout", "10", "nmap", "-p", "139", "--script", "nbstat", target_ip]
            netbios_result = run_command(netbios_cmd, "windows_netbios", timeout=20)
            result["checks_performed"].append("NetBIOS Detection")
            
            if netbios_result.get("status") == "success" and "open" in netbios_result.get("stdout", ""):
                result["services_detected"].append("NetBIOS")
                result["vulnerabilities"].append({
                    "type": "NetBIOS Service Active",
                    "severity": "Low",
                    "description": "NetBIOS service is active and may leak system information"
                })
        except Exception as e:
            result["checks_performed"].append(f"NetBIOS Check Failed: {str(e)}")
        
        # Summary
        result["total_vulnerabilities"] = len(result["vulnerabilities"])
        result["total_services"] = len(result["services_detected"])
        result["duration"] = time.time() - start_time
        
        if result["total_vulnerabilities"] > 0:
            result["risk_level"] = "Medium" if result["total_vulnerabilities"] > 2 else "Low"
        else:
            result["risk_level"] = "Low"
    
    # Save result
    result_file = os.path.join(scan_dir, "windows_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_crackmapexec_scan(target_ip: str, scan_profile: str, scan_dir: str):
    """11) CrackMapExec - Advanced Windows Network Security Scanner"""
    # Ensure scan directory exists
    os.makedirs(scan_dir, exist_ok=True)
    
    if SIMULATION_MODE:
        result = {
            "scanner": "crackmapexec",
            "timestamp": time.time(),
            "target": target_ip,
            "status": "simulated",
            "smb_info": {
                "os": "Windows 10 Pro",
                "domain": "WORKGROUP",
                "signing": False,
                "smbv1": True
            },
            "vulnerabilities": [
                {"issue": "SMBv1 Enabled", "severity": "critical", "cve": "CVE-2017-0144"},
                {"issue": "SMB Signing Disabled", "severity": "high", "description": "SMB signing not required"}
            ]
        }
    else:
        # Configure crackmapexec command based on scan profile
        vulnerabilities = []
        
        if scan_profile == "small":
            # Small scan - basic SMB enumeration (no timeout flag - not supported)
            cmd = ["sudo", "/snap/bin/crackmapexec", "smb", target_ip]
        elif scan_profile == "medium":
            # Medium scan - comprehensive SMB analysis
            cmd = ["sudo", "/snap/bin/crackmapexec", "smb", target_ip, "--shares"]
        else:  # deep
            # Deep scan - full Windows network analysis with vulnerability checks
            cmd = ["sudo", "/snap/bin/crackmapexec", "smb", target_ip, "--shares", "--sessions", "--disks", "--loggedon-users"]
        
        result = run_command(cmd, "crackmapexec", timeout=120)
        
        # Parse CrackMapExec output for Windows vulnerabilities
        if result.get("stdout"):
            stdout = result.get("stdout", "")
            
            # Check for SMB signing
            if "signing:False" in stdout or "SMB signing:False" in stdout:
                vulnerabilities.append({
                    "type": "SMB Signing Disabled",
                    "severity": "High",
                    "description": "SMB message signing is not required, allowing man-in-the-middle attacks",
                    "recommendation": "Enable SMB signing in Group Policy"
                })
            
            # Check for SMBv1
            if "SMBv1:True" in stdout or "smbv1 enabled" in stdout.lower():
                vulnerabilities.append({
                    "type": "SMBv1 Protocol Enabled",
                    "severity": "Critical",
                    "cve": "CVE-2017-0144",
                    "description": "SMBv1 is vulnerable to EternalBlue and other attacks",
                    "recommendation": "Disable SMBv1 protocol immediately"
                })
            
            # Check for accessible shares
            if "READ" in stdout or "WRITE" in stdout:
                vulnerabilities.append({
                    "type": "SMB Shares Accessible",
                    "severity": "Medium",
                    "description": "SMB shares are accessible without proper authentication",
                    "recommendation": "Implement proper access controls on SMB shares"
                })
            
            result["vulnerabilities"] = vulnerabilities
    
    # Save result
    result_file = os.path.join(scan_dir, "crackmapexec_result.json")
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    
    return result


def run_command(cmd: list, scanner_name: str, timeout: int = None):
    """Execute command with timeout and return structured result"""
    start_time = time.time()
    
    # Use scanner-specific timeout if provided, otherwise use default
    if timeout is None:
        # Default to medium timeout if not specified
        timeout = SCANNERS.get(scanner_name, {}).get("timeout", 30)
    
    try:
        # Reduce timeout by 10% to ensure we don't hit the hard limit
        adjusted_timeout = int(timeout * 0.9)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=adjusted_timeout,  # Use adjusted timeout
            text=True
        )
        
        return {
            "scanner": scanner_name,
            "command": " ".join(cmd),
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timestamp": time.time(),
            "status": "success" if result.returncode == 0 else "warning",
            "duration": time.time() - start_time
        }
    except subprocess.TimeoutExpired:
        return {
            "scanner": scanner_name,
            "command": " ".join(cmd),
            "status": "timeout",
            "error": f"Command timed out after {timeout} seconds",
            "timestamp": time.time(),
            "duration": time.time() - start_time
        }
    except Exception as e:
        return {
            "scanner": scanner_name,
            "command": " ".join(cmd),
            "status": "error",
            "error": str(e),
            "timestamp": time.time(),
            "duration": time.time() - start_time
        }


def save_scan_result(scan_dir: str, filename: str, data: dict):
    """Save scan result to JSON file"""
    filepath = os.path.join(scan_dir, filename)
    # Ensure directory exists
    os.makedirs(scan_dir, exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)


def extract_vulnerabilities_from_nmap_vulners(nmap_output: str):
    """Extract CVE vulnerabilities from nmap vulners output"""
    import xml.etree.ElementTree as ET
    
    vulnerabilities = []
    
    try:
        root = ET.fromstring(nmap_output)
        
        # Find all script elements with vulners output
        for script in root.findall('.//script[@id="vulners"]'):
            output = script.get('output', '')
            
            # Parse CVE entries from output
            for line in output.split('\n'):
                if 'CVE-' in line:
                    # Extract CVE ID and CVSS score
                    parts = line.strip().split()
                    for part in parts:
                        if part.startswith('CVE-'):
                            cve_id = part.rstrip(':,')
                            cvss = 'Unknown'
                            
                            # Try to find CVSS score
                            for p in parts:
                                try:
                                    score = float(p)
                                    if 0 <= score <= 10:
                                        cvss = str(score)
                                        break
                                except ValueError:
                                    continue
                            
                            vulnerabilities.append({
                                'cve': cve_id,
                                'cvss': cvss,
                                'severity': 'High' if cvss != 'Unknown' and float(cvss) >= 7.0 else 'Medium' if cvss != 'Unknown' and float(cvss) >= 4.0 else 'Low',
                                'description': f'Security vulnerability {cve_id}'
                            })
    except Exception:
        pass
    
    return vulnerabilities


def generate_final_report(target_ip: str, scan_profile: str, scan_results: dict, scan_dir: str):
    """Generate final consolidated report with profile-specific formatting and Windows vulnerability detection"""
    timestamp = time.time()
    
    # Profile-specific report formatting
    if scan_profile == "small":
        report_format = "basic"
        detail_level = "summary"
    elif scan_profile == "medium":
        report_format = "detailed"
        detail_level = "moderate"
    else:  # deep
        report_format = "comprehensive"
        detail_level = "full"
    
    # Create report structure
    report = {
        "scan_id": f"scan-{uuid.uuid4().hex[:12]}",
        "target": target_ip,
        "profile": scan_profile,
        "format": report_format,
        "detail_level": detail_level,
        "scan_timestamp": timestamp,
        "scan_date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)),
        "scanners_used": [],
        "summary": {
            "total_scanners": 0,
            "successful_scans": 0,
            "failed_scans": 0,
            "skipped_scans": 0,
            "vulnerabilities_found": 0,
            "critical_issues": 0,
            "open_ports": []  # Add open ports to summary
        },
        "results": {},
        "open_ports": [],  # Add open ports at top level
        "windows_vulnerabilities": []  # Add Windows-specific vulnerabilities
    }
    
    # Process scan results
    critical_issues = 0
    vulnerabilities_found = 0
    open_ports = []  # Collect open ports from nmap results
    windows_vulnerabilities = []  # Collect Windows-specific vulnerabilities
    
    for scanner_name, result in scan_results.items():
        report["scanners_used"].append(scanner_name)
        
        # Add scanner result to report
        report["results"][scanner_name] = result
        
        # Extract open ports from nmap results
        if scanner_name == "nmap" and result.get("status") == "success":
            open_ports.extend(extract_open_ports_from_nmap(result.get("stdout", "")))
        
        # Extract CVE vulnerabilities from nmap vulners
        if scanner_name == "nmap_vulners" and result.get("status") == "success":
            cve_vulns = extract_vulnerabilities_from_nmap_vulners(result.get("stdout", ""))
            for cve in cve_vulns:
                windows_vulnerabilities.append(cve)
                vulnerabilities_found += 1
                if cve.get("severity") in ["Critical", "High"]:
                    critical_issues += 1
        
        # Windows-specific vulnerability detection
        if scanner_name == "windows" and result.get("vulnerabilities"):
            windows_vulnerabilities.extend(result["vulnerabilities"])
            vulnerabilities_found += len(result["vulnerabilities"])
        
        # Detect Windows vulnerabilities from open_ports list (more reliable)
        if scanner_name == "nmap":
            # Check each detected port for Windows services
            for port_info in open_ports:
                port_num = port_info.get("port")
                state = port_info.get("state", "unknown")
                service = port_info.get("service", "")
                
                # SMB (445)
                if port_num == "445" or service == "microsoft-ds":
                    windows_vulnerabilities.append({
                        "type": "SMB Service Exposed",
                        "severity": "High" if state == "open" else "Medium",
                        "port": port_num,
                        "state": state,
                        "description": f"SMB file sharing service is {state} - indicates Windows file sharing is active",
                        "recommendation": "Restrict SMB access to trusted networks only or disable if not needed"
                    })
                    vulnerabilities_found += 1
                    if state == "open":
                        critical_issues += 1
                
                # RDP (3389)
                elif port_num == "3389" or service == "ms-wbt-server":
                    windows_vulnerabilities.append({
                        "type": "RDP Service Exposed",
                        "severity": "Critical" if state == "open" else "High",
                        "port": port_num,
                        "state": state,
                        "description": f"Remote Desktop Protocol is {state} - remote access service detected",
                        "recommendation": "Use VPN, enable NLA, or restrict RDP access to specific IP addresses"
                    })
                    vulnerabilities_found += 1
                    if state == "open":
                        critical_issues += 1
                
                # NetBIOS (139)
                elif port_num == "139" or service == "netbios-ssn":
                    windows_vulnerabilities.append({
                        "type": "NetBIOS Service Active",
                        "severity": "Medium" if state == "open" else "Low",
                        "port": port_num,
                        "state": state,
                        "description": f"NetBIOS service is {state} - may leak system information",
                        "recommendation": "Disable NetBIOS over TCP/IP if not required"
                    })
                    vulnerabilities_found += 1
                
                # Windows RPC (135)
                elif port_num == "135" or service == "msrpc":
                    windows_vulnerabilities.append({
                        "type": "Windows RPC Exposed",
                        "severity": "High" if state == "open" else "Medium",
                        "port": port_num,
                        "state": state,
                        "description": f"Windows RPC endpoint mapper is {state} - Windows management service detected",
                        "recommendation": "Restrict RPC access using Windows Firewall or disable if not needed"
                    })
                    vulnerabilities_found += 1
                
                # WinRM (5985/5986)
                elif port_num in ["5985", "5986"] or service in ["wsman", "wsmans"]:
                    windows_vulnerabilities.append({
                        "type": "Windows Remote Management (WinRM) Exposed",
                        "severity": "High" if state == "open" else "Medium",
                        "port": port_num,
                        "state": state,
                        "description": f"WinRM service is {state} - PowerShell remoting enabled",
                        "recommendation": "Restrict WinRM access to management networks only"
                    })
                    vulnerabilities_found += 1
        
        # Check enum4linux results for SMB vulnerabilities
        if scanner_name == "enum4linux" and result.get("stdout"):
            stdout = result.get("stdout", "")
            if "Server doesn't allow session" not in stdout and len(stdout.strip()) > 100:
                windows_vulnerabilities.append({
                    "type": "SMB Anonymous Access",
                    "severity": "High", 
                    "description": "SMB allows anonymous enumeration of shares and users",
                    "recommendation": "Disable anonymous SMB access"
                })
                vulnerabilities_found += 1
                critical_issues += 1
        
        # Update summary statistics
        if result.get("status") == "success":
            report["summary"]["successful_scans"] += 1
        elif result.get("status") == "skipped":
            report["summary"]["skipped_scans"] += 1
        else:
            report["summary"]["failed_scans"] += 1
        
        # Count vulnerabilities and critical issues from other scanners
        if "vulnerabilities" in result:
            vulnerabilities_found += len(result["vulnerabilities"])
            for vuln in result["vulnerabilities"]:
                if vuln.get("risk", "").upper() in ["CRITICAL", "HIGH"] or vuln.get("severity", "").upper() in ["CRITICAL", "HIGH"]:
                    critical_issues += 1
        
        # Handle different result formats
        if "findings" in result:
            vulnerabilities_found += len(result["findings"])
            for finding in result["findings"]:
                if finding.get("risk", "").upper() in ["CRITICAL", "HIGH"]:
                    critical_issues += 1
        
        # Show "NA" for tools that return nothing
        if result.get("status") == "success" and not any(key in result for key in ["vulnerabilities", "findings", "technologies", "services", "certificates"]):
            result["content"] = "NA"
    
    # If no ports were detected, do a quick fallback scan
    if not open_ports:
        try:
            # Quick TCP connect scan on common Windows ports
            quick_scan_cmd = ["sudo", "nmap", "-Pn", "-sT", "-p", "135,139,445,3389,5985,5986", 
                            "--max-retries", "1", "--host-timeout", "10s", target_ip, "-oX", "-"]
            quick_result = subprocess.run(quick_scan_cmd, capture_output=True, text=True, timeout=15)
            if quick_result.returncode == 0:
                fallback_ports = extract_open_ports_from_nmap(quick_result.stdout)
                if fallback_ports:
                    open_ports.extend(fallback_ports)
        except Exception:
            pass
    
    # Add open ports and Windows vulnerabilities to report
    report["open_ports"] = open_ports
    report["summary"]["open_ports"] = open_ports
    report["windows_vulnerabilities"] = windows_vulnerabilities
    
    # Update summary
    report["summary"]["total_scanners"] = len(scan_results)
    report["summary"]["vulnerabilities_found"] = vulnerabilities_found
    report["summary"]["critical_issues"] = critical_issues
    
    # Add Windows-specific summary if Windows vulnerabilities found
    if windows_vulnerabilities:
        report["summary"]["windows_specific"] = {
            "total_windows_vulnerabilities": len(windows_vulnerabilities),
            "high_severity": len([v for v in windows_vulnerabilities if v.get("severity") == "High"]),
            "medium_severity": len([v for v in windows_vulnerabilities if v.get("severity") == "Medium"]),
            "low_severity": len([v for v in windows_vulnerabilities if v.get("severity") == "Low"])
        }
    
    # Save report
    report_file = os.path.join(scan_dir, "final_report.json")
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    
    return report


def extract_open_ports_from_nmap(nmap_output):
    """Extract open and filtered ports from nmap XML output"""
    open_ports = []
    
    try:
        # Parse XML output
        import xml.etree.ElementTree as ET
        if not nmap_output.strip():
            return open_ports
            
        root = ET.fromstring(nmap_output)
        
        # Extract port information
        for host in root.findall('.//host'):
            # First, handle individual port elements
            for port in host.findall('.//port'):
                state_elem = port.find('state')
                port_state = state_elem.get('state') if state_elem is not None else 'unknown'
                
                # Extract both open and filtered ports (filtered means firewall is blocking)
                if port_state in ['open', 'filtered']:
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    service_elem = port.find('service')
                    
                    port_info = {
                        "port": port_id,
                        "protocol": protocol,
                        "state": port_state
                    }
                    
                    if service_elem is not None:
                        service_name = service_elem.get('name')
                        service_product = service_elem.get('product')
                        service_version = service_elem.get('version')
                        
                        if service_name:
                            port_info["service"] = service_name
                        if service_product:
                            port_info["product"] = service_product
                        if service_version:
                            port_info["version"] = service_version
                    
                    open_ports.append(port_info)
            
            # Handle extraports (when many ports have the same state, nmap groups them)
            for extraports in host.findall('.//extraports'):
                state = extraports.get('state')
                if state in ['open', 'filtered']:
                    # Find the extrareasons element which contains the port list
                    extrareasons = extraports.find('extrareasons')
                    if extrareasons is not None:
                        ports_str = extrareasons.get('ports', '')
                        protocol = extrareasons.get('proto', 'tcp')
                        
                        # Parse port ranges (e.g., "1-1000,3389,5985-5986")
                        if ports_str:
                            port_list = []
                            for part in ports_str.split(','):
                                if '-' in part:
                                    # Handle range
                                    start, end = map(int, part.split('-'))
                                    port_list.extend(range(start, end + 1))
                                else:
                                    # Single port
                                    port_list.append(int(part))
                            
                            # Add each port (limit to common Windows ports to avoid too many results)
                            windows_ports = [21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 
                                           464, 587, 636, 993, 995, 1433, 1434, 3268, 3269, 3389, 5985, 5986, 
                                           8080, 8443, 9389]
                            
                            for port_num in port_list:
                                if port_num in windows_ports:
                                    port_info = {
                                        "port": str(port_num),
                                        "protocol": protocol,
                                        "state": state
                                    }
                                    # Try to guess service name for common ports
                                    service_map = {
                                        135: "msrpc", 139: "netbios-ssn", 445: "microsoft-ds",
                                        3389: "ms-wbt-server", 5985: "wsman", 5986: "wsmans",
                                        80: "http", 443: "https", 22: "ssh", 21: "ftp",
                                        1433: "ms-sql-s", 389: "ldap", 636: "ldaps", 88: "kerberos"
                                    }
                                    if port_num in service_map:
                                        port_info["service"] = service_map[port_num]
                                    
                                    open_ports.append(port_info)
    except Exception as e:
        # If XML parsing fails, try to extract ports using regex
        import re
        # Pattern to match open ports in nmap output
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*?))?$'
        for line in nmap_output.split('\n'):
            match = re.search(port_pattern, line)
            if match:
                port_info = {
                    "port": match.group(1),
                    "protocol": match.group(2),
                    "state": "open",
                    "service": match.group(3)
                }
                if match.group(4):
                    port_info["product"] = match.group(4).strip()
                open_ports.append(port_info)
    
    return open_ports


init_auth_db()
load_existing_jobs()

# Serve frontend files
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    # If path exists in dist, serve it; otherwise return index.html for SPA routing
    if path and os.path.exists(os.path.join(DIST_DIR, path)):
        return send_from_directory(DIST_DIR, path)
    index = os.path.join(DIST_DIR, "index.html")
    if os.path.exists(index):
        return send_from_directory(DIST_DIR, "index.html")
    return "Frontend not built. Please run npm build.", 500

# Utility: parse nmap -sn output
def parse_nmap_hosts(nmap_text):
    devices = []
    current_name = None
    current_ip = None
    current_mac = None
    current_os = "Unknown"
    host_is_up = False

    # Use regex for IPv4 and MAC
    ip_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
    mac_re = re.compile(r"MAC Address: ([0-9A-Fa-f:]{17})")
    
    for line in nmap_text.splitlines():
        line = line.strip()
        
        # New host found
        if line.startswith("Nmap scan report for"):
            # Save previous host if it was up
            if current_ip and host_is_up:
                devices.append({
                    "ip": current_ip,
                    "name": current_name or current_ip,
                    "os": current_os,
                    "mac": current_mac or "N/A"
                })
            
            # Reset for new host
            current_ip = None
            current_name = None
            current_mac = None
            current_os = "Unknown"
            host_is_up = False
            
            # Extract IP
            ip_match = ip_re.search(line)
            if ip_match:
                current_ip = ip_match.group(1)
            
            # Extract hostname
            if "(" in line and ")" in line:
                try:
                    name_part = line.split("Nmap scan report for", 1)[1].strip()
                    if "(" in name_part:
                        host_name = name_part.split("(", 1)[0].strip()
                        current_name = host_name if host_name else None
                except Exception:
                    current_name = None
        
        # Check if host is up
        elif "Host is up" in line:
            host_is_up = True
        elif "Host seems down" in line or "0 hosts up" in line:
            host_is_up = False
        
        # Extract MAC address
        elif "MAC Address:" in line:
            mac_match = mac_re.search(line)
            if mac_match:
                current_mac = mac_match.group(1)
        
        # Detect OS from various indicators
        elif any(keyword in line for keyword in ["Running:", "OS details:", "OS CPE:", "Device type:"]):
            os_info = line.split(":", 1)[1].strip() if ":" in line else line
            
            # Detect OS type from string
            if "Android" in os_info or "android" in os_info:
                current_os = "Android"
            elif "Linux" in os_info or "linux" in os_info:
                current_os = "Linux"
            elif "Windows" in os_info or "Microsoft Windows" in os_info:
                current_os = "Windows"
            elif "Mac" in os_info or "macOS" in os_info or "OS X" in os_info or "Darwin" in os_info:
                current_os = "macOS"
            elif "iOS" in os_info or "iPhone" in os_info or "iPad" in os_info:
                current_os = "iOS"

    # Don't forget the last host
    if current_ip and host_is_up:
        devices.append({
            "ip": current_ip,
            "name": current_name or current_ip,
            "os": current_os,
            "mac": current_mac or "N/A"
        })

    return devices


# Utility: parse nmap output with OS detection
def parse_nmap_hosts_with_os(nmap_text):
    devices = []
    current_device = None
    host_is_up = False
    
    ip_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
    mac_re = re.compile(r"MAC Address: ([0-9A-Fa-f:]{17})")
    
    for line in nmap_text.splitlines():
        line = line.strip()
        
        if line.startswith("Nmap scan report for"):
            # Save previous device if it was up
            if current_device and current_device.get("ip") and host_is_up:
                devices.append(current_device)
            
            # Start new device
            current_device = {"name": None, "ip": None, "os": "Unknown", "mac": "N/A"}
            host_is_up = False
            
            ip_match = ip_re.search(line)
            if ip_match:
                current_device["ip"] = ip_match.group(1)
            
            if "(" in line and ")" in line:
                try:
                    name_part = line.split("Nmap scan report for", 1)[1].strip()
                    if "(" in name_part:
                        host_name = name_part.split("(", 1)[0].strip()
                        current_device["name"] = host_name if host_name else current_device["ip"]
                except Exception:
                    pass
            
            if not current_device["name"]:
                current_device["name"] = current_device["ip"] or "Unknown"
        
        # Check if host is up
        elif "Host is up" in line:
            host_is_up = True
        elif "Host seems down" in line:
            host_is_up = False
        
        # Extract MAC address
        elif "MAC Address:" in line:
            mac_match = mac_re.search(line)
            if mac_match:
                current_device["mac"] = mac_match.group(1)
        
        # Detect OS type from various nmap output formats
        elif any(keyword in line for keyword in ["Running:", "OS details:", "Aggressive OS guesses:", "OS CPE:"]):
            os_info = line.split(":", 1)[1].strip() if ":" in line else line
            
            # Detect OS type from string
            if "Linux" in os_info or "linux" in os_info:
                if "Android" in os_info or "android" in os_info:
                    current_device["os"] = "Android"
                else:
                    current_device["os"] = "Linux"
            elif "Windows" in os_info or "Microsoft Windows" in os_info:
                current_device["os"] = "Windows"
            elif "Mac" in os_info or "macOS" in os_info or "OS X" in os_info or "Darwin" in os_info:
                current_device["os"] = "macOS"
            elif "iOS" in os_info or "iPhone" in os_info or "iPad" in os_info:
                current_device["os"] = "iOS"
            elif "Android" in os_info:
                current_device["os"] = "Android"
            else:
                current_device["os"] = os_info[:50]  # First 50 chars
        
        # Also check for open/filtered ports to infer OS
        elif current_device and ("open" in line or "filtered" in line) and current_device["os"] == "Unknown":
            # Windows-specific ports (even if filtered, indicates Windows)
            if any(port in line for port in ["135/tcp", "139/tcp", "445/tcp", "3389/tcp", "msrpc", "netbios-ssn", "microsoft-ds", "ms-wbt-server"]):
                current_device["os"] = "Windows"
            elif "22/tcp" in line and "ssh" in line:
                current_device["os"] = "Linux"
        
        # Check MAC address vendor for additional OS hints
        elif current_device and "MAC Address:" in line and current_device["os"] == "Unknown":
            if any(vendor in line.lower() for vendor in ["microsoft", "intel", "realtek", "broadcom"]):
                # These vendors are commonly associated with Windows machines
                current_device["os"] = "Windows"
            elif any(vendor in line.lower() for vendor in ["apple", "cupertino"]):
                current_device["os"] = "macOS"
    
    # Add last device if it was up
    if current_device and current_device.get("ip") and host_is_up:
        devices.append(current_device)
    
    return devices

# Discover devices using nmap with OS detection
@app.route("/api/discover", methods=["GET"])
def discover_devices():
    net = request.args.get("net", "local")
    
    # Auto-detect local network if requested
    if net == "local":
        # Get local network range
        try:
            # Try to get the local network from ip route
            result = subprocess.check_output(["ip", "route", "show"], stderr=subprocess.DEVNULL).decode()
            # Find the line with the local network
            for line in result.splitlines():
                if "dev" in line and "/" in line and "proto kernel" in line:
                    # Extract network range (e.g., "10.50.242.0/24")
                    parts = line.split()
                    for part in parts:
                        if "/" in part and "." in part:
                            net = part
                            break
                    if net != "local":
                        break
        except Exception:
            # Fallback to default if we can't detect
            net = "10.50.242.0/24"
    
    try:
        subprocess.check_output(["nmap", "--version"], stderr=subprocess.DEVNULL)
    except Exception as e:
        return jsonify({"error": "nmap not installed on server", "details": str(e)}), 500

    # Handle different types of network specifications
    if "-" in net and "/" not in net:
        # IP range format: 10.50.242.1-10.50.242.50
        try:
            start_ip, end_ip = net.split("-")
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # Validate IPs
            if not (validate_ip(start_ip) and validate_ip(end_ip)):
                return jsonify({"error": "Invalid IP range format"}), 400
            
            # Use nmap with range notation
            cmd = ["sudo", "nmap", "-sn", "-PR", "--min-rate", "1000", net]
            print(f"Running range scan: {' '.join(cmd)}")
            raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=30).decode(errors="ignore")
            
            if "Nmap scan report" in raw:
                devices = parse_nmap_hosts(raw)
                print(f"Found {len(devices)} devices in range")
                return jsonify({
                    "devices": devices[:50],  # Limit to 50
                    "total": len(devices),
                    "showing": min(len(devices), 50)
                })
            
            return jsonify({"devices": []})
        except Exception as e:
            print(f"Error scanning range: {e}")
            return jsonify({"error": f"Failed to scan range: {str(e)}"}), 500
    elif "," in net:
        # Comma-separated IPs
        ips = [ip.strip() for ip in net.split(",")]
        # Validate each IP
        valid_ips = []
        for ip in ips:
            if validate_ip(ip):
                valid_ips.append(ip)
        
        if not valid_ips:
            return jsonify({"error": "No valid IP addresses provided"}), 400
            
        # Scan each IP individually and combine results
        all_devices = []
        for ip in valid_ips:
            # Try multiple scan techniques
            scan_methods = [
                ["nmap", "-sn", "-O", "--osscan-guess", ip],  # Ping scan with OS detection
                ["nmap", "-sn", ip],  # Simple ping scan
                ["nmap", "-Pn", "-sS", "-p", "22,80,443", ip],  # TCP SYN scan on common ports
                ["nmap", "-Pn", "-sU", "-p", "53,67,68", ip]   # UDP scan on common ports
            ]
            
            device_found = False
            for cmd in scan_methods:
                try:
                    raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=15).decode(errors="ignore")
                    if "Nmap scan report" in raw:
                        devices = parse_nmap_hosts_with_os(raw) if "-O" in cmd else parse_nmap_hosts(raw)
                        if devices:
                            all_devices.extend(devices)
                            device_found = True
                            break
                except subprocess.TimeoutExpired:
                    continue
                except subprocess.CalledProcessError:
                    continue
                except Exception:
                    continue
            
            # If no scan method worked, add the IP as an unknown device
            if not device_found:
                all_devices.append({
                    "ip": ip,
                    "name": f"Device-{ip.replace('.', '-')}",
                    "os": "Unknown"
                })
        
        # Remove duplicates
        unique_devices = []
        seen_ips = set()
        for device in all_devices:
            if device["ip"] not in seen_ips:
                unique_devices.append(device)
                seen_ips.add(device["ip"])
        
        return jsonify({"devices": unique_devices})
    elif "/" in net:
        # CIDR notation network range - Discovery with IP, OS, and MAC address
        all_devices = []
        seen_ips = set()
        
        # Use ARP scan to discover all devices on local network with MAC addresses
        # This is the most reliable method for local network discovery
        scan_methods = [
            # Method 1: ARP scan with OS detection (best for local network - gets MAC addresses)
            ["sudo", "nmap", "-sn", "-PR", "-O", "--osscan-guess", net],
            # Method 2: Simple ARP scan (fallback if OS detection fails)
            ["sudo", "nmap", "-sn", "-PR", net],
        ]
        
        for cmd in scan_methods:
            try:
                print(f"Running network discovery: {' '.join(cmd)}")
                raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=60).decode(errors="ignore")
                if "Nmap scan report" in raw:
                    # Use OS detection parser if -O flag was used
                    if "-O" in cmd:
                        devices = parse_nmap_hosts_with_os(raw)
                    else:
                        devices = parse_nmap_hosts(raw)
                    
                    for device in devices:
                        if device["ip"] not in seen_ips:
                            all_devices.append(device)
                            seen_ips.add(device["ip"])
                            print(f"Found device: {device['ip']} - {device.get('name', 'Unknown')} - OS: {device.get('os', 'Unknown')} - MAC: {device.get('mac', 'N/A')}")
                    
                    # If we found devices, stop trying other methods
                    if all_devices:
                        print(f"Found {len(all_devices)} devices on network")
                        break
            except subprocess.TimeoutExpired:
                print(f"Timeout for command: {' '.join(cmd)}")
                continue
            except subprocess.CalledProcessError as e:
                print(f"Command failed: {' '.join(cmd)} - {e}")
                continue
            except Exception as e:
                print(f"Error running command: {' '.join(cmd)} - {e}")
                continue
        
        # If we found devices, return them
        if all_devices:
            print(f"Total devices discovered: {len(all_devices)}")
            return jsonify({
                "devices": all_devices,
                "total": len(all_devices),
                "showing": len(all_devices)
            })
        
        # Fallback: return empty list
        print("No devices found on network")
        return jsonify({"devices": []})
    else:
        # Single IP address
        if not validate_ip(net):
            return jsonify({"error": "Invalid IP address provided"}), 400
            
        # Try multiple scan techniques for single IP
        scan_methods = [
            # Method 1: Comprehensive TCP SYN scan with OS detection
            ["sudo", "nmap", "-sS", "-sV", "-O", "-Pn", "-p", "22,80,135,139,443,445,3389", "--osscan-guess", net],
            # Method 2: Simple ping scan with OS detection
            ["sudo", "nmap", "-sn", "-O", "--osscan-guess", net],
            # Method 3: TCP connect scan on common ports
            ["nmap", "-Pn", "-sT", "-p", "22,80,135,139,443,445,3389", net],
            # Method 4: Simple ping scan
            ["nmap", "-sn", net],
            # Method 5: ARP ping (for local network)
            ["sudo", "nmap", "-sn", "-PR", net],
        ]
        
        for cmd in scan_methods:
            try:
                print(f"Running single IP discovery: {' '.join(cmd)}")
                raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=30).decode(errors="ignore")
                if "Nmap scan report" in raw:
                    devices = parse_nmap_hosts_with_os(raw) if "-O" in cmd else parse_nmap_hosts(raw)
                    if devices:
                        print(f"Found device: {devices[0]}")
                        return jsonify({"devices": devices})
            except subprocess.TimeoutExpired:
                print(f"Timeout for single IP command: {' '.join(cmd)}")
                continue
            except subprocess.CalledProcessError as e:
                print(f"Single IP command failed: {' '.join(cmd)} - {e}")
                continue
            except Exception as e:
                print(f"Error running single IP command: {' '.join(cmd)} - {e}")
                continue
        
        # Fallback: return empty list
        print(f"No response from single IP: {net}")
        return jsonify({"devices": []})


@app.route("/api/auth/register", methods=["POST"])
def register_user():
    data = request.json or {}
    first_name = (data.get("firstName") or "").strip()
    last_name = (data.get("lastName") or "").strip()
    email = (data.get("email") or "").strip().lower()
    date_of_birth = (data.get("dateOfBirth") or "").strip()
    password = data.get("password") or ""
    confirm_password = data.get("confirmPassword") or ""

    if not all([first_name, last_name, email, date_of_birth, password, confirm_password]):
        return jsonify({"error": "All fields are required"}), 400
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400
    if "@" not in email:
        return jsonify({"error": "Invalid email address"}), 400

    password_hash = generate_password_hash(password)
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO users (first_name, last_name, email, date_of_birth, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (first_name, last_name, email, date_of_birth, password_hash, time.time()),
            )
        except sqlite3.IntegrityError:
            return jsonify({"error": "A user with this email already exists"}), 409
        conn.commit()
        user_id = cur.lastrowid
        return (
            jsonify(
                {
                    "id": str(user_id),
                    "firstName": first_name,
                    "lastName": last_name,
                    "email": email,
                    "dateOfBirth": date_of_birth,
                }
            ),
            201,
        )
    finally:
        conn.close()


@app.route("/api/auth/login", methods=["POST"])
def login_user():
    data = request.json or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    if not password:
        return jsonify({"error": "Password is required"}), 400

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, first_name, last_name, email, date_of_birth, password_hash, is_admin FROM users WHERE email = ?",
            (email,),
        )
        row = cur.fetchone()

        if row is None:
            return jsonify({"error": "Invalid email or password"}), 401

        # Verify password
        if not check_password_hash(row["password_hash"], password):
            return jsonify({"error": "Invalid email or password"}), 401

        # Password is correct - return user data
        return jsonify(
            {
                "id": str(row["id"]),
                "firstName": row["first_name"],
                "lastName": row["last_name"],
                "email": row["email"],
                "dateOfBirth": row["date_of_birth"],
                "isAdmin": bool(row["is_admin"])
            }
        )
    finally:
        conn.close()


# Admin endpoints
@app.route("/api/admin/users", methods=["GET"])
def get_all_users():
    """Get all users (admin only)"""
    # In a real app, you'd verify the admin token here
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, first_name, last_name, email, date_of_birth, created_at, is_admin FROM users ORDER BY created_at DESC"
        )
        rows = cur.fetchall()
        
        users = []
        for row in rows:
            users.append({
                "id": row["id"],
                "firstName": row["first_name"],
                "lastName": row["last_name"],
                "email": row["email"],
                "dateOfBirth": row["date_of_birth"],
                "createdAt": row["created_at"],
                "isAdmin": bool(row["is_admin"])
            })
        
        return jsonify({"users": users})
    finally:
        conn.close()


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id: int):
    """Delete a user (admin only)"""
    # Prevent deleting the main admin account
    if user_id == 1:
        return jsonify({"error": "Cannot delete the main admin account"}), 403
    
    conn = get_db_connection()
    try:
        # Check if user exists
        cur = conn.cursor()
        cur.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Delete the user
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        
        return jsonify({"message": f"User {user['email']} deleted successfully"})
    finally:
        conn.close()


@app.route("/api/admin/users/<int:user_id>/toggle-admin", methods=["POST"])
def toggle_admin_status(user_id: int):
    """Toggle admin status for a user"""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, is_admin, email FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        new_admin_status = 0 if user["is_admin"] else 1
        conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_admin_status, user_id))
        conn.commit()
        
        return jsonify({
            "message": f"User {user['email']} admin status updated",
            "isAdmin": bool(new_admin_status)
        })
    finally:
        conn.close()


def validate_ip(ip: str) -> bool:
    if not ip_regex.match(ip):
        return False
    # Ensure each octet is 0-255
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def ensure_nmap_available():
    if SIMULATION_MODE:
        return True, None
    try:
        subprocess.check_output(["nmap", "--version"], stderr=subprocess.DEVNULL)
        return True, None
    except FileNotFoundError:
        return False, "nmap binary not found. Install nmap on the Raspberry Pi backend."
    except Exception as exc:
        return False, f"Unable to execute nmap: {exc}"
import os
import time
import uuid
import json
import threading

import time
import threading
import uuid
import os
import json



@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    data = request.json or {}
    ip = data.get("ip")
    profile = data.get("profile", "medium").lower()

    # Map frontend-friendly profile names to backend profiles
    # Frontend currently uses values like "quick" and "full"; backend expects
    # "small", "medium", or "deep".
    if profile in {"fast", "quick"}:
        profile = "small"
    elif profile in {"full", "deep_scan"}:
        profile = "deep"

    if not ip:
        return jsonify({"error": "IP required"}), 400
    if not validate_ip(ip):
        return jsonify({"error": "Invalid IPv4 address"}), 400

    if profile not in {"small", "medium", "deep"}:
        return jsonify({"error": "Profile must be small, medium, or deep"}), 400
    
    # Clean up old scan data for this IP before starting a new scan
    cleanup_old_scan_data(ip)
    
    # Select scanners based on profile - Windows-focused security assessment
    if profile == "small":
        # Small scan - Essential network discovery (4 tools - ~36%)
        scanners = ["nmap", "nikto", "wappalyzer", "sslyze"]
    elif profile == "medium":
        # Medium scan - Comprehensive security assessment (7 tools - ~64%)
        scanners = ["nmap", "nikto", "nmap_vuln", "wappalyzer", "sslyze", "testssl", "enum4linux"]
    else:  # deep
        # Deep scan - Complete vulnerability assessment (11 tools - 100%) - Windows optimized
        scanners = ["nmap", "nikto", "nmap_vuln", "nmap_vulners", "smbmap", "enum4linux", "wappalyzer", "sslyze", "testssl", "windows", "crackmapexec"]

    job_id = f"job-{uuid.uuid4().hex[:12]}"
    job = {
        "id": job_id,
        "ip": ip,
        "status": "queued",
        "created_at": time.time(),
        "profile": profile,
        "scanners": scanners,
        "progress": 0
    }
    with jobs_lock:
        jobs[job_id] = job
        persist_job(job)

    worker = threading.Thread(target=run_scan_job, args=(job_id, ip, profile, scanners))
    worker.start()

    return jsonify({"job_id": job_id}), 202


@app.route("/api/scan/jobs", methods=["GET"])
def list_jobs():
    with jobs_lock:
        return jsonify({"jobs": list(jobs.values())})


@app.route("/api/scan/jobs/<job_id>", methods=["GET"])
def get_job(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(job)


@app.route("/api/scanners", methods=["GET"])
def get_scanners():
    """Return list of available scanners"""
    return jsonify({
        "scanners": [
            {"id": key, "name": value["name"], "timeout": value["timeout"]}
            for key, value in SCANNERS.items()
        ]
    })


@app.route("/api/scan/results/<ip>", methods=["GET"])
def get_scan_results(ip: str):
    """Get all scan results for a specific IP"""
    scan_dir = os.path.join(SCANS_DIR, ip.replace(".", "_"))
    
    if not os.path.exists(scan_dir):
        return jsonify({"error": "No scan results found for this IP"}), 404
    
    results = {}
    for filename in os.listdir(scan_dir):
        if filename.endswith(".json"):
            scanner_name = filename.replace(".json", "")
            filepath = os.path.join(scan_dir, filename)
            try:
                with open(filepath, "r") as f:
                    results[scanner_name] = json.load(f)
            except Exception:
                continue
    
    return jsonify(results)


@app.route("/api/scan/report/<ip>", methods=["GET"])
def get_final_report(ip: str):
    """Get final merged report for a specific IP"""
    scan_dir = os.path.join(SCANS_DIR, ip.replace(".", "_"))
    report_path = os.path.join(scan_dir, "final_report.json")
    
    if not os.path.exists(report_path):
        return jsonify({"error": "No final report found for this IP"}), 404
    
    try:
        with open(report_path, "r") as f:
            report = json.load(f)
        
        # Ensure required fields are at the top level for frontend compatibility
        if "target" not in report:
            report["target"] = ip
        if "scanners_used" not in report and "results" in report:
            report["scanners_used"] = list(report["results"].keys())
        if "summary" not in report:
            report["summary"] = {}
            
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": f"Failed to load report: {str(e)}"}), 500


@app.route("/api/reports/list", methods=["GET"])
def list_all_reports():
    """List all available scan reports"""
    print("Reports endpoint called")
    if not os.path.exists(SCANS_DIR):
        print("SCANS_DIR does not exist")
        return jsonify({"reports": []})
    
    reports = []
    print(f"SCANS_DIR: {SCANS_DIR}")
    print(f"SCANS_DIR exists: {os.path.exists(SCANS_DIR)}")
    if os.path.exists(SCANS_DIR):
        print(f"SCANS_DIR contents: {os.listdir(SCANS_DIR)}")
    
    for ip_dir in os.listdir(SCANS_DIR):
        scan_dir = os.path.join(SCANS_DIR, ip_dir)
        report_path = os.path.join(scan_dir, "final_report.json")
        
        print(f"Checking {report_path}")
        print(f"Report path exists: {os.path.exists(report_path)}")
        
        if os.path.exists(report_path):
            try:
                with open(report_path, "r") as f:
                    report = json.load(f)
                    # Add IP from directory name
                    report["ip_directory"] = ip_dir
                    # Ensure required fields are at the top level for frontend compatibility
                    if "target" not in report and "ip_directory" in report:
                        # Extract IP from directory name (replace underscores with dots)
                        report["target"] = report["ip_directory"].replace("_", ".")
                    if "scanners_used" not in report and "results" in report:
                        report["scanners_used"] = list(report["results"].keys())
                    # Fix for reports that have individual_results instead of results
                    if "individual_results" in report and "results" not in report:
                        report["results"] = report["individual_results"]
                        del report["individual_results"]
                    # Fix for reports that have total_vulnerabilities instead of vulnerabilities_found
                    if "summary" in report:
                        if "total_vulnerabilities" in report["summary"] and "vulnerabilities_found" not in report["summary"]:
                            report["summary"]["vulnerabilities_found"] = report["summary"]["total_vulnerabilities"]
                        # Ensure all required summary fields exist
                        required_summary_fields = ["total_scanners", "successful_scans", "failed_scans", "skipped_scans", "vulnerabilities_found", "critical_issues", "open_ports"]
                        for field in required_summary_fields:
                            if field not in report["summary"]:
                                report["summary"][field] = 0
                    else:
                        report["summary"] = {
                            "total_scanners": 0,
                            "successful_scans": 0,
                            "failed_scans": 0,
                            "skipped_scans": 0,
                            "vulnerabilities_found": 0,
                            "critical_issues": 0,
                            "open_ports": []
                        }
                    reports.append(report)
                    print(f"Added report for {ip_dir}")
            except Exception as e:
                print(f"Error loading report {report_path}: {e}")
                continue
    
    # Sort by scan timestamp (newest first)
    reports.sort(key=lambda x: x.get("scan_timestamp", x.get("timestamp", 0)), reverse=True)
    print(f"Returning {len(reports)} reports")
    response = jsonify({"reports": reports})
    print(f"Response size: {len(json.dumps({'reports': reports}))} bytes")
    return response


@app.route("/api/report/download/<ip>", methods=["GET"])
def download_report(ip: str):
    """Generate and download report in PDF format only"""
    scan_dir = os.path.join(SCANS_DIR, ip.replace(".", "_"))
    report_path = os.path.join(scan_dir, "final_report.json")
    
    if not os.path.exists(report_path):
        return jsonify({"error": "No report found"}), 404
    
    try:
        with open(report_path, "r") as f:
            report = json.load(f)
        
        # Generate PDF report
        try:
            pdf_content = generate_pdf_report(report)
            from flask import Response
            return Response(
                pdf_content,
                mimetype="application/pdf",
                headers={"Content-Disposition": f"attachment;filename=security_report_{ip}_{time.strftime('%Y%m%d')}.pdf"}
            )
        except Exception as e:
            # Fallback to HTML if PDF generation fails
            html_content = generate_html_report(report)
            from flask import Response
            return Response(
                html_content,
                mimetype="text/html",
                headers={"Content-Disposition": f"attachment;filename=security_report_{ip}_{time.strftime('%Y%m%d')}.html"}
            )
            
    except Exception as e:
        return jsonify({"error": f"Failed to generate report: {str(e)}"}), 500


def generate_txt_report(report: dict) -> str:
    """Generate plain text report"""
    lines = []
    lines.append("="*80)
    lines.append("PISHIELD VULNERABILITY SCAN REPORT")
    lines.append("="*80)
    lines.append(f"Target: {report.get('target', 'Unknown')}")
    lines.append(f"Scan Date: {report.get('scan_date', 'Unknown')}")
    lines.append(f"Scanners Used: {', '.join(report.get('scanners_used', []))}")
    lines.append("="*80)
    lines.append("")
    
    # Summary
    summary = report.get('summary', {})
    lines.append("VULNERABILITY SUMMARY")
    lines.append("-"*80)
    lines.append(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    lines.append(f"  - Critical: {summary.get('critical', 0)}")
    lines.append(f"  - High: {summary.get('high', 0)}")
    lines.append(f"  - Medium: {summary.get('medium', 0)}")
    lines.append(f"  - Low: {summary.get('low', 0)}")
    lines.append(f"  - Info: {summary.get('info', 0)}")
    lines.append("")
    
    # Open Ports
    open_ports = report.get('open_ports', [])
    if open_ports:
        lines.append("OPEN PORTS")
        lines.append("-"*80)
        lines.append(f"{'Port':<8} {'Protocol':<10} {'Service':<15} {'Product':<20} {'Version'}")
        lines.append("-"*80)
        for port in open_ports:
            lines.append(f"{port.get('port', 'N/A'):<8} {port.get('protocol', 'N/A'):<10} {port.get('service', 'Unknown'):<15} {port.get('product', 'N/A'):<20} {port.get('version', 'N/A')}")
        lines.append("")
    
    # Individual scanner results
    lines.append("SCANNER RESULTS")
    lines.append("="*80)
    for scanner_name, result in report.get('results', {}).items():
        lines.append(f"\n[{scanner_name.upper()}]")
        lines.append("-"*80)
        lines.append(f"Status: {result.get('status', 'unknown')}")
        if 'error' in result:
            lines.append(f"Error: {result['error']}")
        if 'message' in result:
            lines.append(f"Message: {result['message']}")
        lines.append("")
    
    lines.append("="*80)
    lines.append("End of Report")
    lines.append("="*80)
    
    return "\n".join(lines)


def generate_html_report(report: dict) -> str:
    """Generate HTML report"""
    summary = report.get('summary', {})
    scanners = report.get('scanners_used', [])
    open_ports = report.get('open_ports', [])
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PiShield Scan Report - {report.get('target', 'Unknown')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2563eb; border-bottom: 3px solid #2563eb; padding-bottom: 10px; }}
        h2 {{ color: #1e40af; margin-top: 30px; }}
        .header {{ background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%); color: white; padding: 20px; margin: -30px -30px 30px -30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8fafc; border-left: 4px solid #2563eb; padding: 15px; }}
        .stat-card.critical {{ border-left-color: #dc2626; }}
        .stat-card.high {{ border-left-color: #ea580c; }}
        .stat-card.medium {{ border-left-color: #f59e0b; }}
        .stat-card.low {{ border-left-color: #84cc16; }}
        .stat-label {{ font-size: 12px; color: #64748b; text-transform: uppercase; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #1e293b; }}
        .scanner-result {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin: 10px 0; }}
        .scanner-name {{ font-weight: bold; color: #1e40af; font-size: 18px; }}
        .status {{ display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .status.success {{ background: #dcfce7; color: #166534; }}
        .status.warning {{ background: #fef3c7; color: #92400e; }}
        .status.error {{ background: #fee2e2; color: #991b1b; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f1f5f9; font-weight: bold; }}
        @media print {{ body {{ background: white; }} .container {{ box-shadow: none; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin: 0; border: none; color: white;">🛡️ PiShield Vulnerability Scan Report</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">Target: {report.get('target', 'Unknown')} | Scan Date: {report.get('scan_date', 'Unknown')}</p>
        </div>
        
        <h2>📊 Vulnerability Summary</h2>
        <div class="summary">
            <div class="stat-card">
                <div class="stat-label">Total Vulnerabilities</div>
                <div class="stat-value">{summary.get('total_vulnerabilities', 0)}</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-label">Critical</div>
                <div class="stat-value">{summary.get('critical', 0)}</div>
            </div>
            <div class="stat-card high">
                <div class="stat-label">High</div>
                <div class="stat-value">{summary.get('high', 0)}</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-label">Medium</div>
                <div class="stat-value">{summary.get('medium', 0)}</div>
            </div>
            <div class="stat-card low">
                <div class="stat-label">Low</div>
                <div class="stat-value">{summary.get('low', 0)}</div>
            </div>
        </div>
        
        <h2>🔍 Scanners Used ({len(scanners)})</h2>
        <p>{', '.join(scanners)}</p>
        
        <!-- Open Ports Section -->
        {f'''
        <h2>🌐 Open Ports ({len(open_ports)})</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
        ''' if open_ports else ''}
        {'''
                '''.join([f'''
                <tr>
                    <td>{port.get('port', 'N/A')}</td>
                    <td>{port.get('protocol', 'N/A')}</td>
                    <td>{port.get('service', 'Unknown')}</td>
                    <td>{port.get('product', 'N/A')}</td>
                    <td>{port.get('version', 'N/A')}</td>
                </tr>
                ''' for port in open_ports]) if open_ports else ''}
        {'''
            </tbody>
        </table>
        ''' if open_ports else ''}
        
        <h2>📋 Individual Scanner Results</h2>
'''
    
    for scanner_name, result in report.get('individual_results', {}).items():
        status = result.get('status', 'unknown')
        status_class = 'success' if status == 'success' else 'warning' if status == 'warning' else 'error'
        
        html += f'''
        <div class="scanner-result">
            <div class="scanner-name">{scanner_name.upper()}</div>
            <span class="status {status_class}">{status}</span>
            '''
        
        if 'error' in result:
            html += f'<p><strong>Error:</strong> {result["error"]}</p>'
        if 'message' in result:
            html += f'<p><strong>Message:</strong> {result["message"]}</p>'
        
        html += '</div>'
    
    html += '''
    </div>
</body>
</html>
'''
    
    return html


def generate_pdf_report(report: dict) -> bytes:
    """Generate professional PDF report with improved design"""
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.pdfgen import canvas
    from io import BytesIO
    import datetime
    
    # Create a BytesIO buffer to hold the PDF
    buffer = BytesIO()
    
    # Custom page template with header and footer
    def add_page_decorations(canvas_obj, doc):
        canvas_obj.saveState()
        # Header
        canvas_obj.setFillColor(colors.HexColor('#1e40af'))
        canvas_obj.rect(0, A4[1] - 50, A4[0], 50, fill=True, stroke=False)
        canvas_obj.setFillColor(colors.white)
        canvas_obj.setFont('Helvetica-Bold', 16)
        canvas_obj.drawString(72, A4[1] - 32, "iScan Security Report")
        
        # Footer
        canvas_obj.setFillColor(colors.HexColor('#6b7280'))
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.drawString(72, 30, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        canvas_obj.drawRightString(A4[0] - 72, 30, f"Page {doc.page}")
        canvas_obj.restoreState()
    
    # Create the PDF document
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=A4, 
        rightMargin=60, 
        leftMargin=60, 
        topMargin=70, 
        bottomMargin=50
    )
    
    # Define custom styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=10,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#1e40af'),
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#6b7280')
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceBefore=20,
        spaceAfter=12,
        textColor=colors.HexColor('#1e40af'),
        fontName='Helvetica-Bold',
        borderPadding=5,
        leftIndent=0
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading3'],
        fontSize=12,
        spaceBefore=10,
        spaceAfter=6,
        textColor=colors.HexColor('#374151'),
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#1f2937')
    )
    
    # Story to hold all elements
    story = []
    
    # Cover Page
    story.append(Spacer(1, 2*inch))
    story.append(Paragraph("VULNERABILITY SCAN REPORT", title_style))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(f"Target: <b>{report.get('target', 'Unknown')}</b>", subtitle_style))
    story.append(Paragraph(f"Scan Date: {report.get('scan_date', 'Unknown')}", subtitle_style))
    story.append(PageBreak())
    
    # Executive Summary Section
    story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
    story.append(Spacer(1, 0.2*inch))
    
    summary = report.get('summary', {})
    vulnerabilities_found = summary.get('vulnerabilities_found', 0)
    critical_issues = summary.get('critical_issues', 0)
    
    # Risk Assessment Box
    risk_level = "CRITICAL" if critical_issues > 0 else "HIGH" if vulnerabilities_found > 5 else "MEDIUM" if vulnerabilities_found > 0 else "LOW"
    risk_color = colors.HexColor('#dc2626') if risk_level == "CRITICAL" else colors.HexColor('#ea580c') if risk_level == "HIGH" else colors.HexColor('#f59e0b') if risk_level == "MEDIUM" else colors.HexColor('#10b981')
    
    risk_data = [[Paragraph(f"<b>OVERALL RISK LEVEL: {risk_level}</b>", ParagraphStyle('RiskText', parent=body_style, fontSize=14, textColor=colors.white, alignment=TA_CENTER))]]
    risk_table = Table(risk_data, colWidths=[6.5*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_color),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ('ROUNDEDCORNERS', [10, 10, 10, 10]),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Summary Statistics in Grid
    summary_data = [
        [
            Paragraph("<b>Total Scanners</b><br/><font size=18 color='#1e40af'>" + str(summary.get('total_scanners', 0)) + "</font>", body_style),
            Paragraph("<b>Successful Scans</b><br/><font size=18 color='#10b981'>" + str(summary.get('successful_scans', 0)) + "</font>", body_style),
            Paragraph("<b>Failed Scans</b><br/><font size=18 color='#ef4444'>" + str(summary.get('failed_scans', 0)) + "</font>", body_style),
        ],
        [
            Paragraph("<b>Vulnerabilities</b><br/><font size=18 color='#f59e0b'>" + str(vulnerabilities_found) + "</font>", body_style),
            Paragraph("<b>Critical Issues</b><br/><font size=18 color='#dc2626'>" + str(critical_issues) + "</font>", body_style),
            Paragraph("<b>Open Ports</b><br/><font size=18 color='#3b82f6'>" + str(len(summary.get('open_ports', []))) + "</font>", body_style),
        ]
    ]
    
    summary_table = Table(summary_data, colWidths=[2.17*inch, 2.17*inch, 2.17*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f9fafb')),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 1.5, colors.HexColor('#e5e7eb')),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ('ROUNDEDCORNERS', [5, 5, 5, 5]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Scan Information
    story.append(Paragraph("SCAN INFORMATION", heading_style))
    info_data = [
        ['Target IP Address:', report.get('target', 'Unknown')],
        ['Scan Profile:', report.get('profile', 'Standard').upper()],
        ['Scan Date & Time:', report.get('scan_date', 'Unknown')],
        ['Report ID:', report.get('scan_id', 'N/A')[:20] + '...' if len(report.get('scan_id', '')) > 20 else report.get('scan_id', 'N/A')],
        ['Scanners Used:', ', '.join(report.get('scanners_used', [])[:5]) + ('...' if len(report.get('scanners_used', [])) > 5 else '')]
    ]
    
    info_table = Table(info_data, colWidths=[2*inch, 4.5*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#eff6ff')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1f2937')),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dbeafe')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.4*inch))
    
    # Open Ports Section
    open_ports = summary.get('open_ports', [])
    if open_ports:
        story.append(Paragraph(f"OPEN PORTS ({len(open_ports)} detected)", heading_style))
        story.append(Spacer(1, 0.1*inch))
        
        port_data = [[
            Paragraph('<b>Port</b>', body_style),
            Paragraph('<b>Protocol</b>', body_style),
            Paragraph('<b>Service</b>', body_style),
            Paragraph('<b>State</b>', body_style)
        ]]
        
        for port in open_ports[:20]:  # Limit to 20 ports
            state_color = '#dc2626' if port.get('state') == 'open' else '#f59e0b'
            port_data.append([
                Paragraph(f"<b>{port.get('port', 'N/A')}</b>", body_style),
                Paragraph(port.get('protocol', 'tcp').upper(), body_style),
                Paragraph(port.get('service', 'Unknown'), body_style),
                Paragraph(f"<font color='{state_color}'><b>{port.get('state', 'unknown').upper()}</b></font>", body_style)
            ])
        
        port_table = Table(port_data, colWidths=[1*inch, 1.2*inch, 2.5*inch, 1.8*inch])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(port_table)
        story.append(Spacer(1, 0.3*inch))
    
    # Windows Vulnerabilities Section
    windows_vulns = report.get('windows_vulnerabilities', [])
    if windows_vulns:
        story.append(PageBreak())
        story.append(Paragraph(f"DETECTED VULNERABILITIES ({len(windows_vulns)})", heading_style))
        story.append(Spacer(1, 0.1*inch))
        
        for vuln in windows_vulns[:15]:  # Limit to 15 vulnerabilities
            severity = vuln.get('severity', 'Unknown')
            severity_color = '#dc2626' if severity in ['Critical', 'High'] else '#f59e0b' if severity == 'Medium' else '#10b981'
            
            vuln_content = [
                [Paragraph(f"<b>{vuln.get('type', 'Unknown Vulnerability')}</b>", subheading_style)],
                [Paragraph(f"<b>Severity:</b> <font color='{severity_color}'><b>{severity}</b></font>", body_style)],
                [Paragraph(f"<b>Description:</b> {vuln.get('description', 'No description available')}", body_style)]
            ]
            
            if vuln.get('recommendation'):
                vuln_content.append([Paragraph(f"<b>Recommendation:</b> {vuln.get('recommendation')}", body_style)])
            
            vuln_table = Table(vuln_content, colWidths=[6.5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fef3c7') if severity == 'Medium' else colors.HexColor('#fee2e2') if severity in ['Critical', 'High'] else colors.HexColor('#f0fdf4')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('BOX', (0, 0), (-1, -1), 1.5, colors.HexColor('#e5e7eb')),
            ]))
            story.append(vuln_table)
            story.append(Spacer(1, 0.15*inch))
    
    # Scanner Execution Details
    story.append(PageBreak())
    story.append(Paragraph("SCANNER EXECUTION DETAILS", heading_style))
    story.append(Spacer(1, 0.1*inch))
    
    results = report.get('results', {})
    scanner_summary_data = [[
        Paragraph('<b>Scanner</b>', body_style),
        Paragraph('<b>Status</b>', body_style),
        Paragraph('<b>Duration</b>', body_style)
    ]]
    
    for scanner_name, result in results.items():
        status = result.get('status', 'Unknown')
        status_color = '#10b981' if status == 'success' else '#f59e0b' if status == 'warning' else '#ef4444'
        duration = result.get('duration', 0)
        
        scanner_summary_data.append([
            Paragraph(scanner_name.replace('_', ' ').title(), body_style),
            Paragraph(f"<font color='{status_color}'><b>{status.upper()}</b></font>", body_style),
            Paragraph(f"{duration:.1f}s" if duration else 'N/A', body_style)
        ])
    
    scanner_table = Table(scanner_summary_data, colWidths=[3*inch, 2*inch, 1.5*inch])
    scanner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(scanner_table)
    
    # Footer
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph(
        "This report was automatically generated by iScan Security Scanner. "
        "For questions or concerns, please contact your security administrator.",
        ParagraphStyle('Footer', parent=body_style, fontSize=8, alignment=TA_CENTER, textColor=colors.HexColor('#6b7280'))
    ))
    
    # Build PDF with custom page template
    doc.build(story, onFirstPage=add_page_decorations, onLaterPages=add_page_decorations)
    
    # Get the PDF data
    pdf_data = buffer.getvalue()
    buffer.close()
    
    return pdf_data


def limit_scan_reports():
    """Limit stored reports to only the 5 most recent ones"""
    if not os.path.exists(SCANS_DIR):
        return
    
    # Get all scan directories with their modification times
    scan_dirs = []
    for item in os.listdir(SCANS_DIR):
        item_path = os.path.join(SCANS_DIR, item)
        if os.path.isdir(item_path):
            # Get the latest modification time of any file in the directory
            latest_mod_time = 0
            for root, dirs, files in os.walk(item_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    mod_time = os.path.getmtime(file_path)
                    if mod_time > latest_mod_time:
                        latest_mod_time = mod_time
            scan_dirs.append((item_path, latest_mod_time))
    
    # Sort by modification time (newest first)
    scan_dirs.sort(key=lambda x: x[1], reverse=True)
    
    # Remove directories beyond the 5 most recent
    for dir_path, mod_time in scan_dirs[5:]:
        try:
            import shutil
            shutil.rmtree(dir_path)
        except Exception as e:
            print(f"Failed to remove old scan directory {dir_path}: {e}")


def cleanup_old_scan_data(ip: str):
    """Remove old scan data for a specific IP before starting a new scan"""
    try:
        scan_dir = os.path.join(SCANS_DIR, ip.replace(".", "_"))
        if os.path.exists(scan_dir):
            import shutil
            shutil.rmtree(scan_dir)
            print(f"Cleaned up old scan data for {ip}")
    except Exception as e:
        print(f"Failed to clean up old scan data for {ip}: {e}")


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react_app(path):
    """Serve React app for all non-API routes"""
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
