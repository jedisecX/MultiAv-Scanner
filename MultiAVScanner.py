#!/usr/bin/env python3
# JediSecX Multi-AV Local + VirusTotal Scanner
# jedisec.com | jedisec.us | jedisec.cloud | jedisec.online | jedisec.me

import os
import sys
import subprocess
import platform
import hashlib
import requests
import shutil
import time

# ====== CONFIG ======
VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"  # <-- Change this to your VirusTotal API Key
# =====================

def scan_with_clamav(file_path):
    print("[*] Checking for ClamAV installation...")
    if not shutil.which("clamscan"):
        print("[-] ClamAV not installed. Please install it: sudo apt install clamav")
        return "ClamAV Not Installed"

    print("[*] Scanning with ClamAV...")
    try:
        result = subprocess.run(["clamscan", "--no-summary", file_path], capture_output=True, text=True)
        output = result.stdout.strip()

        if "OK" in output:
            return "CLEAN"
        elif "FOUND" in output:
            return "INFECTED"
        else:
            return "UNKNOWN RESULT"
    except Exception as e:
        return f"ERROR: {e}"

def scan_with_windows_defender(file_path):
    print("[*] Scanning with Windows Defender...")
    try:
        command = f'powershell.exe -Command "Start-MpScan -ScanPath \'{file_path}\' -ScanType CustomScan"'
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        output = result.stdout.strip()

        if "No threats" in output or "0 threats" in output:
            return "CLEAN"
        elif "threat" in output.lower() or "threats" in output.lower():
            return "INFECTED"
        else:
            return "UNKNOWN RESULT"
    except Exception as e:
        return f"ERROR: {e}"

def virustotal_scan(file_path):
    if VIRUSTOTAL_API_KEY == "YOUR_API_KEY_HERE":
        print("[-] No VirusTotal API key provided. Skipping VT scan.")
        return "VT Scan Skipped"

    print("[*] Scanning with VirusTotal...")

    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
            file_hash = hashlib.sha256(file_content).hexdigest()

        # Check if hash already exists on VT
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            harmless_count = data['data']['attributes']['last_analysis_stats']['harmless']
            suspicious_count = data['data']['attributes']['last_analysis_stats']['suspicious']

            print(f"[VT] Malicious: {malicious_count} | Harmless: {harmless_count} | Suspicious: {suspicious_count}")
            if malicious_count > 0 or suspicious_count > 0:
                return "INFECTED"
            else:
                return "CLEAN"
        elif response.status_code == 404:
            print("[VT] File not found on VirusTotal. Uploading...")
            url = "https://www.virustotal.com/api/v3/files"
            files = {"file": (os.path.basename(file_path), open(file_path, "rb"))}
            response = requests.post(url, headers=headers, files=files)

            if response.status_code == 200:
                print("[VT] Uploaded. Waiting 20 seconds for scan...")
                time.sleep(20)
                return virustotal_scan(file_path)  # Re-query after upload
            else:
                return f"VT Upload Failed: {response.status_code}"

        else:
            return f"VT Query Error: {response.status_code}"

    except Exception as e:
        return f"ERROR: {e}"

def main(file_path):
    if not os.path.isfile(file_path):
        print("[-] Invalid file path.")
        return

    print(f"[*] Starting Multi-AV + VirusTotal Scan on: {file_path}\n")
    
    os_type = platform.system().lower()

    if "linux" in os_type:
        local_result = scan_with_clamav(file_path)
    elif "windows" in os_type:
        local_result = scan_with_windows_defender(file_path)
    else:
        print("[-] Unsupported OS for local scanner.")
        local_result = "Not Scanned"

    print(f"\n[+] Local Scan Result: {local_result}\n")

    vt_result = virustotal_scan(file_path)

    print(f"\n[+] VirusTotal Scan Result: {vt_result}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} /path/to/file")
        sys.exit(1)

    main(sys.argv[1])
