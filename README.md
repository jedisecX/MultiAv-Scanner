# MultiAv-Scanner
This will have multiple versions.

MultiAVScanner.py

First: ClamAV or Windows Defender local scan

Then: VirusTotal cloud scan

Then: Print clean, infected, suspicious status



---

Important Note

You MUST replace:

VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"

with your actual API key from https://virustotal.com under your profile.

(They allow ~500 API calls/day free.)


---

Example Usage:

python3 multi_av_virustotal_scanner.py /path/to/suspicious_file.exe

