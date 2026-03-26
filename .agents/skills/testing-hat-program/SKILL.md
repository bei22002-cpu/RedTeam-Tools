# Testing the Hat Program CLI

## Overview
The Hat Program is an interactive menu-driven Python CLI cybersecurity toolkit at `hat-program/hat_program.py`. It requires Python 3.6+ with no third-party dependencies (stdlib only).

## How to Run
```bash
python3 hat-program/hat_program.py
# Some features need root:
sudo python3 hat-program/hat_program.py
```

## Menu Navigation
- The program uses numbered menus. Enter a number and press Enter.
- `0` always goes back/exits.
- 13 main menu options: 3 core hat modules + 8 new tool modules + System Info + About.

## Safe Local Testing (No Network / No Root)
These modules can be tested locally without making network connections or needing root:

1. **Dashboard (option 11)**
   - Quick Health Check (sub-option 2): Runs 10 local system checks with PASS/FAIL, shows a health score
   - Security Score Card (sub-option 6): Scores 4 categories (Authentication, Network, Hardening, Monitoring) out of 100
   - Security Posture Dashboard (sub-option 1): Shows system info, ports, users, disk, memory

2. **Crypto Toolkit (option 6)**
   - Hash Generator (sub-option 1): Hash any text with 8 algorithms. Verify with known values:
     - `hello world` -> MD5: `5eb63bbbe01eeed093cb22bb8f5acdc3`
     - `hello world` -> SHA-256: `b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9`
   - Base64 Encode/Decode (sub-option 3): Encode text and verify output
     - `Hat Program Test` -> `SGF0IFByb2dyYW0gVGVzdA==`
   - Hex Encode/Decode (sub-option 4)
   - Generate Random Passwords/Keys (sub-option 5)

3. **Report Generator (option 10)**
   - Quick Security Report (sub-option 1): Generates HTML/text report files in /tmp/

## Modules Requiring Network Access
- Web Scanner (option 5): Makes HTTP requests to target URLs
- Threat Intel (option 7): Queries external APIs (ThreatFox, URLhaus, ip-api.com)
- Auto Recon (option 8): Active scanning of targets

## Modules Requiring Root
- Incident Response (option 9): Some features need root for /proc access, tcpdump, etc.
- Vulnerability Scanner (option 4): Config audit and some checks need root

## Compilation Check
Verify all files compile without syntax errors:
```bash
cd hat-program && for f in hat_program.py modules/*.py; do python3 -m py_compile "$f" && echo "$f OK"; done
```

## Testing via Konsole
Since this is an interactive CLI, use konsole (GUI terminal) for visual testing:
```bash
nohup konsole --hold -e bash &>/dev/null &
```
Then type commands in the konsole window using computer use tools.

## Devin Secrets Needed
None - this tool uses only Python stdlib and local Linux utilities.
