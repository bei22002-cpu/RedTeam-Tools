# Hat Program - Complete User Guide

## Quick Start

### On Windows (using WSL)
1. **First time only** — right-click `windows_setup.bat` > **Run as administrator**
2. **Every time** — double-click `run_hat_program.bat` (or in PowerShell: `.\hat-program\run_hat_program.bat`)

### On Linux
```bash
cd hat-program
python3 hat_program.py

# For full features (root required for some tools):
sudo python3 hat_program.py
```

### Install Optional Tools (Linux)
```bash
bash install.sh
```
This installs nmap, dig, curl, whois, openssl, tcpdump, and other tools that enhance the program's capabilities. The program works without them but with limited functionality.

---

## File Structure

```
hat-program/
|-- hat_program.py           # Main program - run this to start
|-- install.sh               # Linux tool installer script
|-- windows_setup.bat        # Windows: installs WSL + Ubuntu + tools
|-- run_hat_program.bat      # Windows: launches program through WSL
|-- GUIDE.md                 # This file
|-- HAT_PROGRAM_README.md    # Original readme
|-- modules/
    |-- utils.py             # Shared utilities (colors, menus, commands)
    |-- red_hat.py           # Offensive security tools
    |-- blue_hat.py          # Defensive security tools
    |-- black_hat.py         # Threat simulation (educational)
    |-- vulnerability_scanner.py  # CVE and config auditing
    |-- web_scanner.py       # Web application scanning
    |-- crypto_toolkit.py    # Cryptography tools
    |-- threat_intel.py      # OSINT and threat intelligence
    |-- auto_recon.py        # Automated reconnaissance pipelines
    |-- incident_response.py # Forensics and incident handling
    |-- report_generator.py  # Security report creation
    |-- dashboard.py         # Security posture overview
    |-- client_finder.py     # Find potential cybersecurity clients
```

---

## Main Program (`hat_program.py`)

This is the entry point. Run it and you get a menu with 14 options. Type a number to enter a module, type `0` to go back or exit.

---

## Module 1: Red Hat - Offensive Security (`red_hat.py`)

**Purpose:** Reconnaissance and penetration testing tools for finding vulnerabilities in networks and systems.

| # | Tool | What It Does | Example Use |
|---|------|-------------|-------------|
| 1 | Network Discovery | Finds live hosts on a network using ARP scan or ping sweep | Enter `192.168.1.0/24` to find all devices on your network |
| 2 | Port Scanner | Scans a target for open ports and running services | Enter an IP to see what ports are open (SSH, HTTP, etc.) |
| 3 | Banner Grabbing | Connects to a port and reads the service banner | Check what software version is running on port 80 |
| 4 | DNS Enumeration | Looks up all DNS records for a domain (A, MX, NS, TXT, etc.) | Enter `example.com` to see its DNS setup |
| 5 | OS Fingerprinting | Guesses the operating system based on ping TTL values | TTL=64 = Linux, TTL=128 = Windows |
| 6 | Traceroute | Maps the network path to a target | See every hop between you and a server |
| 7 | WHOIS Lookup | Gets registration info for a domain or IP | Find who owns a domain, when it was registered |
| 8 | HTTP Headers | Fetches and analyzes HTTP response headers | Check if a website has security headers (HSTS, CSP, etc.) |
| 9 | SSL/TLS Analysis | Inspects a website's SSL certificate | Check certificate expiry, issuer, encryption strength |
| 10 | Subdomain Enum | Brute-forces common subdomain names | Find `admin.example.com`, `api.example.com`, etc. |
| 11 | Tool Check | Shows which red team tools are installed on your system | Lists nmap, nikto, sqlmap, etc. and whether they're available |

**Best for:** Security assessments, penetration testing, network audits.
**Needs root?** Some tools (nmap ARP scan) work better with root.

---

## Module 2: Blue Hat - Defensive Security (`blue_hat.py`)

**Purpose:** Monitor, audit, and harden your own systems against attacks.

| # | Tool | What It Does | Example Use |
|---|------|-------------|-------------|
| 1 | System Security Audit | Full audit: OS info, pending updates, running/failed services | Quick overview of your system's security state |
| 2 | Firewall Status | Shows UFW, iptables, nftables, or firewalld rules | Verify your firewall is active and properly configured |
| 3 | Active Connections | Lists all current network connections | See what's connected to your machine right now |
| 4 | Process Analysis | Top CPU/memory users, root processes, suspicious process check | Find crypto miners or unauthorized software |
| 5 | User Account Audit | Lists users with shells, UID 0 accounts, empty passwords, recent logins | Find unauthorized accounts or failed login attempts |
| 6 | SUID/SGID Check | Finds files with elevated permissions | Detect potential privilege escalation paths |
| 7 | Log Analysis | Reads auth logs, syslog, kernel messages, failed SSH, sudo usage | Investigate security incidents from logs |
| 8 | Open Ports Audit | Lists all listening ports and checks for risky ones (Telnet, etc.) | Make sure only necessary ports are open |
| 9 | Cron Job Review | Reviews all scheduled tasks for suspicious entries | Find unauthorized cron jobs (reverse shells, downloads) |
| 10 | SSH Config Audit | Checks SSH configuration for security issues | Verify root login is disabled, key auth is enabled |
| 11 | Hardening Checklist | Runs 15+ checks and gives you a hardening score | Scored checklist: firewall, updates, SSH config, etc. |
| 12 | Tool Check | Shows which blue team tools are installed | Lists ss, netstat, ufw, fail2ban, etc. |

**Best for:** System administrators, compliance audits, hardening servers.
**Needs root?** Yes, for full functionality (reading logs, checking shadow file).

---

## Module 3: Black Hat - Threat Simulation (`black_hat.py`)

**Purpose:** Educational tools that demonstrate common attack techniques. **For authorized testing only.**

| # | Tool | What It Does | Example Use |
|---|------|-------------|-------------|
| 1 | Password Analyzer | Scores password strength (length, complexity, entropy, common patterns) | Test if `MyP@ss123!` is strong enough |
| 2 | Hash Cracker | Identifies hash types and tries common passwords against them | Paste an MD5 hash, it tries to crack it |
| 3 | Packet Capture | Captures live network packets with tcpdump/tshark | See traffic on your network in real-time |
| 4 | ARP Inspection | Checks ARP table for duplicate MACs (spoofing detection) | Detect man-in-the-middle attacks |
| 5 | Wireless Discovery | Finds wireless interfaces and scans for nearby Wi-Fi networks | See all Wi-Fi networks around you |
| 6 | Exploit Search | Searches exploit databases (searchsploit, NVD) for known vulnerabilities | Search for `apache 2.4` exploits |
| 7 | Reverse Shell Gen | Generates reverse shell one-liners in Bash, Python, PHP, etc. | For authorized pen testing engagements |
| 8 | Payload Encoding | Demonstrates Base64/hex encoding of payloads | See how attackers obfuscate commands |
| 9 | Stego Detection | Detects hidden data in image files | Check if images contain hidden messages |
| 10 | Metadata Extraction | Pulls metadata from files (EXIF, PDF info, etc.) | Find GPS coordinates, author info in photos/docs |
| 11 | Tool Check | Shows which offensive tools are installed | Lists hashcat, john, metasploit, etc. |

**Best for:** Security awareness training, authorized penetration testing.
**Needs root?** Yes for packet capture and wireless scanning.

---

## Module 4: Vulnerability Scanner (`vulnerability_scanner.py`)

**Purpose:** Find security vulnerabilities on your system and network.

| # | Tool | What It Does |
|---|------|-------------|
| 1 | Local Vuln Assessment | Comprehensive scan of your local system for vulnerabilities |
| 2 | Package CVE Check | Checks installed packages against known CVE databases |
| 3 | Web Vuln Scan | Scans a web server for common vulnerabilities (uses Nikto if available) |
| 4 | SSL/TLS Test | Tests SSL/TLS configuration for weak ciphers, protocols, etc. |
| 5 | SMB Vuln Check | Checks for SMB/Samba vulnerabilities (EternalBlue, etc.) |
| 6 | Config Audit | Audits Linux configuration: permissions, services, kernel settings |
| 7 | Docker Security | Audits Docker installation and running containers for issues |
| 8 | Kernel Exploit Suggester | Checks kernel version against known kernel exploits |
| 9 | Password Policy Audit | Reviews password policies, aging, complexity requirements |
| 10 | Service Version Check | Checks versions of running services against known vulnerabilities |

**Best for:** Vulnerability assessments, compliance scanning, system hardening.

---

## Module 5: Web Scanner (`web_scanner.py`)

**Purpose:** Assess web application security.

| # | Tool | What It Does |
|---|------|-------------|
| 1 | Tech Fingerprinting | Identifies web technologies (server, framework, CMS, CDN) |
| 2 | Directory Discovery | Finds hidden directories and files (uses gobuster/dirb or built-in wordlist) |
| 3 | Security Header Audit | Scores all security headers (HSTS, CSP, X-Frame-Options, etc.) |
| 4 | Cookie Analysis | Checks cookie flags (Secure, HttpOnly, SameSite) |
| 5 | Form Discovery | Finds all HTML forms and input fields on a page |
| 6 | JS File Analysis | Scans JavaScript files for API keys, secrets, endpoints |
| 7 | Robots/Sitemap | Reads robots.txt, sitemap.xml, and security.txt |
| 8 | WAF Detection | Detects Web Application Firewalls (Cloudflare, AWS WAF, etc.) |
| 9 | CMS Detection | Identifies WordPress, Joomla, Drupal, and other CMS platforms |
| 10 | Full Web Recon | Runs all of the above in one pipeline |

**Best for:** Web application penetration testing, website security assessments.

---

## Module 6: Crypto Toolkit (`crypto_toolkit.py`)

**Purpose:** Cryptographic operations - hashing, encryption, key generation.

| # | Tool | What It Does |
|---|------|-------------|
| 1 | Hash Generator | Hash any text with MD5, SHA-1, SHA-256, SHA-512, SHA3, BLAKE2, HMAC |
| 2 | File Hash Verifier | Calculate and compare file hashes to verify integrity |
| 3 | Base64 Encode/Decode | Encode or decode Base64 strings |
| 4 | Hex Encode/Decode | Encode or decode hexadecimal strings |
| 5 | Random Generator | Generate secure passwords, passphrases, and cryptographic keys |
| 6 | RSA Key Generator | Generate RSA key pairs (2048/4096-bit) |
| 7 | Self-Signed Cert | Generate a self-signed SSL/TLS certificate |
| 8 | Certificate Inspector | Inspect certificates from remote servers or local files |
| 9 | File Encrypt/Decrypt | Encrypt or decrypt files using AES-256-CBC or ChaCha20 |
| 10 | SSH Key Tool | Generate and analyze SSH keys (RSA, ED25519) |

**Best for:** DevOps, system administrators, anyone needing crypto operations.
**Works on Windows?** Most features use Python's hashlib (no Linux tools needed).

---

## Module 7: Threat Intel (`threat_intel.py`)

**Purpose:** OSINT (Open Source Intelligence) and threat intelligence gathering.

| # | Tool | What It Does |
|---|------|-------------|
| 1 | IP Reputation | Check an IP against DNS blocklists and reputation services |
| 2 | Domain Intelligence | Full domain analysis: DNS, CT logs, subdomains, HTTP, technologies |
| 3 | Email OSINT | Check email domain security: SPF, DMARC, DKIM records |
| 4 | Username OSINT | Check if a username exists across 10+ platforms (GitHub, Twitter, etc.) |
| 5 | Threat Feed Check | Check IPs/domains against ThreatFox and URLhaus threat feeds |
| 6 | Geolocation Lookup | Get geographic location of an IP address |
| 7 | Abuse Contact | Find the abuse contact for an IP or domain |
| 8 | Dark Web Check | Check for dark web mentions (requires Tor) |
| 9 | Social Media Footprint | Analyze social media presence for a person or organization |
| 10 | Breach Check | Check if credentials may have been exposed in data breaches |

**Best for:** Threat analysts, investigators, security researchers.

---

## Module 8: Auto Recon (`auto_recon.py`)

**Purpose:** Automated reconnaissance pipelines that run multiple tools in sequence.

| # | Tool | What It Does |
|---|------|-------------|
| 1 | Full Target Recon | 10-step pipeline: WHOIS, DNS, subdomains, ports, HTTP, SSL, traceroute, tech fingerprint, geolocation |
| 2 | Passive Recon | Gathers info without making direct connections to the target |
| 3 | Infrastructure Recon | Host discovery, OS detection, service enumeration on a network |
| 4 | Person/Org OSINT | OSINT focused on people or organizations |
| 5 | Custom Pipeline | Build your own recon pipeline by selecting which steps to run |

**Best for:** Penetration testers who want comprehensive automated recon.

---

## Module 9: Incident Response (`incident_response.py`)

**Purpose:** Handle security incidents - collect evidence, analyze threats, contain damage.

| # | Tool | What It Does |
|---|------|-------------|
| 1 | Live Triage | Captures volatile data: processes, connections, users, memory info |
| 2 | Forensic Timeline | Builds a timeline from system artifacts (file modifications, logs) |
| 3 | IOC Scanner | Scans for Indicators of Compromise: malware, rootkits, crypto miners, backdoors |
| 4 | Process Memory Analysis | Analyzes process memory for suspicious strings and injected code |
| 5 | Network Forensics | Captures network state and traffic for analysis |
| 6 | Filesystem Forensics | Checks for recently modified files, hidden files, deleted data |
| 7 | Malware Quarantine | Isolates suspicious files (moves + removes permissions) |
| 8 | Persistence Scan | Checks startup scripts, cron jobs, kernel modules for persistence |
| 9 | Evidence Collection | Packages system data with SHA-256 hash manifests for chain of custody |
| 10 | IR Checklist | Step-by-step incident response procedure checklist |

**Best for:** Incident responders, forensic analysts, SOC teams.
**Needs root?** Yes, for most features.

---

## Module 10: Report Generator (`report_generator.py`)

**Purpose:** Generate professional security reports in HTML and text formats.

| # | Tool | What It Does |
|---|------|-------------|
| 1 | Quick Security Report | Fast scan + report with key findings (HTML with dark theme) |
| 2 | Session Report | Generates report from findings collected during your session |
| 3 | Full System Report | Comprehensive 8-section system audit report |
| 4 | Network Assessment | Network-focused assessment report |
| 5 | Compliance Report | Compliance-focused summary with scoring |
| 6 | Export to JSON | Export all findings in JSON format |
| 7 | View Findings | Display all findings collected in this session |

**Best for:** Generating deliverables for clients, documenting assessments.
**Output:** HTML files (styled with dark theme) and plain text.

---

## Module 11: Dashboard (`dashboard.py`)

**Purpose:** At-a-glance security overview of your system.

| # | Tool | What It Does |
|---|------|-------------|
| 1 | Security Posture | Comprehensive overview of system security state |
| 2 | Quick Health Check | 10 pass/fail checks with a health score |
| 3 | Network Overview | Network interfaces, connections, DNS, routing info |
| 4 | User Activity | Recent logins, active users, sudo activity |
| 5 | Service Monitor | Status of running services |
| 6 | Security Scorecard | 100-point score across 4 categories with visual bars |

**Best for:** Quick security status checks, daily monitoring.

---

## Module 12: Client Finder (`client_finder.py`)

**Purpose:** Find potential clients for your cybersecurity services.

| # | Tool | What It Does |
|---|------|-------------|
| 1 | Scan Website Posture | Passively assesses a domain's security (SSL, headers, DNS) and gives a 0-100 score |
| 2 | Bulk Domain Audit | Scan multiple domains at once, ranked by priority |
| 3 | Expired SSL Finder | Find businesses with expired or expiring SSL certificates |
| 4 | Missing Headers Finder | Find businesses missing critical security headers |
| 5 | Local Business Discovery | Tips and search strategies for finding local businesses by industry |
| 6 | Tech Stack Profiler | Identify a business's technology stack (CMS, CDN, frameworks, hosting) |
| 7 | Prospect Report | Generate HTML/text report of all prospects with priority ranking |
| 8 | View Prospects | Display all prospects collected in this session |
| 9 | Export to CSV | Export prospects to CSV for importing into your CRM |
| 10 | Cold Outreach Emails | Generate personalized outreach email templates based on specific findings |

**How scoring works:**
- Starts at 100, deducts points for: missing SSL (-30), missing security headers (-5 each), no HTTPS redirect (-10), no SPF (-10), no DMARC (-10)
- Lower score = more security issues = higher-value prospect
- **HIGH-VALUE**: Score below 50 | **MODERATE**: 50-75 | **LOW**: Above 75

**Best for:** Cybersecurity consultants, MSPs, freelance security professionals.

---

## Utility Files

### `utils.py` - Shared Utilities
Used by all modules. Provides:
- **Colors** — ANSI color codes for terminal output
- **print_info/warning/error/status** — Colored output helpers
- **run_command** — Runs shell commands with timeout and error handling
- **check_tool** — Checks if a Linux tool is installed
- **check_root** — Checks if running as root (works on both Linux and Windows)
- **display_menu** — Renders numbered menus and handles input
- **validate_ip/validate_port** — Input validation

### `install.sh` - Tool Installer
Installs recommended Linux tools. Supports apt, yum, dnf, and pacman. Tools installed:
- **Networking:** nmap, masscan, netcat, curl, wget, whois, dnsutils
- **Analysis:** tcpdump, tshark, openssl, nikto
- **Forensics:** foremost, binwalk, exiftool, clamav
- **Other:** john, hydra, gobuster, dirb

### `windows_setup.bat` - Windows First-Time Setup
Run as Administrator. It:
1. Installs WSL (Windows Subsystem for Linux)
2. Installs Ubuntu inside WSL
3. Installs Python and Linux security tools inside Ubuntu
4. Only needs to be run once

### `run_hat_program.bat` - Windows Launcher
Double-click to launch the program through WSL. Automatically:
1. Checks that WSL and Ubuntu are available
2. Converts the Windows file path to a WSL path
3. Runs `python3 hat_program.py` inside Ubuntu

---

## Tips

- **Type `0` to go back** from any menu to the previous menu
- **Ctrl+C** interrupts the current operation and returns to the menu
- **Some tools need root** — run with `sudo` on Linux for full functionality
- **Missing tools are handled gracefully** — the program falls back to basic alternatives when specialized tools aren't installed
- **Reports are saved as HTML** — open them in any web browser for a styled dark-theme view
- **Client Finder prospects persist for the session** — scan multiple domains, then generate one report or export at the end
- **No internet required** for most defensive/local tools (Blue Hat, Dashboard, Crypto Toolkit)
- **Internet required** for: Client Finder scans, Threat Intel lookups, web scanning, WHOIS/DNS queries
