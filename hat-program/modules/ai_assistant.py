"""
AI Assistant Module - Interactive Cybersecurity AI with Skill Upgrades
Comprehensive knowledge base for all Hat Program modules, optional OpenAI API
integration for advanced Q&A, and a skill upgrade system that installs/upgrades
tools and unlocks advanced capabilities.
"""

import os
import sys
import json
import time
import shutil
import urllib.request
import urllib.error
import ssl
from modules.utils import (
    run_command, check_tool, check_root, require_root,
    print_info, print_warning, print_error, print_status,
    print_section, print_banner, get_user_input, confirm_action,
    display_menu, Colors
)

# ─────────────────────────────────────────────
# Watch Dogs-style UI helpers
# ─────────────────────────────────────────────

def _ctos_print(text, color=Colors.CYAN, delay=0.01):
    """Print text with a ctOS-style typewriter effect."""
    prefix = f"{color}[ctOS]{Colors.RESET} "
    sys.stdout.write(prefix)
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")


def _ctos_banner():
    """Print ctOS-style banner."""
    art = f"""{Colors.CYAN}{Colors.BOLD}
    ┌─────────────────────────────────────────────────────────┐
    │  ██████╗████████╗ ██████╗ ███████╗     █████╗ ██╗      │
    │ ██╔════╝╚══██╔══╝██╔═══██╗██╔════╝    ██╔══██╗██║      │
    │ ██║        ██║   ██║   ██║███████╗    ███████║██║      │
    │ ██║        ██║   ██║   ██║╚════██║    ██╔══██║██║      │
    │ ╚██████╗   ██║   ╚██████╔╝███████║    ██║  ██║██║      │
    │  ╚═════╝   ╚═╝    ╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚═╝      │
    │                                                         │
    │  Hat Program AI Assistant v1.0                          │
    │  Type your question or 'help' for commands              │
    │  Type 'exit' to return to main menu                     │
    └─────────────────────────────────────────────────────────┘
{Colors.RESET}"""
    print(art)


# ─────────────────────────────────────────────
# Knowledge Base - covers every module
# ─────────────────────────────────────────────

KNOWLEDGE_BASE = {
    # ── Main program ──
    "getting started": {
        "answer": """To get started with the Hat Program:
1. Run: sudo python3 hat_program.py
2. You'll see the main menu with 22 options
3. Pick a number (1-22) to enter any module
4. Each module has its own sub-menu with specific tools
5. Option 0 always goes back or exits

Running as root (sudo) gives you full access to all tools. Without root, some
network scanning and packet capture features will be limited.

The program is organized into three tiers:
  - RED HAT (options 1, 13-14, 16, 18-19): Offensive security
  - BLUE HAT (option 2, 9-11): Defensive security
  - BLACK HAT (option 3): Threat simulation
  - TOOLS (options 4-8, 12, 20): Specialized scanners and utilities""",
        "keywords": ["start", "begin", "run", "launch", "how to", "getting started", "first time", "setup", "install"]
    },
    "main menu": {
        "answer": """The main menu has 22 options:

CORE MODULES:
  1. Red Hat        - Offensive Security / Penetration Testing
  2. Blue Hat       - Defensive Security / Monitoring & Hardening
  3. Black Hat      - Threat Simulation / Security Awareness

TOOL MODULES:
  4. Vuln Scanner   - CVE Checks, Config Audits, SSL/Docker/Kernel
  5. Web Scanner    - Directory Discovery, Headers, WAF, CMS, Tech
  6. Crypto Toolkit - Hashing, Encryption, Certificates, SSH Keys
  7. Threat Intel   - IP Reputation, OSINT, Threat Feeds, Breaches
  8. Auto Recon     - Automated Reconnaissance Pipelines

OPERATIONS:
  9. Incident Response - Live Triage, Forensics, IOC Scanning
  10. Report Generator - HTML/Text Reports, Compliance Scoring
  11. Dashboard        - Security Posture, Health Check, Scorecard
  12. Client Finder    - Find Prospects, Audit Domains, Outreach

ADVANCED (v3.0):
  13. Bluetooth Scanner  - BLE/Classic Scan, RFCOMM, OBEX
  14. WiFi Attack Suite  - Deauth, Evil Twin, WPS, PMKID
  15. Forensics & Malware - PE/ELF, YARA, Memory, Disk
  16. Evasion & Tunneling - SSH/DNS/ICMP Tunnels, Proxy Chains
  17. AD & LDAP Tools    - Kerberoast, PTH, BloodHound, SMB
  18. Exploitation       - Buffer Overflow, Shellcode, ROP
  19. Social Engineering - Phishing, Pretexting, USB Payloads
  20. API Security       - REST/GraphQL, JWT, SQLi, CORS, SSRF

SYSTEM:
  21. System Information
  22. About""",
        "keywords": ["menu", "options", "list", "modules", "what can", "features", "capabilities"]
    },

    # ── Red Hat ──
    "red hat": {
        "answer": """Red Hat (Option 1) - Offensive Security & Penetration Testing

11 tools for network reconnaissance and enumeration:
  1. Network Discovery    - Find live hosts on a network (nmap -sn)
  2. Port Scanner         - Scan for open ports on a target
  3. DNS Enumeration      - Query DNS records (A, MX, NS, TXT, etc.)
  4. Banner Grabbing      - Identify service versions on open ports
  5. OS Fingerprinting    - Detect remote operating system (nmap -O)
  6. Traceroute           - Map network path to target
  7. WHOIS Lookup         - Domain registration info
  8. HTTP Header Analysis - Check web server headers for security issues
  9. SSL/TLS Analysis     - Check certificate details and cipher suites
  10. Subdomain Enum      - Discover subdomains of a target domain
  11. Full Port Scan      - Comprehensive scan of all 65535 ports

USAGE: Pick option 1 from the main menu, then choose a tool. You'll be
asked for a target IP or hostname. Most tools require nmap to be installed.

EXAMPLE WORKFLOW:
  1. Network Discovery -> find live hosts on 192.168.1.0/24
  2. Port Scanner -> scan interesting hosts
  3. Banner Grabbing -> identify services
  4. OS Fingerprinting -> identify OS
  5. Use Vuln Scanner (option 4) to check for CVEs""",
        "keywords": ["red hat", "offensive", "pentest", "penetration", "attack", "scan", "nmap", "reconnaissance", "recon"]
    },

    # ── Blue Hat ──
    "blue hat": {
        "answer": """Blue Hat (Option 2) - Defensive Security & System Hardening

12 tools for monitoring and protecting your system:
  1. System Security Audit   - Check system config, permissions, services
  2. Firewall Inspection     - View iptables/ufw/firewalld rules
  3. Connection Monitor      - See active network connections (netstat/ss)
  4. Process Analysis        - Find suspicious running processes
  5. User Account Audit      - Check for weak accounts, sudo users
  6. SUID/SGID Checker       - Find files with elevated permissions
  7. Log Analysis            - Parse auth/syslog for suspicious events
  8. Open Port Audit         - Check listening ports and services
  9. Cron Job Review         - Audit scheduled tasks for persistence
  10. SSH Hardening Check    - Verify SSH config security
  11. System Hardening       - Full checklist with scoring (pass/fail)
  12. File Integrity Check   - Monitor critical file changes

BEST USE: Run the System Hardening checklist (option 11) first to get
an overall score, then fix the issues it identifies.""",
        "keywords": ["blue hat", "defensive", "defense", "harden", "monitor", "protect", "security audit", "firewall"]
    },

    # ── Black Hat ──
    "black hat": {
        "answer": """Black Hat (Option 3) - Fully Functional Threat Simulation

72 functions across 12 tool categories - all execute real operations:
  1. Password Analysis    - Test password strength, entropy, crack time
  2. Hash Cracking        - Dictionary + brute force + hashcat/john
  3. Hash Generator       - MD5, SHA1, SHA256, SHA512, BLAKE2
  4. Packet Capture       - tcpdump/tshark with duration limits
  5. Wireless Scanning    - WiFi discovery, monitor mode, channel hop
  6. ARP Analysis         - ARP table, spoof detection, cache poison
  7. Exploit Search       - searchsploit + NVD API lookups
  8. Reverse Shell Gen    - Bash/Python/Netcat/PowerShell/PHP shells
  9. Payload Encoding     - Base64/Hex/ROT13/URL/XOR + multi-layer
  10. Steganography       - steghide/binwalk/LSB analysis
  11. Metadata Extract    - exiftool extraction and stripping
  12. Tool Availability   - Check 37+ tools with auto-install

EXAMPLE: To crack a hash:
  Option 3 -> Option 2 (Hash Cracking) -> Paste your hash
  It will try dictionary attack first, then brute force if needed.""",
        "keywords": ["black hat", "threat", "simulation", "crack", "hash", "password", "exploit", "shell", "payload"]
    },

    # ── Vulnerability Scanner ──
    "vulnerability scanner": {
        "answer": """Vulnerability Scanner (Option 4) - Local & Remote Vuln Assessment

10 scanning modules:
  1. Local Package CVE Check  - Check installed packages for known CVEs
  2. Web Vuln Scanner         - Nikto integration for web servers
  3. SSL/TLS Vulnerability    - Check for Heartbleed, POODLE, weak ciphers
  4. SMB Vulnerability Check  - EternalBlue, SMB signing, null sessions
  5. Linux Config Audit       - Permissions, services, kernel parameters
  6. Docker Security Audit    - Container config, image vulns, daemon settings
  7. Kernel Exploit Suggester - Check kernel version against known exploits
  8. Password Policy Audit    - PAM config, aging, complexity rules
  9. Service Version Check    - Compare running services against vuln databases
  10. Full Vulnerability Scan - Run all checks in sequence

TIP: Start with option 10 (Full Scan) to get a comprehensive overview,
then drill into specific areas that need attention.""",
        "keywords": ["vuln", "vulnerability", "cve", "exploit", "nikto", "ssl", "smb", "docker", "kernel"]
    },

    # ── Web Scanner ──
    "web scanner": {
        "answer": """Web Application Scanner (Option 5) - Web Security Testing

11 tools for web application security:
  1. Technology Fingerprint  - Detect CMS, frameworks, server tech
  2. Directory Discovery     - Find hidden paths (gobuster/dirb/fallback)
  3. Security Header Audit   - Check headers with scoring
  4. Cookie Analysis         - Check cookie security flags
  5. Form & Input Discovery  - Find all forms and input fields
  6. JavaScript Analysis     - Scan JS files for secrets/API keys
  7. robots.txt/sitemap      - Parse robots.txt and sitemap.xml
  8. WAF Detection           - Identify Web Application Firewalls
  9. CMS Detection           - WordPress/Drupal/Joomla specific checks
  10. Full Web Recon         - Run all tools in pipeline
  11. security.txt Check     - Check for security.txt file

EXAMPLE: Scan a website:
  Option 5 -> Option 10 (Full Web Recon) -> Enter URL
  This runs all 10 checks in sequence and shows results.""",
        "keywords": ["web", "website", "http", "directory", "header", "cookie", "waf", "cms", "wordpress"]
    },

    # ── Crypto Toolkit ──
    "crypto toolkit": {
        "answer": """Cryptography Toolkit (Option 6) - Crypto Operations

9 cryptographic tools:
  1. Hash Generator       - MD5, SHA1, SHA256, SHA512, BLAKE2, HMAC
  2. File Hash Verifier   - Verify file integrity with known hashes
  3. Encode/Decode        - Base64 and hex encoding/decoding
  4. Password Generator   - Random passwords, passphrases, keys
  5. RSA Key Generator    - Generate RSA key pairs (2048/4096 bit)
  6. Certificate Generator - Create self-signed SSL certificates
  7. Certificate Inspector - Examine remote or local certificates
  8. File Encryption      - AES-256-CBC and ChaCha20 encryption
  9. SSH Key Generator    - Generate ED25519/RSA SSH key pairs

Works 100% without any external tools - pure Python implementations.
Great for CTFs and daily crypto operations.""",
        "keywords": ["crypto", "hash", "encrypt", "decrypt", "certificate", "ssl", "rsa", "ssh key", "password generate"]
    },

    # ── Threat Intel ──
    "threat intel": {
        "answer": """Threat Intelligence & OSINT (Option 7) - Open Source Intelligence

10 intelligence gathering tools:
  1. IP Reputation       - Check IPs against DNS blocklists + ipinfo.io
  2. Domain Intelligence - DNS + CT logs + subdomain enumeration
  3. Email OSINT         - SPF/DMARC/DKIM verification
  4. Username OSINT      - Search 10+ platforms for a username
  5. Threat Feed Check   - ThreatFox and URLhaus API lookups
  6. IP Geolocation      - Geographic location of IP addresses
  7. Abuse Contact       - Find abuse contacts for an IP/domain
  8. Dark Web Check      - Tor-based .onion checks
  9. Social Media Footprint - Social media presence analysis
  10. Data Breach Resources - Links to breach checking services

EXAMPLE: Investigate a suspicious IP:
  Option 7 -> Option 1 (IP Reputation) -> Enter IP
  Then Option 6 (Geolocation) to see where it's from.""",
        "keywords": ["threat", "intel", "osint", "reputation", "ip", "domain", "email", "username", "breach"]
    },

    # ── Auto Recon ──
    "auto recon": {
        "answer": """Automated Reconnaissance (Option 8) - Recon Pipelines

5 automated reconnaissance modes:
  1. Full Target Recon     - 10-step pipeline: WHOIS -> DNS -> subdomains ->
                             ports -> HTTP -> SSL -> traceroute -> tech -> geo
  2. Passive Recon Only    - No active scanning, OSINT only
  3. Infrastructure Recon  - Host discovery + OS detection + services
  4. Person/Org OSINT      - Search for people or organizations
  5. Custom Pipeline       - Build your own recon workflow

EXAMPLE: Full recon on a domain:
  Option 8 -> Option 1 -> Enter domain (e.g. example.com)
  Runs all 10 steps automatically and shows results.""",
        "keywords": ["auto", "recon", "reconnaissance", "pipeline", "automate", "scan all"]
    },

    # ── Incident Response ──
    "incident response": {
        "answer": """Incident Response (Option 9) - Forensics & Triage

10 IR tools:
  1. Live System Triage    - Collect volatile data (memory, connections, processes)
  2. Forensic Timeline     - Build timeline of system events
  3. IOC Scanner           - Scan for indicators of compromise
  4. Process Memory Analysis - Analyze process memory maps
  5. Network Forensics     - Capture and analyze network traffic
  6. Filesystem Forensics  - Find recently modified/suspicious files
  7. Malware Quarantine    - Isolate suspicious files with ClamAV
  8. Persistence Scanner   - Check for backdoors and persistence
  9. Evidence Collection   - Collect evidence with SHA-256 manifests
  10. IR Checklist         - Step-by-step incident response procedure

EXAMPLE: Respond to a suspected breach:
  Option 9 -> Option 1 (Live Triage) first to collect volatile data
  Then Option 3 (IOC Scanner) to look for malicious indicators.""",
        "keywords": ["incident", "response", "forensic", "triage", "ioc", "malware", "quarantine", "evidence"]
    },

    # ── Report Generator ──
    "report generator": {
        "answer": """Report Generator (Option 10) - Professional Security Reports

7 report types:
  1. Quick Security Report  - Summary HTML/text report
  2. Session Report         - Report from collected findings
  3. Full System Audit      - 8-section comprehensive audit report
  4. Network Assessment     - Network-focused report
  5. Compliance Report      - Compliance scoring report
  6. JSON Export            - Machine-readable data export
  7. Findings Viewer        - Review collected findings

Reports are saved as HTML and/or text files in the current directory.
Great for presenting findings to clients.""",
        "keywords": ["report", "generate", "html", "compliance", "audit report", "findings", "export"]
    },

    # ── Dashboard ──
    "dashboard": {
        "answer": """Security Dashboard (Option 11) - Overview & Scoring

6 dashboard views:
  1. Security Posture Overview  - Overall security status
  2. Quick Health Check         - 10 pass/fail checks with score
  3. Network Status Overview    - Network connections and interfaces
  4. User Activity Summary      - Login history and user stats
  5. Service Status Monitor     - Running services check
  6. Security Scorecard         - 4 categories, 100-point scale

EXAMPLE: Quick system check:
  Option 11 -> Option 2 (Quick Health Check)
  Shows 10 checks with pass/fail and a Health Score out of 10.""",
        "keywords": ["dashboard", "score", "health", "posture", "overview", "status"]
    },

    # ── Client Finder ──
    "client finder": {
        "answer": """Client Finder (Option 12) - Find Cybersecurity Clients

10 business development tools:
  1. Domain Security Scan    - Score a website's security 0-100
  2. Bulk Domain Audit       - Scan multiple domains at once
  3. SSL Expiry Finder       - Find sites with expiring certificates
  4. Missing Headers Finder  - Find sites missing security headers
  5. Local Business Discovery - Find businesses by industry/location
  6. Tech Stack Profiler     - Identify CMS, CDN, frameworks
  7. Prospect Report         - Generate HTML/text prospect reports
  8. CSV Export              - Export prospects for CRM import
  9. Outreach Email Gen      - Create personalized cold emails
  10. View Prospects         - Review saved prospects

WORKFLOW: Scan domains -> Score them -> Generate reports -> Create outreach emails""",
        "keywords": ["client", "finder", "prospect", "business", "outreach", "email", "crm", "sales"]
    },

    # ── Bluetooth Scanner ──
    "bluetooth scanner": {
        "answer": """Bluetooth & BLE Scanner (Option 13) - Wireless Device Scanning

10 tools for Bluetooth security testing:
  1. Classic BT Scan       - Scan for classic Bluetooth devices (hcitool)
  2. BLE Device Scan       - Scan for Bluetooth Low Energy devices
  3. Device Info            - Get detailed info and SDP services
  4. SDP Enumeration       - Service Discovery Protocol scanning
  5. RFCOMM Channel Scan   - Scan RFCOMM channels 1-30
  6. OBEX File Browser     - Browse files via OBEX protocol
  7. Signal Monitor        - Monitor RSSI signal strength
  8. L2CAP Ping            - L2CAP connectivity test
  9. Interface Info         - Show Bluetooth adapter info
  10. Tool Check           - Check 17 available BT tools

REQUIRES: bluez, bluetooth tools. Install: sudo apt install bluez""",
        "keywords": ["bluetooth", "ble", "rfcomm", "obex", "sdp", "hcitool", "wireless device"]
    },

    # ── WiFi Attacks ──
    "wifi attacks": {
        "answer": """WiFi Attack Suite (Option 14) - Wireless Security Testing

12 tools for WiFi penetration testing:
  1. Interface Management  - Monitor mode, channel, MAC, TX power
  2. WiFi Recon            - Scan networks with airodump-ng
  3. Deauth Attack         - Deauthentication with aireplay-ng
  4. WPS Attack            - WPS PIN brute force (reaver/bully)
  5. PMKID Capture         - PMKID hash capture for offline cracking
  6. Handshake Crack       - WPA/WPA2 capture and cracking
  7. Evil Twin AP          - Rogue access point with hostapd
  8. Karma Attack          - Karma/MANA attack setup
  9. Rogue AP Detection    - Detect unauthorized access points
  10. Jamming Detection    - Detect WiFi interference
  11. Captive Portal       - Create captive portal for testing
  12. Tool Check           - Check 21 available WiFi tools

REQUIRES: aircrack-ng suite. Install: sudo apt install aircrack-ng

WARNING: Only use on networks you own or have written authorization to test.
Deauthentication and jamming attacks are illegal without authorization.""",
        "keywords": ["wifi", "wireless", "deauth", "evil twin", "wps", "pmkid", "handshake", "aircrack", "wpa"]
    },

    # ── Forensics & Malware ──
    "forensics malware": {
        "answer": """Forensics & Malware Analysis (Option 15) - Digital Forensics

16 tools for forensic analysis:
  1. Binary Analysis       - PE/ELF file analysis with entropy
  2. Hash Lookup           - Check hashes against MalwareBazaar/VirusTotal
  3. String Analysis       - Extract URLs, IPs, emails, registry keys
  4. YARA Scan             - Scan with YARA rules
  5. Memory Analysis       - Analyze memory dumps (Volatility)
  6. Disk Forensics        - Analyze disk images (Sleuth Kit)
  7. File Carving          - Recover deleted files (foremost/scalpel)
  8. Timeline Analysis     - Build forensic timeline
  9. Sandbox Detection     - Detect VM/sandbox indicators
  10. Malware Triage       - Generate malware triage report
  11. Registry Analysis    - Offline Windows registry analysis
  12. Log Correlation      - Correlate events across log sources
  13. Tool Check           - Check 23 available forensics tools

EXAMPLE: Analyze a suspicious file:
  Option 15 -> Option 1 (Binary Analysis) -> Enter file path""",
        "keywords": ["forensic", "malware", "binary", "yara", "memory", "disk", "carve", "volatility", "sleuth"]
    },

    # ── Evasion & Tunneling ──
    "evasion tunneling": {
        "answer": """Firewall Evasion & Tunneling (Option 16) - Network Evasion

11 evasion and tunneling tools:
  1. SSH Tunnel          - Local/remote/dynamic port forwarding
  2. DNS Tunneling       - iodine/dnscat2/manual DNS exfil
  3. ICMP Tunneling      - ptunnel-ng data over ping
  4. HTTP/HTTPS Tunnel   - chisel/socat/stunnel wrappers
  5. Proxy Chain         - proxychains4 setup and testing
  6. Traffic Obfuscation - 9 nmap evasion techniques
  7. Port Knocking       - knock sequences to open hidden ports
  8. Covert Channels     - TCP timestamp/ICMP/DNS TXT/HTTP header
  9. Firewall Analysis   - iptables/nftables/ufw/firewalld review
  10. NAT Traversal      - STUN/UPnP/NAT-PMP
  11. Tool Check         - Check 17 available evasion tools

EXAMPLE: Set up a SOCKS proxy through SSH:
  Option 16 -> Option 1 (SSH Tunnel) -> Option 3 (Dynamic SOCKS)
  Then use: curl --socks5 localhost:1080 http://example.com""",
        "keywords": ["evasion", "tunnel", "ssh", "dns tunnel", "icmp", "proxy", "proxychains", "covert", "firewall"]
    },

    # ── AD & LDAP ──
    "ad ldap": {
        "answer": """Active Directory & LDAP (Option 17) - Domain Attacks

11 AD/LDAP attack tools:
  1. LDAP Enumeration     - Anonymous/authenticated queries
  2. AD Domain Enum       - enum4linux/rpcclient/DNS SRV
  3. Kerberos Attacks      - Kerberoasting, AS-REP roasting
  4. Pass-the-Hash/Ticket - PTH/PTT/overpass-the-hash/DCSync
  5. SMB Enumeration      - Share listing, CrackMapExec
  6. BloodHound Collection - Map AD relationships
  7. Password Spraying    - Spray passwords against AD users
  8. GPP Passwords        - Extract Group Policy Preference passwords
  9. NTLM Relay           - ntlmrelayx setup
  10. AD Certificate Abuse - ADCS ESC1-ESC8 via certipy
  11. Tool Check           - Check 20 available AD tools

REQUIRES: Impacket suite. Install: pip install impacket
Also useful: bloodhound, certipy-ad, crackmapexec""",
        "keywords": ["active directory", "ad", "ldap", "kerberos", "kerberoast", "pass the hash", "pth", "bloodhound", "smb", "ntlm"]
    },

    # ── Advanced Exploitation ──
    "exploitation": {
        "answer": """Advanced Exploitation (Option 18) - Exploit Development

10 exploit development tools:
  1. Buffer Overflow Helper - Cyclic pattern, offset finder, bad chars
  2. Shellcode Generator    - Linux/Windows shellcode + msfvenom
  3. ROP Gadget Finder      - ROPgadget/ropper for ROP chains
  4. Protocol Fuzzer        - TCP/HTTP/buffer overflow fuzzing
  5. Format String Helper   - Format string exploit payloads
  6. Metasploit Interface   - Search exploits, generate payloads
  7. Exploit Compiler       - Compile C/ASM/Python exploits
  8. Return Address Finder  - Find JMP ESP/CALL ESP gadgets
  9. Egg Hunter Generator   - Generate egg hunter shellcode
  10. Tool Check            - Check 17 available exploit tools

EXAMPLE: Develop a buffer overflow exploit:
  Option 18 -> Option 1 -> Generate cyclic pattern (500 bytes)
  Send pattern to target, find crash offset
  Option 1 -> Find pattern offset -> Enter EIP value
  Option 2 -> Generate shellcode for your target""",
        "keywords": ["exploit", "buffer overflow", "shellcode", "rop", "fuzz", "metasploit", "msfvenom", "format string"]
    },

    # ── Social Engineering ──
    "social engineering": {
        "answer": """Social Engineering Toolkit (Option 19) - SE Attacks

11 social engineering tools:
  1. Phishing Email Gen     - 6 templates (password reset, IT support, etc.)
  2. Credential Harvester   - Login page clones with capture server
  3. USB Rubber Ducky       - DuckyScript payload creator
  4. QR Code Attacks        - Malicious QR code generation
  5. Pretexting Scripts      - 5 scenario scripts
  6. Spearphish Campaign    - Campaign planning tool
  7. Vishing Scripts        - Voice phishing scripts
  8. Physical Security      - Physical assessment checklist
  9. Awareness Report       - Training report generator
  10. Website Cloner        - Clone sites for testing (wget/httrack)
  11. Tool Check            - Check 14 available SE tools

ALL TOOLS REQUIRE WRITTEN AUTHORIZATION before use on real targets.""",
        "keywords": ["social engineering", "phishing", "pretexting", "vishing", "usb", "rubber ducky", "credential"]
    },

    # ── API Security ──
    "api security": {
        "answer": """API Security Scanner (Option 20) - API Penetration Testing

12 API security tools:
  1. Endpoint Discovery    - Test 40+ common API paths + Swagger parsing
  2. Auth Testing          - IDOR, method tampering, default tokens
  3. Rate Limit Test       - Detect missing rate limiting
  4. SQL Injection         - 11 SQLi payloads with detection
  5. GraphQL Attacks       - Introspection, depth, batching, mutations
  6. JWT Analyzer          - Decode, check expiry, find weaknesses
  7. Parameter Fuzzer      - 10 payload categories
  8. CORS Tester           - Test for CORS misconfigurations
  9. Mass Assignment       - Test privileged field injection
  10. SSRF Detection       - 12 SSRF payloads (cloud metadata)
  11. API Doc Parser       - Analyze Swagger/OpenAPI documentation
  12. Tool Check           - Check 15 available API tools

EXAMPLE: Test an API:
  Option 20 -> Option 1 (Endpoint Discovery) -> Enter base URL
  Then Option 2 (Auth Testing) to check for auth bypasses.""",
        "keywords": ["api", "rest", "graphql", "jwt", "token", "cors", "ssrf", "sql injection", "sqli", "endpoint"]
    },

    # ── How-To Guides ──
    "scan a network": {
        "answer": """How to scan a network:

QUICK SCAN:
  Main Menu -> Option 1 (Red Hat) -> Option 1 (Network Discovery)
  Enter target: 192.168.1.0/24 (scans your local network)

DETAILED SCAN:
  1. Network Discovery -> find live hosts
  2. Port Scanner -> scan each live host
  3. Banner Grabbing -> identify services
  4. OS Fingerprinting -> identify operating systems

FULL AUTO SCAN:
  Main Menu -> Option 8 (Auto Recon) -> Option 3 (Infrastructure Recon)
  This runs host discovery + OS detection + service enum automatically.

STEALTH SCAN:
  Main Menu -> Option 16 (Evasion) -> Option 6 (Traffic Obfuscation)
  Use fragmented packets, decoys, or timing evasion.""",
        "keywords": ["scan network", "network scan", "find hosts", "discover", "nmap scan", "port scan"]
    },

    "crack a password": {
        "answer": """How to crack passwords/hashes:

HASH CRACKING:
  Main Menu -> Option 3 (Black Hat) -> Option 2 (Hash Cracking)
  1. Paste your hash (MD5, SHA1, SHA256, etc.)
  2. It auto-detects the hash type
  3. Tries dictionary attack first (built-in wordlist)
  4. Then brute force if dictionary fails
  5. Can also use hashcat/john if installed

PASSWORD STRENGTH TESTING:
  Main Menu -> Option 3 (Black Hat) -> Option 1 (Password Analysis)
  Enter a password to test - shows entropy, strength score, crack time.

TIPS:
  - For faster cracking, use hashcat with GPU: hashcat -m 0 hash.txt rockyou.txt
  - Download rockyou.txt wordlist for better coverage
  - John the Ripper also works: john --format=raw-md5 hash.txt""",
        "keywords": ["crack", "password", "hash", "brute force", "dictionary", "hashcat", "john", "rockyou"]
    },

    "find vulnerabilities": {
        "answer": """How to find vulnerabilities:

AUTOMATED SCANNING:
  1. Option 4 (Vuln Scanner) -> Option 10 (Full Scan) - comprehensive local check
  2. Option 5 (Web Scanner) -> Option 10 (Full Web Recon) - web app assessment
  3. Option 8 (Auto Recon) -> Option 1 (Full Target Recon) - full external recon

MANUAL APPROACH:
  1. Scan ports: Option 1 (Red Hat) -> Port Scanner
  2. Check services: Option 4 (Vuln Scanner) -> Service Version Check
  3. Check web: Option 5 (Web Scanner) -> Security Header Audit
  4. Check SSL: Option 4 (Vuln Scanner) -> SSL/TLS Vulnerability
  5. Check config: Option 4 (Vuln Scanner) -> Linux Config Audit

API TESTING:
  Option 20 (API Security) -> Start with Endpoint Discovery, then Auth Testing

EXPLOIT SEARCH:
  Option 3 (Black Hat) -> Option 7 (Exploit Search)
  Search searchsploit and NVD for known exploits.""",
        "keywords": ["find vuln", "vulnerability", "pentest", "assessment", "audit", "security test"]
    },

    "install tools": {
        "answer": """How to install all required tools:

QUICK INSTALL (one command):
  sudo apt update && sudo apt install -y nmap dnsutils whois curl openssl \\
    net-tools tcpdump nikto hydra john aircrack-ng bluez hcitool reaver \\
    hashcat foremost binwalk exiftool steghide gobuster enum4linux \\
    smbclient ldap-utils proxychains4 socat knockd qrencode wget

PYTHON TOOLS:
  pip install impacket bloodhound certipy-ad pwntools ROPgadget ropper

WINDOWS (WSL) SETUP:
  Run hat-program/windows_setup.bat as Administrator - installs everything.

CHECK WHAT'S INSTALLED:
  Each module has a "Tool Check" option (usually the last option in the menu)
  that shows which tools are installed and which are missing.

The program works without any external tools for Python-based features
(crypto, password analysis, hash generation, etc.) but network tools
like nmap, aircrack-ng, etc. need to be installed separately.""",
        "keywords": ["install", "setup", "apt", "pip", "tools", "dependencies", "requirements", "missing"]
    },

    "watch dogs": {
        "answer": """Welcome to the ctOS, operative.

The Hat Program gives you Watch Dogs-style capabilities:

PROFILER (scan targets):
  Option 1 (Red Hat) -> Network Discovery -> scan any network
  Option 7 (Threat Intel) -> IP/Domain/Username OSINT

HACKING (exploit targets):
  Option 3 (Black Hat) -> Reverse shells, packet capture, exploits
  Option 18 (Exploitation) -> Buffer overflows, shellcode, ROP chains
  Option 17 (AD & LDAP) -> Domain takeover, pass-the-hash

CTOS ACCESS (network control):
  Option 14 (WiFi Attacks) -> Deauth, evil twin, handshake crack
  Option 16 (Evasion) -> SSH tunnels, proxy chains, covert channels
  Option 13 (Bluetooth) -> Scan and enumerate nearby devices

SURVEILLANCE (monitoring):
  Option 2 (Blue Hat) -> Connection monitoring, process analysis
  Option 9 (Incident Response) -> Live triage, IOC scanning
  Option 11 (Dashboard) -> Real-time security overview

Use the Skill Upgrade system to level up your toolkit!""",
        "keywords": ["watch dogs", "watchdog", "ctos", "hack", "game", "aiden", "dedsec"]
    },
}


# ─────────────────────────────────────────────
# Skill Upgrade System
# ─────────────────────────────────────────────

SKILL_TREE = {
    "recon": {
        "name": "Reconnaissance",
        "description": "Network discovery, port scanning, OSINT gathering",
        "levels": [
            {"level": 1, "name": "Scout", "tools": ["nmap", "whois", "dnsutils", "curl"], "apt": "nmap dnsutils whois curl"},
            {"level": 2, "name": "Analyst", "tools": ["nikto", "gobuster", "dirb"], "apt": "nikto gobuster dirb"},
            {"level": 3, "name": "Operator", "tools": ["theharvester", "recon-ng", "amass"], "apt": "theharvester recon-ng", "pip": "amass"},
        ],
    },
    "exploit": {
        "name": "Exploitation",
        "description": "Vulnerability exploitation, shellcode, buffer overflows",
        "levels": [
            {"level": 1, "name": "Script Kiddie", "tools": ["gcc", "gdb", "nasm"], "apt": "gcc gdb nasm"},
            {"level": 2, "name": "Hacker", "tools": ["metasploit-framework", "searchsploit"], "apt": "exploitdb", "note": "Metasploit: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod 755 /tmp/msfinstall && sudo /tmp/msfinstall"},
            {"level": 3, "name": "Elite", "tools": ["ROPgadget", "ropper", "pwntools"], "pip": "ROPgadget ropper pwntools"},
        ],
    },
    "wireless": {
        "name": "Wireless",
        "description": "WiFi and Bluetooth attack capabilities",
        "levels": [
            {"level": 1, "name": "Listener", "tools": ["aircrack-ng", "iw", "wireless-tools"], "apt": "aircrack-ng iw wireless-tools"},
            {"level": 2, "name": "Interceptor", "tools": ["reaver", "bully", "hostapd"], "apt": "reaver bully hostapd"},
            {"level": 3, "name": "Ghost", "tools": ["hcxdumptool", "hcxtools", "bluez"], "apt": "hcxdumptool hcxtools bluez"},
        ],
    },
    "forensics": {
        "name": "Forensics",
        "description": "Digital forensics and malware analysis",
        "levels": [
            {"level": 1, "name": "Investigator", "tools": ["binwalk", "foremost", "exiftool"], "apt": "binwalk foremost libimage-exiftool-perl"},
            {"level": 2, "name": "Analyst", "tools": ["volatility", "sleuthkit", "yara"], "apt": "sleuthkit yara", "pip": "volatility3"},
            {"level": 3, "name": "Expert", "tools": ["radare2", "ghidra"], "apt": "radare2", "note": "Ghidra: Download from https://ghidra-sre.org/"},
        ],
    },
    "network": {
        "name": "Network",
        "description": "Network attacks, evasion, and tunneling",
        "levels": [
            {"level": 1, "name": "Rookie", "tools": ["tcpdump", "netcat", "socat"], "apt": "tcpdump netcat-openbsd socat"},
            {"level": 2, "name": "Operative", "tools": ["proxychains4", "tor", "stunnel4"], "apt": "proxychains4 tor stunnel4"},
            {"level": 3, "name": "Shadow", "tools": ["chisel", "iodine", "ptunnel-ng"], "apt": "iodine ptunnel-ng", "note": "Chisel: Download from https://github.com/jpillora/chisel/releases"},
        ],
    },
    "ad_attack": {
        "name": "Active Directory",
        "description": "Domain exploitation and lateral movement",
        "levels": [
            {"level": 1, "name": "User", "tools": ["smbclient", "ldap-utils", "enum4linux"], "apt": "smbclient ldap-utils enum4linux"},
            {"level": 2, "name": "Domain User", "tools": ["impacket", "crackmapexec"], "pip": "impacket crackmapexec"},
            {"level": 3, "name": "Domain Admin", "tools": ["bloodhound", "certipy-ad", "evil-winrm"], "pip": "bloodhound certipy-ad evil-winrm"},
        ],
    },
    "social": {
        "name": "Social Engineering",
        "description": "Social engineering and phishing",
        "levels": [
            {"level": 1, "name": "Con Artist", "tools": ["wget", "curl"], "apt": "wget curl"},
            {"level": 2, "name": "Manipulator", "tools": ["httrack", "swaks", "qrencode"], "apt": "httrack swaks qrencode"},
            {"level": 3, "name": "Mastermind", "tools": ["setoolkit", "gophish", "beef-xss"], "note": "SET: sudo apt install set\nGoPhish: https://github.com/gophish/gophish/releases"},
        ],
    },
    "crypto": {
        "name": "Cryptography",
        "description": "Hash cracking and crypto attacks",
        "levels": [
            {"level": 1, "name": "Decoder", "tools": ["openssl", "base64"], "apt": "openssl"},
            {"level": 2, "name": "Breaker", "tools": ["john", "hashcat", "hydra"], "apt": "john hashcat hydra"},
            {"level": 3, "name": "Cryptographer", "tools": ["hashcat-utils", "hcxtools"], "apt": "hashcat-utils hcxtools"},
        ],
    },
}

PROGRESS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".skill_progress.json")


def _load_progress():
    """Load skill progress from disk."""
    try:
        if os.path.isfile(PROGRESS_FILE):
            with open(PROGRESS_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_progress(progress):
    """Save skill progress to disk."""
    try:
        with open(PROGRESS_FILE, "w") as f:
            json.dump(progress, f, indent=2)
    except Exception:
        pass


def _get_skill_level(skill_id):
    """Get the current level for a skill by checking installed tools."""
    skill = SKILL_TREE.get(skill_id)
    if not skill:
        return 0
    current_level = 0
    for level_info in skill["levels"]:
        all_installed = True
        for tool in level_info["tools"]:
            if not shutil.which(tool):
                # Check for Python packages too
                try:
                    __import__(tool.replace("-", "_"))
                except ImportError:
                    all_installed = False
                    break
        if all_installed:
            current_level = level_info["level"]
        else:
            break
    return current_level


def _show_skill_tree():
    """Display the full skill tree with current progress."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}")
    print("    ╔══════════════════════════════════════════════════╗")
    print("    ║           S K I L L   T R E E                   ║")
    print("    ╚══════════════════════════════════════════════════╝")
    print(Colors.RESET)
    total_points = 0
    max_points = 0
    for skill_id, skill in SKILL_TREE.items():
        current = _get_skill_level(skill_id)
        max_level = len(skill["levels"])
        total_points += current
        max_points += max_level
        # Progress bar
        filled = current
        empty = max_level - current
        bar = f"{Colors.GREEN}{'█' * filled}{Colors.RED}{'░' * empty}{Colors.RESET}"
        level_name = ""
        if current > 0:
            level_name = skill["levels"][current - 1]["name"]
        else:
            level_name = "Locked"
        color = Colors.GREEN if current == max_level else Colors.YELLOW if current > 0 else Colors.RED
        print(f"  {color}{Colors.BOLD}{skill['name']:20s}{Colors.RESET} [{bar}] Lv {current}/{max_level} - {level_name}")
        print(f"    {Colors.WHITE}{skill['description']}{Colors.RESET}")
    print(f"\n  {Colors.CYAN}{Colors.BOLD}Overall Progress: {total_points}/{max_points} skill points{Colors.RESET}")
    rank = "Unranked"
    if total_points >= max_points:
        rank = "LEGENDARY HACKER"
    elif total_points >= max_points * 0.75:
        rank = "ELITE OPERATIVE"
    elif total_points >= max_points * 0.5:
        rank = "SKILLED HACKER"
    elif total_points >= max_points * 0.25:
        rank = "APPRENTICE"
    elif total_points > 0:
        rank = "NOVICE"
    print(f"  {Colors.YELLOW}{Colors.BOLD}Rank: {rank}{Colors.RESET}\n")


def _upgrade_skill(skill_id):
    """Upgrade a specific skill to the next level."""
    skill = SKILL_TREE.get(skill_id)
    if not skill:
        print_error("Unknown skill.")
        return
    current = _get_skill_level(skill_id)
    if current >= len(skill["levels"]):
        print_info("%s is already at MAX LEVEL!" % skill["name"])
        return
    next_level = skill["levels"][current]
    print_section("Upgrading %s to Level %d: %s" % (skill["name"], next_level["level"], next_level["name"]))
    print_info("Tools to install: %s" % ", ".join(next_level["tools"]))
    if not require_root("skill upgrade"):
        print_warning("Some installations may fail without root.")
    if not confirm_action("Install tools and upgrade?"):
        return
    success = True
    # APT packages
    if "apt" in next_level:
        print_status("Installing system packages: %s" % next_level["apt"])
        stdout, stderr, rc = run_command("sudo apt update -qq 2>&1 && sudo apt install -y %s 2>&1" % next_level["apt"], timeout=180)
        if stdout:
            # Show last few lines
            lines = stdout.strip().split("\n")
            for line in lines[-5:]:
                print_info("  %s" % line)
        if rc != 0:
            print_warning("Some packages may have failed: %s" % stderr[:200] if stderr else "")
            success = False
    # PIP packages
    if "pip" in next_level:
        print_status("Installing Python packages: %s" % next_level["pip"])
        stdout, stderr, rc = run_command("pip install %s 2>&1" % next_level["pip"], timeout=180)
        if stdout:
            lines = stdout.strip().split("\n")
            for line in lines[-3:]:
                print_info("  %s" % line)
        if rc != 0:
            # Try pip3
            run_command("pip3 install %s 2>&1" % next_level["pip"], timeout=180)
    # Manual install notes
    if "note" in next_level:
        print_section("Manual Installation Required")
        print_info(next_level["note"])
    # Verify
    new_level = _get_skill_level(skill_id)
    if new_level > current:
        _ctos_print("SKILL UPGRADED! %s -> Level %d: %s" % (skill["name"], new_level, next_level["name"]), Colors.GREEN, 0.02)
    elif success:
        print_warning("Some tools may need manual installation. See notes above.")
    else:
        print_error("Upgrade incomplete. Check error messages and try installing manually.")


def _upgrade_all():
    """Attempt to upgrade all skills to the next level."""
    if not require_root("full skill upgrade"):
        return
    if not confirm_action("Upgrade ALL skills? This will install many packages."):
        return
    # Collect all apt and pip packages needed
    all_apt = []
    all_pip = []
    notes = []
    for skill_id, skill in SKILL_TREE.items():
        current = _get_skill_level(skill_id)
        for level_info in skill["levels"]:
            if level_info["level"] > current:
                if "apt" in level_info:
                    all_apt.append(level_info["apt"])
                if "pip" in level_info:
                    all_pip.append(level_info["pip"])
                if "note" in level_info:
                    notes.append("%s Lv%d: %s" % (skill["name"], level_info["level"], level_info["note"]))
    if all_apt:
        apt_str = " ".join(all_apt)
        print_status("Installing all system packages...")
        _ctos_print("Downloading skill packages...", Colors.CYAN, 0.015)
        run_command("sudo apt update -qq 2>&1", timeout=60)
        stdout, _, _ = run_command("sudo apt install -y %s 2>&1" % apt_str, timeout=300)
        if stdout:
            lines = stdout.strip().split("\n")
            for line in lines[-5:]:
                print_info("  %s" % line)
    if all_pip:
        pip_str = " ".join(all_pip)
        print_status("Installing Python packages...")
        run_command("pip install %s 2>&1" % pip_str, timeout=300)
    if notes:
        print_section("Manual Installation Notes")
        for note in notes:
            print_info(note)
    _ctos_print("Skill upgrade complete! Recalculating levels...", Colors.GREEN, 0.02)
    _show_skill_tree()


# ─────────────────────────────────────────────
# OpenAI API Integration (optional)
# ─────────────────────────────────────────────

API_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".openai_key")

def _load_api_key():
    """Load OpenAI API key from file or environment."""
    # Try environment variable first
    key = os.environ.get("OPENAI_API_KEY", "")
    if key:
        return key
    # Try file
    try:
        if os.path.isfile(API_KEY_FILE):
            with open(API_KEY_FILE) as f:
                return f.read().strip()
    except Exception:
        pass
    return ""


def _save_api_key(key):
    """Save API key to file."""
    try:
        with open(API_KEY_FILE, "w") as f:
            f.write(key)
        os.chmod(API_KEY_FILE, 0o600)
        print_info("API key saved.")
    except Exception as e:
        print_error("Failed to save: %s" % str(e))


def _ask_openai(question, api_key):
    """Send a question to OpenAI API and return the response."""
    system_prompt = """You are ctOS AI, the built-in AI assistant for the Hat Program - a comprehensive
cybersecurity toolkit with 20 modules covering offensive security (Red Hat), defensive security (Blue Hat),
threat simulation (Black Hat), and advanced modules for Bluetooth, WiFi, Forensics, Evasion, Active Directory,
Exploitation, Social Engineering, and API Security.

You help users understand cybersecurity concepts, use the program's tools effectively, and learn
penetration testing techniques. Be practical, give specific commands and steps. Keep answers concise
but thorough. Reference specific menu options (e.g. "Option 3 -> Option 2") when directing users
to program features. Always remind users to only test systems they own or have written authorization to test."""

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": "Bearer %s" % api_key,
        "Content-Type": "application/json",
    }
    payload = json.dumps({
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
        "max_tokens": 1000,
        "temperature": 0.7,
    }).encode()

    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        if e.code == 401:
            return "[ERROR] Invalid API key. Use 'set key' to update your OpenAI API key."
        elif e.code == 429:
            return "[ERROR] Rate limited. Wait a moment and try again."
        else:
            return "[ERROR] API error %d: %s" % (e.code, body[:200])
    except Exception as e:
        return "[ERROR] Failed to reach OpenAI: %s" % str(e)


# ─────────────────────────────────────────────
# Knowledge Base Search
# ─────────────────────────────────────────────

def _search_knowledge(question):
    """Search the knowledge base for the best matching answer."""
    question_lower = question.lower().strip()
    best_match = None
    best_score = 0
    for topic, info in KNOWLEDGE_BASE.items():
        score = 0
        # Check for keyword matches
        for keyword in info["keywords"]:
            if keyword in question_lower:
                # Longer keyword matches are more specific/valuable
                score += len(keyword.split())
        # Check if topic name itself is mentioned
        if topic.replace("_", " ") in question_lower:
            score += 3
        if score > best_score:
            best_score = score
            best_match = info["answer"]
    return best_match, best_score


# ─────────────────────────────────────────────
# Main AI Assistant Interface
# ─────────────────────────────────────────────

def ai_assistant():
    """AI Assistant - Interactive cybersecurity Q&A with skill upgrades."""
    _ctos_banner()
    api_key = _load_api_key()
    if api_key:
        _ctos_print("OpenAI API connected. AI mode: ENHANCED", Colors.GREEN, 0.015)
    else:
        _ctos_print("Running in OFFLINE mode (built-in knowledge base).", Colors.YELLOW, 0.015)
        _ctos_print("Type 'set key' to add OpenAI API key for enhanced AI.", Colors.YELLOW, 0.015)
    print()

    while True:
        try:
            question = input(f"{Colors.CYAN}{Colors.BOLD}ctOS>{Colors.RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if not question:
            continue

        q_lower = question.lower().strip()

        # ── Special commands ──
        if q_lower in ("exit", "quit", "back", "q"):
            _ctos_print("Disconnecting from ctOS...", Colors.YELLOW, 0.02)
            break

        elif q_lower == "help":
            print_section("ctOS AI Commands")
            print_info("  help         - Show this help")
            print_info("  skills       - View skill tree & current levels")
            print_info("  upgrade      - Upgrade a specific skill")
            print_info("  upgrade all  - Upgrade all skills at once")
            print_info("  scan         - Scan system for installed tools")
            print_info("  set key      - Set OpenAI API key for enhanced AI")
            print_info("  status       - Show AI mode and system status")
            print_info("  exit         - Return to main menu")
            print_info("")
            print_info("  Or just type any question about the Hat Program!")
            print_info("  Examples:")
            print_info("    'how do I scan a network?'")
            print_info("    'what does the black hat module do?'")
            print_info("    'how to crack a hash?'")
            print_info("    'explain Kerberoasting'")
            continue

        elif q_lower == "skills":
            _show_skill_tree()
            continue

        elif q_lower == "upgrade all":
            _upgrade_all()
            continue

        elif q_lower.startswith("upgrade"):
            # Show skill menu for upgrade
            skill_ids = list(SKILL_TREE.keys())
            skill_names = ["%s (Lv %d/%d)" % (SKILL_TREE[sid]["name"], _get_skill_level(sid), len(SKILL_TREE[sid]["levels"])) for sid in skill_ids]
            choice = display_menu("Upgrade Skill", skill_names + ["Upgrade ALL"], Colors.GREEN)
            if choice == 0:
                continue
            elif choice == len(skill_ids) + 1:
                _upgrade_all()
            else:
                _upgrade_skill(skill_ids[choice - 1])
            continue

        elif q_lower == "scan":
            _ctos_print("Scanning system capabilities...", Colors.CYAN, 0.015)
            _show_skill_tree()
            # Also show total tools
            all_tools = set()
            for skill in SKILL_TREE.values():
                for level in skill["levels"]:
                    all_tools.update(level["tools"])
            installed = sum(1 for t in all_tools if shutil.which(t))
            print_info("Total tools tracked: %d" % len(all_tools))
            print_info("Installed: %d/%d (%.0f%%)" % (installed, len(all_tools), installed / len(all_tools) * 100 if all_tools else 0))
            continue

        elif q_lower in ("set key", "api key", "openai key"):
            print_info("Enter your OpenAI API key (starts with 'sk-').")
            print_info("Get one at: https://platform.openai.com/api-keys")
            key = get_user_input("API Key")
            if key and key.startswith("sk-"):
                _save_api_key(key)
                api_key = key
                _ctos_print("API key saved. AI mode: ENHANCED", Colors.GREEN, 0.02)
            elif key:
                print_warning("Key doesn't look like an OpenAI key (should start with 'sk-')")
                if confirm_action("Save anyway?"):
                    _save_api_key(key)
                    api_key = key
            continue

        elif q_lower == "status":
            print_section("ctOS Status")
            print_info("AI Mode: %s" % ("ENHANCED (OpenAI)" if api_key else "OFFLINE (knowledge base)"))
            if api_key:
                print_info("API Key: %s...%s" % (api_key[:7], api_key[-4:]))
            total_points = sum(_get_skill_level(sid) for sid in SKILL_TREE)
            max_points = sum(len(s["levels"]) for s in SKILL_TREE.values())
            print_info("Skill Points: %d/%d" % (total_points, max_points))
            print_info("Knowledge Base: %d topics" % len(KNOWLEDGE_BASE))
            continue

        # ── Answer the question ──
        # First, search built-in knowledge base
        kb_answer, kb_score = _search_knowledge(question)

        if kb_score >= 2:
            # Good match in knowledge base
            _ctos_print("", Colors.CYAN, 0)
            print(f"{Colors.GREEN}{kb_answer}{Colors.RESET}")
            print()
            # If API key available and user wants more
            if api_key and kb_score < 4:
                print_info("(Type 'more' for an AI-enhanced answer)")
        elif api_key:
            # No good KB match, use OpenAI
            _ctos_print("Querying ctOS neural network...", Colors.CYAN, 0.015)
            answer = _ask_openai(question, api_key)
            print(f"\n{Colors.GREEN}{answer}{Colors.RESET}\n")
        else:
            # No KB match and no API
            print_warning("I don't have a specific answer for that in my knowledge base.")
            print_info("Try asking about:")
            print_info("  - A specific module (e.g. 'red hat', 'wifi attacks', 'api security')")
            print_info("  - How to do something (e.g. 'scan a network', 'crack a password')")
            print_info("  - What tools to install (e.g. 'install tools')")
            print_info("  - Getting started (e.g. 'how to get started')")
            print_info("")
            print_info("For advanced AI answers, add an OpenAI API key: type 'set key'")
