# Red/Black/Blue Hat Program

<p align="center">
  <strong>A comprehensive, menu-driven cybersecurity toolkit for Linux</strong>
</p>

> **Warning**
> This tool is for **educational and authorized security testing purposes only**. Unauthorized access to computer systems is illegal.

## Overview

The Hat Program is an interactive CLI tool that integrates offensive security (Red Hat), defensive security (Blue Hat), and threat simulation (Black Hat) capabilities into a single, easy-to-use interface. It leverages native Linux commands and common security tools.

## Quick Start

```bash
# Install dependencies (optional, for full functionality)
sudo bash install.sh

# Run the program
python3 hat_program.py

# For full functionality (some features require root)
sudo python3 hat_program.py
```

## Features

### Red Hat - Offensive Security
| Tool | Description |
|------|-------------|
| Network Discovery | ARP scan / ping sweep to find live hosts |
| Port Scanner | Scan for open ports (nmap or bash fallback) |
| Banner Grabbing | Grab service banners from open ports |
| DNS Enumeration | Enumerate all DNS record types for a domain |
| OS Fingerprinting | TTL-based remote OS identification |
| Traceroute Analysis | Map network paths to targets |
| WHOIS Lookup | Domain/IP registration information |
| HTTP Header Inspection | Analyze web server headers & security headers |
| SSL/TLS Analysis | Certificate inspection and expiry checking |
| Subdomain Enumeration | DNS brute force for common subdomains |

### Blue Hat - Defensive Security
| Tool | Description |
|------|-------------|
| System Security Audit | Comprehensive OS and service review |
| Firewall Status | UFW, iptables, nftables, firewalld inspection |
| Active Connections | Monitor network connections in real-time |
| Process Analysis | Detect suspicious processes and resource usage |
| User Account Audit | Review users, logins, and failed attempts |
| SUID/SGID Check | Find potentially dangerous permission files |
| Log Analysis | Parse auth, syslog, SSH, and sudo logs |
| Open Ports Audit | Audit listening services and common ports |
| Cron Job Review | Review scheduled tasks for suspicious entries |
| SSH Config Audit | Check SSH server security configuration |
| Hardening Checklist | Automated system hardening score |

### Black Hat - Threat Simulation (Educational)
| Tool | Description |
|------|-------------|
| Password Analyzer | Evaluate password strength and entropy |
| Hash Identifier | Identify hash types and dictionary cracking |
| Packet Capture | Capture and inspect network traffic |
| ARP Inspection | Detect ARP spoofing attempts |
| Wireless Discovery | Find wireless interfaces and networks |
| Exploit Search | Search exploit databases (searchsploit/NVD) |
| Reverse Shell Generator | Generate shells for authorized pen testing |
| Payload Encoding | Demonstrate encoding/obfuscation techniques |
| Steganography Detection | Detect hidden data in files |
| Metadata Extraction | Extract file metadata for forensic analysis |

## Requirements

- **OS**: Linux (Ubuntu, Debian, CentOS, Fedora, Arch)
- **Python**: 3.6+
- **Optional tools** (install via `install.sh`):
  - `nmap` - Enhanced scanning
  - `tcpdump` / `tshark` - Packet capture
  - `curl` - HTTP operations
  - `dig` / `nslookup` - DNS tools
  - `openssl` - SSL/TLS analysis
  - `whois` - WHOIS lookups
  - `steghide` / `exiftool` - Forensics
  - And more...

The program includes fallback mechanisms using basic Linux utilities when specialized tools are not installed.

## Project Structure

```
hat-program/
├── hat_program.py           # Main entry point
├── install.sh               # Dependency installer
├── HAT_PROGRAM_README.md    # This file
└── modules/
    ├── __init__.py           # Package init
    ├── utils.py              # Shared utilities (colors, I/O, validation)
    ├── red_hat.py            # Red Hat - Offensive operations
    ├── blue_hat.py           # Blue Hat - Defensive operations
    └── black_hat.py          # Black Hat - Threat simulation
```

## Usage Examples

### Run a network scan (Red Hat)
```
Main Menu → 1 (Red Hat) → 1 (Network Discovery) → Enter target: 192.168.1.0/24
```

### Check system hardening (Blue Hat)
```
Main Menu → 2 (Blue Hat) → 11 (System Hardening Checklist)
```

### Analyze a password (Black Hat)
```
Main Menu → 3 (Black Hat) → 1 (Password Strength Analyzer) → Enter password
```

## License

MIT License - For educational and authorized use only.

## Disclaimer

The materials in this program are for informational and educational purposes only. They are not intended for use in any illegal activities. Always obtain proper authorization before performing any security testing.
