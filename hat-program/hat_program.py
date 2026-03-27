#!/usr/bin/env python3
"""
Red/Black/Blue Hat Program
A comprehensive cybersecurity toolkit for Linux that covers offensive,
defensive, and threat simulation security operations.

Usage:
    python3 hat_program.py

Author: Security Tools Collection
License: MIT - For educational and authorized use only.
"""

import sys
import os
import platform

# Ensure modules directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.utils import (
    Colors,
    print_banner,
    print_section,
    print_info,
    print_warning,
    print_error,
    print_status,
    display_menu,
    run_command,
    check_root,
)
from modules.red_hat import red_hat_menu
from modules.blue_hat import blue_hat_menu
from modules.black_hat import black_hat_menu
from modules.report_generator import report_menu
from modules.vulnerability_scanner import vuln_scanner_menu
from modules.incident_response import incident_response_menu
from modules.threat_intel import threat_intel_menu
from modules.web_scanner import web_scanner_menu
from modules.crypto_toolkit import crypto_toolkit_menu
from modules.auto_recon import auto_recon_menu
from modules.dashboard import dashboard_menu
from modules.client_finder import client_finder_menu
from modules.bluetooth_scanner import bluetooth_scanner
from modules.wifi_attacks import wifi_attack_suite
from modules.forensics_malware import forensics_malware
from modules.evasion_tunneling import evasion_tunneling
from modules.ad_ldap import ad_ldap_tools
from modules.advanced_exploitation import advanced_exploitation
from modules.social_engineering import social_engineering
from modules.api_security import api_security_scanner


MAIN_BANNER = f"""
{Colors.BOLD}{Colors.WHITE}
    ██╗  ██╗ █████╗ ████████╗    ██████╗ ██████╗  ██████╗  ██████╗ ██████╗  █████╗ ███╗   ███╗
    ██║  ██║██╔══██╗╚══██╔══╝    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝ ██╔══██╗██╔══██╗████╗ ████║
    ███████║███████║   ██║       ██████╔╝██████╔╝██║   ██║██║  ███╗██████╔╝███████║██╔████╔██║
    ██╔══██║██╔══██║   ██║       ██╔═══╝ ██╔══██╗██║   ██║██║   ██║██╔══██╗██╔══██║██║╚██╔╝██║
    ██║  ██║██║  ██║   ██║       ██║     ██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝     ╚═╝
{Colors.RESET}
    {Colors.RED}[RED]{Colors.RESET} Offensive Security  |  {Colors.BLUE}[BLUE]{Colors.RESET} Defensive Security  |  {Colors.MAGENTA}[BLACK]{Colors.RESET} Threat Simulation

    {Colors.GREEN}[TOOLS]{Colors.RESET} Vuln Scanner | Web Scanner | Crypto | OSINT | Recon | IR | Reports | Dashboard

    {Colors.RED}[ADV]{Colors.RESET} Bluetooth | WiFi | Forensics | Evasion | AD/LDAP | Exploitation | SE | API

    {Colors.YELLOW}For educational and authorized use only.{Colors.RESET}
"""


def show_system_info():
    """Display basic system information."""
    print_section("System Information")

    print_info(f"System: {platform.system()} {platform.node()} {platform.release()} {platform.machine()}")

    stdout, _, _ = run_command("whoami")
    if stdout:
        print_info(f"User:   {stdout}")

    if check_root():
        print_info("Privileges: ROOT / Administrator")
    else:
        print_warning("Privileges: Standard user (some features may be limited)")

    if platform.system() == "Windows":
        stdout, _, _ = run_command("ipconfig | findstr /i \"IPv4\"")
    else:
        stdout, _, _ = run_command("ip -4 addr show scope global 2>/dev/null | grep inet | head -3")
    if stdout:
        for line in stdout.strip().split("\n"):
            ip_info = line.strip()
            print_info(f"Network: {ip_info}")


def about_screen():
    """Display information about the program."""
    print_banner("About Hat Program", Colors.CYAN)
    print(f"""
  {Colors.BOLD}Red/Black/Blue Hat Cybersecurity Program{Colors.RESET}
  Version: 3.0.0

  A comprehensive, menu-driven cybersecurity toolkit for Linux systems
  that integrates offensive, defensive, and educational security tools.

  {Colors.RED}{Colors.BOLD}RED HAT - Offensive Security:{Colors.RESET}
    Network discovery, port scanning, DNS enumeration, banner grabbing,
    OS fingerprinting, WHOIS lookups, HTTP header inspection, SSL/TLS
    analysis, and subdomain enumeration.

  {Colors.BLUE}{Colors.BOLD}BLUE HAT - Defensive Security:{Colors.RESET}
    System security audits, firewall inspection, connection monitoring,
    process analysis, user account audits, SUID/SGID checks, log
    analysis, open port audits, cron job reviews, SSH hardening, and
    a comprehensive system hardening checklist.

  {Colors.MAGENTA}{Colors.BOLD}BLACK HAT - Threat Simulation:{Colors.RESET}
    Password strength analysis, hash identification/cracking, packet
    capture, ARP inspection, wireless discovery, exploit searching,
    reverse shell generation (authorized testing), payload encoding,
    steganography detection, and metadata extraction.

  {Colors.GREEN}{Colors.BOLD}ADDITIONAL MODULES:{Colors.RESET}
    Vulnerability Scanner, Web Application Scanner, Cryptography Toolkit,
    Threat Intelligence & OSINT, Auto-Reconnaissance, Incident Response,
    Report Generator, and Security Dashboard with scoring.

  {Colors.RED}{Colors.BOLD}ADVANCED MODULES (v3.0):{Colors.RESET}
    Bluetooth & BLE Scanner, WiFi Attack Suite, Forensics & Malware Analysis,
    Firewall Evasion & Tunneling, Active Directory & LDAP, Advanced Exploitation,
    Social Engineering Toolkit, and API Security Scanner.

  {Colors.YELLOW}Disclaimer:{Colors.RESET}
    This tool is provided for educational and authorized security
    testing purposes only. Unauthorized access to computer systems
    is illegal. Always obtain proper authorization before testing.
""")


def main():
    """Main program entry point."""
    print(MAIN_BANNER)
    show_system_info()

    options = [
        f"{Colors.RED}Red Hat{Colors.RESET}        - Offensive Security / Penetration Testing",
        f"{Colors.BLUE}Blue Hat{Colors.RESET}       - Defensive Security / Monitoring & Hardening",
        f"{Colors.MAGENTA}Black Hat{Colors.RESET}      - Threat Simulation / Security Awareness",
        f"{Colors.GREEN}Vuln Scanner{Colors.RESET}   - CVE Checks, Config Audits, SSL/Docker/Kernel",
        f"{Colors.GREEN}Web Scanner{Colors.RESET}    - Directory Discovery, Headers, WAF, CMS, Tech",
        f"{Colors.GREEN}Crypto Toolkit{Colors.RESET} - Hashing, Encryption, Certificates, SSH Keys",
        f"{Colors.GREEN}Threat Intel{Colors.RESET}   - IP Reputation, OSINT, Threat Feeds, Breaches",
        f"{Colors.GREEN}Auto Recon{Colors.RESET}     - Automated Reconnaissance Pipelines",
        f"{Colors.CYAN}Incident Response{Colors.RESET} - Live Triage, Forensics, IOC Scanning",
        f"{Colors.CYAN}Report Generator{Colors.RESET}  - HTML/Text Reports, Compliance Scoring",
        f"{Colors.CYAN}Dashboard{Colors.RESET}        - Security Posture, Health Check, Scorecard",
        f"{Colors.YELLOW}Client Finder{Colors.RESET}    - Find Prospects, Audit Domains, Outreach Tools",
        f"{Colors.RED}Bluetooth Scanner{Colors.RESET} - BLE/Classic Scan, RFCOMM, OBEX, Signal Monitor",
        f"{Colors.RED}WiFi Attack Suite{Colors.RESET} - Deauth, Evil Twin, WPS, PMKID, Handshake Crack",
        f"{Colors.RED}Forensics & Malware{Colors.RESET} - PE/ELF Analysis, YARA, Memory, Disk Forensics",
        f"{Colors.RED}Evasion & Tunneling{Colors.RESET} - SSH Tunnel, DNS Tunnel, Proxy Chains, Covert",
        f"{Colors.MAGENTA}AD & LDAP Tools{Colors.RESET}   - Kerberoast, PTH, BloodHound, SMB, NTLM Relay",
        f"{Colors.RED}Exploitation{Colors.RESET}       - Buffer Overflow, Shellcode, ROP, Fuzzing",
        f"{Colors.RED}Social Engineering{Colors.RESET} - Phishing, Pretexting, USB Payloads, Vishing",
        f"{Colors.CYAN}API Security{Colors.RESET}       - REST/GraphQL, JWT, SQLi, CORS, SSRF, Fuzzing",
        "System Information",
        "About",
    ]

    while True:
        try:
            choice = display_menu("MAIN MENU", options, Colors.WHITE)
            if choice == 0:
                print_info("Exiting Hat Program. Stay secure!")
                sys.exit(0)
            elif choice == 1:
                red_hat_menu()
            elif choice == 2:
                blue_hat_menu()
            elif choice == 3:
                black_hat_menu()
            elif choice == 4:
                vuln_scanner_menu()
            elif choice == 5:
                web_scanner_menu()
            elif choice == 6:
                crypto_toolkit_menu()
            elif choice == 7:
                threat_intel_menu()
            elif choice == 8:
                auto_recon_menu()
            elif choice == 9:
                incident_response_menu()
            elif choice == 10:
                report_menu()
            elif choice == 11:
                dashboard_menu()
            elif choice == 12:
                client_finder_menu()
            elif choice == 13:
                bluetooth_scanner()
            elif choice == 14:
                wifi_attack_suite()
            elif choice == 15:
                forensics_malware()
            elif choice == 16:
                evasion_tunneling()
            elif choice == 17:
                ad_ldap_tools()
            elif choice == 18:
                advanced_exploitation()
            elif choice == 19:
                social_engineering()
            elif choice == 20:
                api_security_scanner()
            elif choice == 21:
                show_system_info()
            elif choice == 22:
                about_screen()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Interrupted. Returning to main menu...{Colors.RESET}")
            continue
        except EOFError:
            print_info("\nExiting Hat Program. Stay secure!")
            sys.exit(0)


if __name__ == "__main__":
    main()
