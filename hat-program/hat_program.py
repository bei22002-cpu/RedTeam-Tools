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

    {Colors.YELLOW}For educational and authorized use only.{Colors.RESET}
"""


def show_system_info():
    """Display basic system information."""
    print_section("System Information")

    stdout, _, _ = run_command("uname -snrm")
    if stdout:
        print_info(f"System: {stdout}")

    stdout, _, _ = run_command("whoami")
    if stdout:
        print_info(f"User:   {stdout}")

    if check_root():
        print_info("Privileges: ROOT")
    else:
        print_warning("Privileges: Standard user (some features may be limited)")

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
  Version: 1.0.0

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
        f"{Colors.RED}Red Hat{Colors.RESET}   - Offensive Security / Penetration Testing",
        f"{Colors.BLUE}Blue Hat{Colors.RESET}  - Defensive Security / Monitoring & Hardening",
        f"{Colors.MAGENTA}Black Hat{Colors.RESET} - Threat Simulation / Security Awareness",
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
                show_system_info()
            elif choice == 5:
                about_screen()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Interrupted. Returning to main menu...{Colors.RESET}")
            continue
        except EOFError:
            print_info("\nExiting Hat Program. Stay secure!")
            sys.exit(0)


if __name__ == "__main__":
    main()
