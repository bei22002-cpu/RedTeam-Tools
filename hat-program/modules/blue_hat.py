"""
Blue Hat Module - Defensive Security / System Monitoring & Hardening
Uses Linux system utilities for monitoring, auditing, and security hardening.
"""

from modules.utils import (
    Colors,
    print_banner,
    print_section,
    print_info,
    print_warning,
    print_error,
    print_status,
    run_command,
    check_tool,
    require_root,
    get_user_input,
    display_menu,
    confirm_action,
    check_required_tools,
)


def blue_hat_menu():
    """Main menu for Blue Hat operations."""
    options = [
        "System Security Audit",
        "Firewall Status & Rules",
        "Active Network Connections",
        "Running Processes Analysis",
        "User Account Audit",
        "File Integrity Check (SUID/SGID)",
        "Log Analysis (auth/syslog)",
        "Open Ports Audit",
        "Cron Job Review",
        "SSH Configuration Audit",
        "System Hardening Checklist",
        "Check Available Blue Team Tools",
    ]

    while True:
        choice = display_menu("BLUE HAT - Defensive Security", options, Colors.BLUE)
        if choice == 0:
            break
        elif choice == 1:
            system_security_audit()
        elif choice == 2:
            firewall_status()
        elif choice == 3:
            active_connections()
        elif choice == 4:
            process_analysis()
        elif choice == 5:
            user_account_audit()
        elif choice == 6:
            suid_sgid_check()
        elif choice == 7:
            log_analysis()
        elif choice == 8:
            open_ports_audit()
        elif choice == 9:
            cron_job_review()
        elif choice == 10:
            ssh_config_audit()
        elif choice == 11:
            hardening_checklist()
        elif choice == 12:
            check_blue_tools()


def system_security_audit():
    """Perform a comprehensive system security audit."""
    print_section("System Security Audit")

    # OS Information
    print_section("Operating System Information")
    stdout, _, _ = run_command("uname -a")
    if stdout:
        print_info(f"Kernel: {stdout}")

    stdout, _, _ = run_command("cat /etc/os-release 2>/dev/null | head -5")
    if stdout:
        print_info(f"OS Release:\n{stdout}")

    # Check for pending updates
    print_section("Pending Security Updates")
    if check_tool("apt"):
        stdout, _, _ = run_command("apt list --upgradable 2>/dev/null | head -20")
        if stdout and "Listing" not in stdout:
            print_warning(f"Pending updates:\n{stdout}")
        else:
            print_info("System appears up to date.")
    elif check_tool("yum"):
        stdout, _, _ = run_command("yum check-update --security 2>/dev/null | head -20")
        if stdout:
            print_warning(f"Pending security updates:\n{stdout}")

    # Check running services
    print_section("Running Services")
    stdout, _, _ = run_command("systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -25")
    if stdout:
        print_info(f"Active services:\n{stdout}")

    # Check for failed services
    print_section("Failed Services")
    stdout, _, _ = run_command("systemctl list-units --type=service --state=failed --no-pager 2>/dev/null")
    if stdout and "0 loaded" not in stdout:
        print_warning(f"Failed services:\n{stdout}")
    else:
        print_info("No failed services detected.")


def firewall_status():
    """Check firewall status and rules."""
    print_section("Firewall Status & Rules")

    # Check UFW
    if check_tool("ufw"):
        print_section("UFW Firewall")
        stdout, _, _ = run_command("ufw status verbose 2>/dev/null")
        if stdout:
            print_info(f"UFW Status:\n{stdout}")
        else:
            print_warning("Could not read UFW status (may need root).")

    # Check iptables
    if check_tool("iptables"):
        print_section("iptables Rules")
        stdout, _, _ = run_command("iptables -L -n --line-numbers 2>/dev/null")
        if stdout:
            print_info(f"iptables rules:\n{stdout}")
        else:
            print_warning("Could not read iptables (may need root).")

    # Check nftables
    if check_tool("nft"):
        print_section("nftables Rules")
        stdout, _, _ = run_command("nft list ruleset 2>/dev/null")
        if stdout:
            print_info(f"nftables rules:\n{stdout}")

    # Check firewalld
    if check_tool("firewall-cmd"):
        print_section("firewalld Status")
        stdout, _, _ = run_command("firewall-cmd --state 2>/dev/null")
        if stdout:
            print_info(f"firewalld: {stdout}")
        stdout, _, _ = run_command("firewall-cmd --list-all 2>/dev/null")
        if stdout:
            print(stdout)


def active_connections():
    """Display active network connections."""
    print_section("Active Network Connections")

    if check_tool("ss"):
        print_status("Fetching active connections with ss...")
        stdout, _, _ = run_command("ss -tunapl 2>/dev/null")
        if stdout:
            print_info("Active connections:")
            print(stdout)
    elif check_tool("netstat"):
        print_status("Fetching active connections with netstat...")
        stdout, _, _ = run_command("netstat -tunapl 2>/dev/null")
        if stdout:
            print_info("Active connections:")
            print(stdout)
    else:
        print_error("Neither ss nor netstat found.")

    # Show established connections specifically
    print_section("Established Connections")
    stdout, _, _ = run_command("ss -tn state established 2>/dev/null")
    if stdout:
        print(stdout)


def process_analysis():
    """Analyze running processes for suspicious activity."""
    print_section("Running Processes Analysis")

    # Top CPU consumers
    print_section("Top 15 CPU Consumers")
    stdout, _, _ = run_command("ps aux --sort=-%cpu | head -16")
    if stdout:
        print(stdout)

    # Top memory consumers
    print_section("Top 15 Memory Consumers")
    stdout, _, _ = run_command("ps aux --sort=-%mem | head -16")
    if stdout:
        print(stdout)

    # Processes running as root
    print_section("Processes Running as Root")
    stdout, _, _ = run_command("ps aux | awk '$1==\"root\"' | head -20")
    if stdout:
        print(stdout)

    # Processes with network connections
    print_section("Processes with Network Connections")
    stdout, _, _ = run_command("ss -tnp 2>/dev/null | tail -20")
    if stdout:
        print(stdout)

    # Check for suspicious processes
    print_section("Suspicious Process Check")
    suspicious = ["cryptominer", "xmrig", "minerd", "kworkerds", "kdevtmpfsi"]
    stdout, _, _ = run_command("ps aux")
    if stdout:
        found_suspicious = False
        for proc in suspicious:
            if proc.lower() in stdout.lower():
                print_error(f"Potentially suspicious process found: {proc}")
                found_suspicious = True
        if not found_suspicious:
            print_info("No known suspicious processes detected.")


def user_account_audit():
    """Audit user accounts on the system."""
    print_section("User Account Audit")

    # Users with login shells
    print_section("Users with Login Shells")
    stdout, _, _ = run_command(
        "awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)/ {print $1, $3, $6, $7}' /etc/passwd"
    )
    if stdout:
        print_info("Users with valid shells:")
        print(f"  {'Username':15s} {'UID':6s} {'Home':25s} {'Shell'}")
        for line in stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 4:
                print(f"  {parts[0]:15s} {parts[1]:6s} {parts[2]:25s} {parts[3]}")

    # Users with UID 0 (root equivalents)
    print_section("Root-Equivalent Users (UID 0)")
    stdout, _, _ = run_command("awk -F: '$3==0 {print $1}' /etc/passwd")
    if stdout:
        users = stdout.strip().split("\n")
        if len(users) > 1:
            print_warning(f"Multiple UID 0 users found: {', '.join(users)}")
        else:
            print_info(f"Only root has UID 0: {users[0]}")

    # Users with empty passwords
    print_section("Password Status Check")
    stdout, _, _ = run_command("awk -F: '($2==\"\" || $2==\"!\") {print $1}' /etc/shadow 2>/dev/null")
    if stdout:
        print_warning(f"Users with empty/locked passwords:\n{stdout}")
    else:
        print_info("All accounts have passwords set (or cannot read shadow file).")

    # Recent logins
    print_section("Recent Login Activity")
    stdout, _, _ = run_command("last -n 15 2>/dev/null")
    if stdout:
        print_info("Recent logins:")
        print(stdout)

    # Failed login attempts
    print_section("Failed Login Attempts")
    stdout, _, _ = run_command("lastb -n 10 2>/dev/null")
    if stdout:
        print_warning("Recent failed logins:")
        print(stdout)
    else:
        print_info("No failed logins found (or need root to check).")


def suid_sgid_check():
    """Find SUID and SGID files on the system."""
    print_section("SUID/SGID File Audit")

    require_root("SUID/SGID search")

    search_path = get_user_input("Search path", "/usr")

    # SUID files
    print_section("SUID Files (Set User ID)")
    print_status(f"Searching for SUID files in {search_path}...")
    stdout, _, _ = run_command(
        f"find {search_path} -perm -4000 -type f 2>/dev/null | head -30",
        timeout=60,
    )
    if stdout:
        print_warning("SUID files found:")
        for f in stdout.split("\n"):
            # Get file details
            details, _, _ = run_command(f"ls -la {f} 2>/dev/null")
            if details:
                print(f"    {details}")
    else:
        print_info("No SUID files found.")

    # SGID files
    print_section("SGID Files (Set Group ID)")
    stdout, _, _ = run_command(
        f"find {search_path} -perm -2000 -type f 2>/dev/null | head -30",
        timeout=60,
    )
    if stdout:
        print_warning("SGID files found:")
        for f in stdout.split("\n"):
            details, _, _ = run_command(f"ls -la {f} 2>/dev/null")
            if details:
                print(f"    {details}")
    else:
        print_info("No SGID files found.")

    # World-writable files
    print_section("World-Writable Files")
    stdout, _, _ = run_command(
        f"find {search_path} -perm -o+w -type f 2>/dev/null | head -20",
        timeout=60,
    )
    if stdout:
        print_warning("World-writable files found:")
        print(stdout)
    else:
        print_info("No world-writable files found.")


def log_analysis():
    """Analyze system logs for security events."""
    print_section("Log Analysis")

    options = [
        "Authentication logs (auth.log)",
        "System log (syslog)",
        "Kernel messages (dmesg)",
        "Failed SSH logins",
        "Sudo usage",
    ]

    choice = display_menu("Select Log Source", options, Colors.BLUE)

    if choice == 0:
        return

    if choice == 1:
        print_section("Authentication Log Analysis")
        log_file = "/var/log/auth.log"
        stdout, _, rc = run_command(f"test -f {log_file} && tail -50 {log_file}")
        if rc == 0 and stdout:
            print_info("Recent auth events:")
            print(stdout)
        else:
            # Try journalctl
            stdout, _, _ = run_command("journalctl -u ssh --no-pager -n 50 2>/dev/null")
            if stdout:
                print(stdout)
            else:
                print_error("Cannot access authentication logs.")

    elif choice == 2:
        print_section("Syslog Analysis")
        stdout, _, rc = run_command("tail -50 /var/log/syslog 2>/dev/null")
        if rc == 0 and stdout:
            print_info("Recent syslog entries:")
            print(stdout)
        else:
            stdout, _, _ = run_command("journalctl --no-pager -n 50 2>/dev/null")
            if stdout:
                print(stdout)
            else:
                print_error("Cannot access system logs.")

    elif choice == 3:
        print_section("Kernel Messages")
        stdout, _, _ = run_command("dmesg --level=err,warn 2>/dev/null | tail -30")
        if stdout:
            print_warning("Kernel warnings/errors:")
            print(stdout)
        else:
            print_info("No kernel warnings/errors found.")

    elif choice == 4:
        print_section("Failed SSH Login Attempts")
        stdout, _, _ = run_command(
            "journalctl -u ssh --no-pager 2>/dev/null | "
            "grep -i 'failed\\|invalid\\|error' | tail -30"
        )
        if stdout:
            print_warning("Failed SSH attempts:")
            print(stdout)
        else:
            stdout, _, _ = run_command(
                "grep -i 'failed\\|invalid' /var/log/auth.log 2>/dev/null | tail -30"
            )
            if stdout:
                print_warning("Failed SSH attempts:")
                print(stdout)
            else:
                print_info("No failed SSH login attempts found.")

    elif choice == 5:
        print_section("Sudo Usage Log")
        stdout, _, _ = run_command(
            "journalctl -t sudo --no-pager -n 30 2>/dev/null"
        )
        if stdout:
            print_info("Recent sudo usage:")
            print(stdout)
        else:
            stdout, _, _ = run_command(
                "grep -i 'sudo' /var/log/auth.log 2>/dev/null | tail -30"
            )
            if stdout:
                print(stdout)
            else:
                print_info("No sudo activity found.")


def open_ports_audit():
    """Audit open ports and listening services."""
    print_section("Open Ports Audit")

    print_status("Checking listening ports...")

    # Get listening ports
    if check_tool("ss"):
        stdout, _, _ = run_command("ss -tlnp 2>/dev/null")
    elif check_tool("netstat"):
        stdout, _, _ = run_command("netstat -tlnp 2>/dev/null")
    else:
        stdout = ""

    if stdout:
        print_info("Listening TCP ports:")
        print(stdout)

    # UDP listeners
    print_section("UDP Listeners")
    if check_tool("ss"):
        stdout, _, _ = run_command("ss -ulnp 2>/dev/null")
    elif check_tool("netstat"):
        stdout, _, _ = run_command("netstat -ulnp 2>/dev/null")
    else:
        stdout = ""

    if stdout:
        print_info("Listening UDP ports:")
        print(stdout)

    # Check for unexpected listeners on common ports
    print_section("Common Port Analysis")
    common_ports = {
        "21": "FTP",
        "22": "SSH",
        "23": "Telnet (INSECURE)",
        "25": "SMTP",
        "53": "DNS",
        "80": "HTTP",
        "443": "HTTPS",
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "6379": "Redis",
        "8080": "HTTP-Alt",
        "8443": "HTTPS-Alt",
        "27017": "MongoDB",
    }

    stdout, _, _ = run_command("ss -tlnp 2>/dev/null")
    if stdout:
        for port, service in common_ports.items():
            if f":{port} " in stdout or f":{port}\t" in stdout:
                if port == "23":
                    print_error(f"Port {port} ({service}) - SHOULD BE DISABLED")
                else:
                    print_info(f"Port {port} ({service}) is listening")


def cron_job_review():
    """Review scheduled cron jobs for suspicious entries."""
    print_section("Cron Job Review")

    # Current user crontab
    print_section("Current User Crontab")
    stdout, _, _ = run_command("crontab -l 2>/dev/null")
    if stdout:
        print_info("User crontab:")
        print(stdout)
    else:
        print_info("No crontab for current user.")

    # System crontabs
    print_section("System Cron Jobs")
    cron_dirs = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.hourly/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
    ]

    for cron_path in cron_dirs:
        stdout, _, rc = run_command(f"ls -la {cron_path} 2>/dev/null")
        if rc == 0 and stdout:
            print_info(f"{cron_path}:")
            print(stdout)

    # Check for suspicious cron entries
    print_section("Suspicious Cron Entry Check")
    stdout, _, _ = run_command(
        "for user in $(cut -d: -f1 /etc/passwd); do "
        "crontab -u $user -l 2>/dev/null | grep -v '^#' | "
        "grep -v '^$' && echo \"  (user: $user)\"; done"
    )
    if stdout:
        print_warning("Active cron entries:")
        print(stdout)

        # Flag suspicious patterns
        suspicious_patterns = ["curl", "wget", "nc ", "ncat", "bash -i", "/dev/tcp", "base64"]
        for pattern in suspicious_patterns:
            if pattern in stdout.lower():
                print_error(f"Suspicious pattern found in cron: '{pattern}'")
    else:
        print_info("No suspicious cron entries found.")


def ssh_config_audit():
    """Audit SSH server configuration."""
    print_section("SSH Configuration Audit")

    ssh_config = "/etc/ssh/sshd_config"
    stdout, _, rc = run_command(f"cat {ssh_config} 2>/dev/null")

    if rc != 0 or not stdout:
        print_error(f"Cannot read {ssh_config} (may need root).")
        return

    config = stdout.lower()
    print_info("SSH Configuration Security Check:")

    checks = [
        ("permitrootlogin no", "permitrootlogin yes", "Root Login",
         "Root login should be disabled"),
        ("passwordauthentication no", "passwordauthentication yes", "Password Auth",
         "Key-based auth is more secure"),
        ("permitemptypasswords no", "permitemptypasswords yes", "Empty Passwords",
         "Empty passwords should be disabled"),
        ("x11forwarding no", "x11forwarding yes", "X11 Forwarding",
         "Disable if not needed"),
        ("maxauthtries", None, "MaxAuthTries",
         "Should be set to a low value (e.g., 3)"),
        ("protocol 2", "protocol 1", "SSH Protocol",
         "Only SSHv2 should be used"),
    ]

    for secure, insecure, name, advice in checks:
        if secure in config:
            print_info(f"  {name}: SECURE - {advice}")
        elif insecure and insecure in config:
            print_warning(f"  {name}: INSECURE - {advice}")
        else:
            print_status(f"  {name}: DEFAULT/NOT SET - {advice}")

    # Check SSH key files
    print_section("SSH Key Files")
    stdout, _, _ = run_command("ls -la ~/.ssh/ 2>/dev/null")
    if stdout:
        print_info("SSH directory contents:")
        print(stdout)
    else:
        print_info("No .ssh directory found for current user.")


def hardening_checklist():
    """Run a system hardening checklist."""
    print_section("System Hardening Checklist")

    checks_passed = 0
    checks_failed = 0
    total_checks = 0

    def check(name, command, expect_rc=0, expect_output=None, invert=False):
        nonlocal checks_passed, checks_failed, total_checks
        total_checks += 1
        stdout, _, rc = run_command(command, timeout=10)
        passed = False

        if expect_output is not None:
            passed = expect_output.lower() in stdout.lower()
        else:
            passed = (rc == expect_rc)

        if invert:
            passed = not passed

        if passed:
            print_info(f"  PASS: {name}")
            checks_passed += 1
        else:
            print_warning(f"  FAIL: {name}")
            checks_failed += 1

    print_status("Running hardening checks...")

    # Filesystem checks
    print_section("Filesystem Security")
    check("No world-writable dirs in PATH",
          "echo $PATH | tr ':' '\\n' | xargs -I{} find {} -maxdepth 0 -perm -o+w 2>/dev/null",
          expect_output="NONE_EXPECTED", invert=True)
    check("/tmp has noexec option",
          "mount | grep ' /tmp '",
          expect_output="noexec")

    # Network security
    print_section("Network Security")
    check("IP forwarding disabled",
          "sysctl net.ipv4.ip_forward 2>/dev/null",
          expect_output="= 0")
    check("SYN cookies enabled",
          "sysctl net.ipv4.tcp_syncookies 2>/dev/null",
          expect_output="= 1")
    check("ICMP redirect acceptance disabled",
          "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null",
          expect_output="= 0")

    # Auth security
    print_section("Authentication Security")
    check("Shadow passwords in use",
          "test -f /etc/shadow", expect_rc=0)
    check("Password hashing is SHA-512",
          "grep -c 'SHA512\\|yescrypt' /etc/login.defs 2>/dev/null",
          expect_rc=0)

    # Service security
    print_section("Service Security")
    check("No telnet server running",
          "ss -tlnp 2>/dev/null | grep ':23 '",
          expect_rc=0, invert=True)
    check("No FTP server running",
          "ss -tlnp 2>/dev/null | grep ':21 '",
          expect_rc=0, invert=True)

    # Summary
    print_section("Hardening Score")
    if total_checks > 0:
        score = (checks_passed / total_checks) * 100
        print_info(f"Passed: {checks_passed}/{total_checks} ({score:.0f}%)")
        if score >= 80:
            print_info("System hardening is GOOD.")
        elif score >= 50:
            print_warning("System hardening needs IMPROVEMENT.")
        else:
            print_error("System hardening is POOR. Immediate action recommended.")


def check_blue_tools():
    """Check availability of common blue team tools."""
    print_section("Blue Team Tool Availability Check")

    tools = [
        "ss", "netstat", "iptables", "ufw", "nft", "firewall-cmd",
        "tcpdump", "wireshark", "tshark", "snort", "suricata",
        "fail2ban-client", "aide", "tripwire", "rkhunter", "chkrootkit",
        "lynis", "clamav", "clamscan", "auditctl", "ausearch",
        "journalctl", "systemctl", "logrotate", "rsyslogd",
        "ossec", "wazuh-agent", "sysdig", "strace", "ltrace",
    ]

    check_required_tools(tools)
