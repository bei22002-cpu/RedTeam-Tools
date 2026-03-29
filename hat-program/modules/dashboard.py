"""
Dashboard Module - System security score, quick overview, and security posture summary.
Provides an at-a-glance view of the system's security state.
"""

import datetime

from modules.utils import (
    Colors,
    print_section,
    print_info,
    print_warning,
    print_error,
    print_status,
    run_command,
    check_tool,
    display_menu,
    confirm_action,
)


def dashboard_menu():
    """Dashboard menu."""
    options = [
        "Security Posture Dashboard",
        "Quick Health Check",
        "Network Status Overview",
        "User Activity Summary",
        "Service Status Monitor",
        "Security Score Card",
    ]

    while True:
        choice = display_menu("SECURITY DASHBOARD", options, Colors.CYAN)
        if choice == 0:
            break
        elif choice == 1:
            security_posture()
        elif choice == 2:
            quick_health_check()
        elif choice == 3:
            network_overview()
        elif choice == 4:
            user_activity()
        elif choice == 5:
            service_monitor()
        elif choice == 6:
            security_scorecard()


def security_posture():
    """Display comprehensive security posture dashboard."""
    print_section("Security Posture Dashboard")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print_info("Scan time: {}".format(now))

    # System info
    stdout, _, _ = run_command("hostname")
    hostname = stdout.strip() if stdout else "unknown"
    stdout, _, _ = run_command("uname -r")
    kernel = stdout.strip() if stdout else "unknown"
    stdout, _, _ = run_command("uptime -p 2>/dev/null || uptime")
    uptime_str = stdout.strip() if stdout else "unknown"

    print_section("System")
    print_info("  Host: {}  |  Kernel: {}".format(hostname, kernel))
    print_info("  Uptime: {}".format(uptime_str))

    # Quick security metrics
    print_section("Security Metrics")

    # Open ports
    stdout, _, _ = run_command("ss -tlnp 2>/dev/null | tail -n +2 | wc -l")
    tcp_ports = stdout.strip() if stdout else "?"
    stdout, _, _ = run_command("ss -ulnp 2>/dev/null | tail -n +2 | wc -l")
    udp_ports = stdout.strip() if stdout else "?"
    print_info("  Listening ports: {} TCP, {} UDP".format(tcp_ports, udp_ports))

    # Established connections
    stdout, _, _ = run_command("ss -tn state established 2>/dev/null | wc -l")
    conn_count = stdout.strip() if stdout else "?"
    print_info("  Established connections: {}".format(conn_count))

    # Users
    stdout, _, _ = run_command("who 2>/dev/null | wc -l")
    logged_in = stdout.strip() if stdout else "?"
    stdout, _, _ = run_command("awk -F: '$7 !~ /(nologin|false)/ {print}' /etc/passwd | wc -l")
    total_users = stdout.strip() if stdout else "?"
    print_info("  Users logged in: {} | Total login accounts: {}".format(logged_in, total_users))

    # Running processes
    stdout, _, _ = run_command("ps aux | wc -l")
    procs = stdout.strip() if stdout else "?"
    print_info("  Running processes: {}".format(procs))

    # Firewall
    stdout, _, _ = run_command("ufw status 2>/dev/null | head -1")
    if stdout and "active" in stdout.lower():
        print_info("  Firewall: ACTIVE")
    else:
        print_warning("  Firewall: INACTIVE or not configured")

    # Pending updates
    stdout, _, _ = run_command("apt list --upgradable 2>/dev/null | wc -l")
    if stdout:
        updates = max(0, int(stdout.strip()) - 1) if stdout.strip().isdigit() else 0
        if updates > 0:
            print_warning("  Pending updates: {}".format(updates))
        else:
            print_info("  Pending updates: 0 (up to date)")

    # Failed services
    stdout, _, _ = run_command(
        "systemctl --failed --no-pager 2>/dev/null | grep 'loaded units' | head -1"
    )
    if stdout:
        print_info("  {}".format(stdout.strip()))

    # Disk usage
    print_section("Disk Usage")
    stdout, _, _ = run_command("df -h / /home /tmp /var 2>/dev/null | tail -n +2")
    if stdout:
        for line in stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 5:
                usage_pct = parts[4].replace("%", "")
                if usage_pct.isdigit() and int(usage_pct) > 90:
                    print_error("  {} ({}% full)".format(parts[5] if len(parts) > 5 else parts[0], usage_pct))
                elif usage_pct.isdigit() and int(usage_pct) > 75:
                    print_warning("  {} ({}% full)".format(parts[5] if len(parts) > 5 else parts[0], usage_pct))
                else:
                    print_info("  {} ({}% used)".format(parts[5] if len(parts) > 5 else parts[0], usage_pct))

    # Memory
    print_section("Memory")
    stdout, _, _ = run_command("free -h | head -2")
    if stdout:
        print(stdout)


def quick_health_check():
    """Quick system health check with pass/fail indicators."""
    print_section("Quick Health Check")

    checks = []

    def check(name, command, expect_fn):
        stdout, _, rc = run_command(command, timeout=10)
        result = expect_fn(stdout, rc)
        status = "PASS" if result else "FAIL"
        checks.append((name, status))
        if result:
            print_info("  [PASS] {}".format(name))
        else:
            print_warning("  [FAIL] {}".format(name))

    # System checks
    check("System is up",
          "uptime", lambda o, r: r == 0)
    check("Root filesystem < 90% full",
          "df / | tail -1 | awk '{print $5}'",
          lambda o, r: o and int(o.strip().replace("%", "")) < 90 if o and o.strip().replace("%", "").isdigit() else False)
    check("Memory available > 10%",
          "free | grep Mem | awk '{print int($7/$2*100)}'",
          lambda o, r: o and int(o.strip()) > 10 if o and o.strip().isdigit() else False)
    check("Firewall is active",
          "ufw status 2>/dev/null",
          lambda o, r: "active" in o.lower() if o else False)
    check("No failed systemd services",
          "systemctl --failed --no-pager 2>/dev/null | grep -c 'failed'",
          lambda o, r: o and o.strip() == "0" if o else True)
    check("SSH service running",
          "systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null",
          lambda o, r: "active" in o if o else False)
    check("No root-equivalent users besides root",
          "awk -F: '$3==0{print $1}' /etc/passwd | wc -l",
          lambda o, r: o and o.strip() == "1" if o else False)
    check("No world-writable files in /etc",
          "find /etc -perm -o+w -type f 2>/dev/null | wc -l",
          lambda o, r: o and o.strip() == "0" if o else True)
    check("NTP/time sync active",
          "timedatectl 2>/dev/null | grep 'synchronized'",
          lambda o, r: "yes" in o.lower() if o else False)
    check("IP forwarding disabled",
          "sysctl net.ipv4.ip_forward 2>/dev/null",
          lambda o, r: "= 0" in o if o else False)

    # Summary
    passed = sum(1 for _, s in checks if s == "PASS")
    total = len(checks)
    pct = (passed / total * 100) if total > 0 else 0
    print_section("Health Score: {}/{} ({:.0f}%)".format(passed, total, pct))


def network_overview():
    """Network status overview."""
    print_section("Network Status Overview")

    # Interfaces
    print_section("Network Interfaces")
    stdout, _, _ = run_command("ip -brief addr show 2>/dev/null")
    if stdout:
        print(stdout)
    else:
        stdout, _, _ = run_command("ip addr show 2>/dev/null | grep -E '(^[0-9]|inet )'")
        if stdout:
            print(stdout)

    # Default route
    print_section("Default Gateway")
    stdout, _, _ = run_command("ip route show default 2>/dev/null")
    if stdout:
        print_info(stdout.strip())

    # DNS
    print_section("DNS Servers")
    stdout, _, _ = run_command("grep nameserver /etc/resolv.conf 2>/dev/null")
    if stdout:
        print(stdout)

    # Connection summary
    print_section("Connection Summary")
    stdout, _, _ = run_command(
        "ss -s 2>/dev/null"
    )
    if stdout:
        print(stdout)

    # Top connections by remote IP
    print_section("Top Remote IPs (established)")
    stdout, _, _ = run_command(
        "ss -tn state established 2>/dev/null | awk '{print $5}' | "
        "cut -d: -f1 | sort | uniq -c | sort -rn | head -10"
    )
    if stdout:
        print(stdout)

    # Listening services
    print_section("Listening Services")
    stdout, _, _ = run_command("ss -tlnp 2>/dev/null")
    if stdout:
        print(stdout)


def user_activity():
    """User activity summary."""
    print_section("User Activity Summary")

    # Currently logged in
    print_section("Currently Logged In")
    stdout, _, _ = run_command("w 2>/dev/null")
    if stdout:
        print(stdout)

    # Recent logins
    print_section("Recent Logins (last 20)")
    stdout, _, _ = run_command("last -n 20 2>/dev/null")
    if stdout:
        print(stdout)

    # Failed login attempts
    print_section("Recent Failed Logins")
    stdout, _, _ = run_command("lastb -n 15 2>/dev/null")
    if stdout:
        print(stdout)
    else:
        stdout, _, _ = run_command(
            "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -10"
        )
        if stdout:
            print(stdout)
        else:
            print_info("No failed login data available (may need root).")

    # Sudo usage
    print_section("Recent Sudo Usage")
    stdout, _, _ = run_command(
        "grep 'sudo:' /var/log/auth.log 2>/dev/null | tail -10"
    )
    if stdout:
        print(stdout)
    else:
        stdout, _, _ = run_command(
            "journalctl -t sudo --no-pager -n 10 2>/dev/null"
        )
        if stdout:
            print(stdout)

    # Account status
    print_section("User Accounts with Login Shells")
    stdout, _, _ = run_command(
        "awk -F: '$7 !~ /(nologin|false)/ {printf \"%-15s UID:%-6s %s\\n\", $1, $3, $6}' /etc/passwd"
    )
    if stdout:
        print(stdout)


def service_monitor():
    """Monitor running services and their status."""
    print_section("Service Status Monitor")

    # Running services
    print_section("Running Services")
    stdout, _, _ = run_command(
        "systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -30"
    )
    if stdout:
        print(stdout)

    # Failed services
    print_section("Failed Services")
    stdout, _, _ = run_command(
        "systemctl list-units --type=service --state=failed --no-pager 2>/dev/null"
    )
    if stdout and "0 loaded" not in stdout:
        print_error("Failed services detected:")
        print(stdout)
    else:
        print_info("No failed services.")

    # Key services status
    print_section("Key Service Status")
    key_services = [
        "sshd", "ssh", "ufw", "fail2ban", "nginx", "apache2",
        "mysql", "postgresql", "docker", "cron", "rsyslog",
        "auditd", "apparmor",
    ]

    for svc in key_services:
        stdout, _, rc = run_command("systemctl is-active {} 2>/dev/null".format(svc))
        if stdout:
            status = stdout.strip()
            if status == "active":
                print_info("  {:20s} ACTIVE".format(svc))
            elif status == "inactive":
                print_status("  {:20s} inactive".format(svc))
            elif status == "failed":
                print_error("  {:20s} FAILED".format(svc))

    # Systemd timers
    print_section("Active Timers")
    stdout, _, _ = run_command("systemctl list-timers --no-pager 2>/dev/null | head -15")
    if stdout:
        print(stdout)


def security_scorecard():
    """Generate a comprehensive security score card."""
    print_section("Security Score Card")
    print_status("Running comprehensive security assessment...")

    categories = {}
    total_score = 0
    total_max = 0

    # 1. Authentication & Access (25 points)
    cat_score = 0
    cat_max = 25

    # Root login disabled in SSH
    stdout, _, _ = run_command("grep -i '^PermitRootLogin no' /etc/ssh/sshd_config 2>/dev/null")
    if stdout:
        cat_score += 5

    # Only one UID 0 user
    stdout, _, _ = run_command("awk -F: '$3==0{print}' /etc/passwd | wc -l")
    if stdout and stdout.strip() == "1":
        cat_score += 5

    # No empty passwords
    stdout, _, _ = run_command("awk -F: '$2==\"\"' /etc/shadow 2>/dev/null | wc -l")
    if stdout and stdout.strip() == "0":
        cat_score += 5

    # Password hashing is strong
    stdout, _, _ = run_command("grep -cE 'SHA512|yescrypt' /etc/login.defs 2>/dev/null")
    if stdout and stdout.strip() != "0":
        cat_score += 5

    # Sudo is configured
    stdout, _, _ = run_command("test -f /etc/sudoers && echo ok")
    if stdout and "ok" in stdout:
        cat_score += 5

    categories["Authentication & Access"] = (cat_score, cat_max)
    total_score += cat_score
    total_max += cat_max

    # 2. Network Security (25 points)
    cat_score = 0
    cat_max = 25

    # Firewall active
    stdout, _, _ = run_command("ufw status 2>/dev/null")
    if stdout and "active" in stdout.lower():
        cat_score += 8

    # IP forwarding disabled
    stdout, _, _ = run_command("sysctl net.ipv4.ip_forward 2>/dev/null")
    if stdout and "= 0" in stdout:
        cat_score += 4

    # SYN cookies enabled
    stdout, _, _ = run_command("sysctl net.ipv4.tcp_syncookies 2>/dev/null")
    if stdout and "= 1" in stdout:
        cat_score += 4

    # ICMP redirects disabled
    stdout, _, _ = run_command("sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null")
    if stdout and "= 0" in stdout:
        cat_score += 4

    # No telnet/rsh
    stdout, _, _ = run_command("ss -tlnp 2>/dev/null | grep -E ':23 |:514 '")
    if not stdout or not stdout.strip():
        cat_score += 5

    categories["Network Security"] = (cat_score, cat_max)
    total_score += cat_score
    total_max += cat_max

    # 3. System Hardening (25 points)
    cat_score = 0
    cat_max = 25

    # ASLR enabled
    stdout, _, _ = run_command("sysctl kernel.randomize_va_space 2>/dev/null")
    if stdout and "= 2" in stdout:
        cat_score += 5

    # No world-writable dirs in system paths
    stdout, _, _ = run_command("find /etc -perm -o+w -type f 2>/dev/null | wc -l")
    if stdout and stdout.strip() == "0":
        cat_score += 5

    # System up to date
    stdout, _, _ = run_command("apt list --upgradable 2>/dev/null | wc -l")
    if stdout and stdout.strip().isdigit() and int(stdout.strip()) <= 1:
        cat_score += 5

    # Disk not full
    stdout, _, _ = run_command("df / | tail -1 | awk '{print $5}'")
    if stdout and stdout.strip().replace("%", "").isdigit():
        if int(stdout.strip().replace("%", "")) < 90:
            cat_score += 5

    # Core dumps disabled
    stdout, _, _ = run_command("sysctl fs.suid_dumpable 2>/dev/null")
    if stdout and "= 0" in stdout:
        cat_score += 5

    categories["System Hardening"] = (cat_score, cat_max)
    total_score += cat_score
    total_max += cat_max

    # 4. Monitoring & Logging (25 points)
    cat_score = 0
    cat_max = 25

    # Syslog running
    stdout, _, _ = run_command("systemctl is-active rsyslog 2>/dev/null")
    if stdout and "active" in stdout:
        cat_score += 5

    # Cron running
    stdout, _, _ = run_command("systemctl is-active cron 2>/dev/null")
    if stdout and "active" in stdout:
        cat_score += 5

    # Auth log exists
    stdout, _, _ = run_command("test -f /var/log/auth.log && echo ok")
    if stdout and "ok" in stdout:
        cat_score += 5

    # Audit daemon
    stdout, _, _ = run_command("systemctl is-active auditd 2>/dev/null")
    if stdout and "active" in stdout:
        cat_score += 5

    # fail2ban
    stdout, _, _ = run_command("systemctl is-active fail2ban 2>/dev/null")
    if stdout and "active" in stdout:
        cat_score += 5

    categories["Monitoring & Logging"] = (cat_score, cat_max)
    total_score += cat_score
    total_max += cat_max

    # Display results
    print_section("Score Card Results")
    pct_total = (total_score / total_max * 100) if total_max > 0 else 0

    for cat_name, (score, max_s) in categories.items():
        pct = (score / max_s * 100) if max_s > 0 else 0
        bar_filled = int(pct / 5)
        bar_empty = 20 - bar_filled
        bar = "#" * bar_filled + "-" * bar_empty

        if pct >= 80:
            color = Colors.GREEN
        elif pct >= 50:
            color = Colors.YELLOW
        else:
            color = Colors.RED

        print("  {}{:30s}{} [{}{:20s}{}] {}/{} ({:.0f}%)".format(
            Colors.BOLD, cat_name, Colors.RESET,
            color, bar, Colors.RESET,
            score, max_s, pct,
        ))

    print()
    if pct_total >= 80:
        print_info("  Overall Score: {}/{} ({:.0f}%) - GOOD".format(total_score, total_max, pct_total))
    elif pct_total >= 50:
        print_warning("  Overall Score: {}/{} ({:.0f}%) - NEEDS IMPROVEMENT".format(total_score, total_max, pct_total))
    else:
        print_error("  Overall Score: {}/{} ({:.0f}%) - CRITICAL".format(total_score, total_max, pct_total))
