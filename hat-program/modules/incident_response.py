"""
Incident Response Module - Forensic timeline, IOC scanner, live response tools.
Helps blue team responders investigate and contain security incidents.
"""

import os
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
    require_root,
    get_user_input,
    display_menu,
    confirm_action,
    check_required_tools,
)


def incident_response_menu():
    """Incident response menu."""
    options = [
        "Live System Triage",
        "Forensic Timeline Builder",
        "IOC Scanner (Indicators of Compromise)",
        "Process Memory Analysis",
        "Network Forensics Snapshot",
        "File System Forensics",
        "Malware Quarantine",
        "Persistence Mechanism Scan",
        "Evidence Collection & Preservation",
        "Incident Response Checklist",
    ]

    while True:
        choice = display_menu("INCIDENT RESPONSE", options, Colors.BLUE)
        if choice == 0:
            break
        elif choice == 1:
            live_triage()
        elif choice == 2:
            forensic_timeline()
        elif choice == 3:
            ioc_scanner()
        elif choice == 4:
            process_memory_analysis()
        elif choice == 5:
            network_forensics()
        elif choice == 6:
            filesystem_forensics()
        elif choice == 7:
            malware_quarantine()
        elif choice == 8:
            persistence_scan()
        elif choice == 9:
            evidence_collection()
        elif choice == 10:
            ir_checklist()


def live_triage():
    """Perform live system triage for incident response."""
    print_section("Live System Triage")
    print_status("Collecting volatile data (most volatile first)...")

    output_dir = get_user_input("Evidence output directory", "/tmp/ir_evidence")
    run_command(f"mkdir -p {output_dir}")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    evidence = []

    # 1. System time
    print_status("[1/10] System time...")
    stdout, _, _ = run_command("date -u && date")
    evidence.append(("system_time", stdout))
    print_info(f"System time: {stdout}")

    # 2. Logged in users
    print_status("[2/10] Logged in users...")
    stdout, _, _ = run_command("who -a")
    evidence.append(("logged_users", stdout))
    if stdout:
        print_info(f"Logged users:\n{stdout}")

    # 3. Network connections
    print_status("[3/10] Network connections...")
    stdout, _, _ = run_command("ss -tunapl 2>/dev/null")
    evidence.append(("network_connections", stdout))
    if stdout:
        print_info("Active connections captured.")

    # 4. Running processes
    print_status("[4/10] Running processes...")
    stdout, _, _ = run_command("ps auxef")
    evidence.append(("processes", stdout))
    print_info("Process list captured.")

    # 5. Open files
    print_status("[5/10] Open files...")
    stdout, _, _ = run_command("lsof -n 2>/dev/null | head -100")
    evidence.append(("open_files", stdout))
    print_info("Open file handles captured.")

    # 6. Network config
    print_status("[6/10] Network configuration...")
    stdout, _, _ = run_command("ip addr show && ip route show && cat /etc/resolv.conf")
    evidence.append(("network_config", stdout))

    # 7. ARP cache
    print_status("[7/10] ARP cache...")
    stdout, _, _ = run_command("arp -a 2>/dev/null || ip neigh show")
    evidence.append(("arp_cache", stdout))

    # 8. Routing table
    print_status("[8/10] Routing table...")
    stdout, _, _ = run_command("ip route show table all 2>/dev/null")
    evidence.append(("routing", stdout))

    # 9. Loaded kernel modules
    print_status("[9/10] Kernel modules...")
    stdout, _, _ = run_command("lsmod")
    evidence.append(("kernel_modules", stdout))

    # 10. Mounted filesystems
    print_status("[10/10] Mounted filesystems...")
    stdout, _, _ = run_command("mount && df -h")
    evidence.append(("filesystems", stdout))

    # Save all evidence
    for name, data in evidence:
        if data:
            filepath = os.path.join(output_dir, f"{name}_{timestamp}.txt")
            with open(filepath, "w") as f:
                f.write(f"# Collected: {datetime.datetime.now().isoformat()}\n")
                f.write(data)

    print_section("Triage Complete")
    print_info(f"Evidence saved to: {output_dir}")


def forensic_timeline():
    """Build a forensic timeline from system artifacts."""
    print_section("Forensic Timeline Builder")

    search_path = get_user_input("Search path for timeline", "/")
    hours = get_user_input("Hours to look back", "24")
    output_file = get_user_input("Output file", "/tmp/forensic_timeline.txt")

    print_status(f"Building timeline for last {hours} hours...")

    timeline = []

    # Recently modified files
    print_status("Finding recently modified files...")
    stdout, _, _ = run_command(
        f"find {search_path} -maxdepth 4 -type f -mmin -{int(hours) * 60} "
        f"-not -path '*/proc/*' -not -path '*/sys/*' -not -path '*/dev/*' "
        f"-printf '%T+ %s %p\\n' 2>/dev/null | sort -r | head -100",
        timeout=60,
    )
    if stdout:
        timeline.append("=== Recently Modified Files ===")
        timeline.append(stdout)

    # Recent auth events
    print_status("Collecting authentication events...")
    stdout, _, _ = run_command(
        f"journalctl --since='-{hours}h' -u ssh --no-pager 2>/dev/null | tail -50"
    )
    if stdout:
        timeline.append("\n=== SSH Events ===")
        timeline.append(stdout)

    # Recent login/logout
    stdout, _, _ = run_command(f"last -n 30 2>/dev/null")
    if stdout:
        timeline.append("\n=== Login/Logout Events ===")
        timeline.append(stdout)

    # Recent sudo activity
    stdout, _, _ = run_command(
        f"journalctl -t sudo --since='-{hours}h' --no-pager 2>/dev/null"
    )
    if stdout:
        timeline.append("\n=== Sudo Activity ===")
        timeline.append(stdout)

    # Recent package installs
    stdout, _, _ = run_command(
        f"grep -h 'install\\|remove\\|upgrade' /var/log/dpkg.log 2>/dev/null | tail -30"
    )
    if stdout:
        timeline.append("\n=== Package Changes ===")
        timeline.append(stdout)

    # Recent systemd service changes
    stdout, _, _ = run_command(
        f"journalctl --since='-{hours}h' -u '*.service' --no-pager 2>/dev/null | "
        f"grep -i 'start\\|stop\\|fail' | tail -30"
    )
    if stdout:
        timeline.append("\n=== Service Events ===")
        timeline.append(stdout)

    # Write timeline
    with open(output_file, "w") as f:
        f.write(f"# Forensic Timeline - Generated {datetime.datetime.now().isoformat()}\n")
        f.write(f"# Search path: {search_path}\n")
        f.write(f"# Time window: last {hours} hours\n\n")
        f.write("\n".join(timeline))

    print_info(f"Timeline saved to: {output_file}")
    print_info(f"Total sections: {len(timeline)}")


def ioc_scanner():
    """Scan for Indicators of Compromise."""
    print_section("IOC Scanner")

    options = [
        "Scan for known malicious IPs/domains",
        "Scan for suspicious files",
        "Scan for rootkit indicators",
        "Scan for crypto miners",
        "Scan for backdoor indicators",
        "Full IOC sweep",
    ]

    choice = display_menu("IOC Scanner Options", options, Colors.BLUE)
    if choice == 0:
        return

    if choice == 1 or choice == 6:
        scan_malicious_connections()
    if choice == 2 or choice == 6:
        scan_suspicious_files()
    if choice == 3 or choice == 6:
        scan_rootkit_indicators()
    if choice == 4 or choice == 6:
        scan_crypto_miners()
    if choice == 5 or choice == 6:
        scan_backdoors()


def scan_malicious_connections():
    """Scan for connections to known malicious indicators."""
    print_section("Malicious Connection Scan")

    print_status("Checking active connections...")
    stdout, _, _ = run_command("ss -tn state established 2>/dev/null")
    if stdout:
        print_info("Established connections:")
        print(stdout)

        # Check for connections to unusual ports
        suspicious_ports = ["4444", "5555", "6666", "1337", "31337", "12345", "54321"]
        for line in stdout.split("\n"):
            for port in suspicious_ports:
                if f":{port}" in line:
                    print_error(f"  Suspicious port detected: {line.strip()}")

    # Check DNS queries if possible
    stdout, _, _ = run_command("cat /etc/resolv.conf")
    if stdout:
        print_section("DNS Configuration")
        print(stdout)

    # Check /etc/hosts for suspicious entries
    print_section("Hosts File Check")
    stdout, _, _ = run_command("cat /etc/hosts")
    if stdout:
        for line in stdout.split("\n"):
            if line.strip() and not line.startswith("#"):
                # Flag unusual entries
                if "localhost" not in line and "ip6" not in line:
                    print_warning(f"  Non-standard hosts entry: {line}")


def scan_suspicious_files():
    """Scan for suspicious files on the system."""
    print_section("Suspicious File Scan")

    # Recently modified system files
    print_status("Checking recently modified system files...")
    stdout, _, _ = run_command(
        "find /bin /sbin /usr/bin /usr/sbin -type f -mtime -7 2>/dev/null | head -20",
        timeout=30,
    )
    if stdout:
        print_warning("System binaries modified in last 7 days:")
        print(stdout)
    else:
        print_info("No recently modified system binaries.")

    # Hidden files in unusual locations
    print_status("Checking for hidden files in unusual locations...")
    stdout, _, _ = run_command(
        "find /tmp /var/tmp /dev/shm -name '.*' -type f 2>/dev/null",
        timeout=15,
    )
    if stdout:
        print_warning("Hidden files in temp directories:")
        print(stdout)

    # Large files in temp
    print_status("Checking for large files in temp directories...")
    stdout, _, _ = run_command(
        "find /tmp /var/tmp -type f -size +10M 2>/dev/null",
        timeout=15,
    )
    if stdout:
        print_warning("Large files in temp directories:")
        print(stdout)

    # Files with suspicious extensions
    print_status("Checking for suspicious file extensions...")
    stdout, _, _ = run_command(
        "find /tmp /var/tmp /home -name '*.sh' -o -name '*.py' -o -name '*.pl' "
        "-o -name '*.elf' -o -name '*.bin' 2>/dev/null | head -20",
        timeout=15,
    )
    if stdout:
        print_warning("Script/binary files in user directories:")
        print(stdout)


def scan_rootkit_indicators():
    """Scan for rootkit indicators."""
    print_section("Rootkit Indicator Scan")

    # Check for hidden processes
    print_status("Checking for hidden processes...")
    stdout_ps, _, _ = run_command("ps aux | wc -l")
    stdout_proc, _, _ = run_command("ls /proc | grep -E '^[0-9]+$' | wc -l")
    if stdout_ps and stdout_proc:
        ps_count = int(stdout_ps.strip())
        proc_count = int(stdout_proc.strip())
        if abs(ps_count - proc_count) > 5:
            print_error(f"Process count mismatch: ps={ps_count}, /proc={proc_count}")
            print_error("This may indicate hidden processes!")
        else:
            print_info(f"Process counts match: ps={ps_count}, /proc={proc_count}")

    # Check for hidden kernel modules
    print_status("Checking kernel modules...")
    stdout, _, _ = run_command("lsmod | wc -l")
    if stdout:
        print_info(f"Loaded kernel modules: {stdout.strip()}")

    # Check for rootkit files
    print_status("Checking for known rootkit files...")
    rootkit_files = [
        "/usr/lib/libproc.a", "/usr/lib/libproc.so",
        "/dev/.tmp", "/dev/.hdd", "/dev/.hda",
        "/tmp/.scsi", "/usr/bin/sourcemask", "/usr/bin/amir",
    ]
    for f in rootkit_files:
        stdout, _, rc = run_command(f"test -f {f} && echo 'found'")
        if "found" in stdout:
            print_error(f"  Rootkit indicator found: {f}")

    # Use rkhunter if available
    if check_tool("rkhunter"):
        if confirm_action("Run rkhunter rootkit scan?"):
            print_status("Running rkhunter...")
            stdout, _, _ = run_command("rkhunter --check --skip-keypress --report-warnings-only 2>&1", timeout=180)
            if stdout:
                print(stdout)
    else:
        print_info("Install rkhunter for comprehensive rootkit scanning: sudo apt install rkhunter")

    # Use chkrootkit if available
    if check_tool("chkrootkit"):
        if confirm_action("Run chkrootkit?"):
            print_status("Running chkrootkit...")
            stdout, _, _ = run_command("chkrootkit 2>&1 | grep -v 'not found' | head -30", timeout=120)
            if stdout:
                print(stdout)


def scan_crypto_miners():
    """Scan for cryptocurrency mining indicators."""
    print_section("Crypto Miner Detection")

    # Check processes
    print_status("Checking for mining processes...")
    miner_names = [
        "xmrig", "xmr-stak", "minerd", "cpuminer", "minergate",
        "kworkerds", "kdevtmpfsi", "kinsing", "cryptonight",
        "stratum", "nicehash", "ethminer",
    ]

    stdout, _, _ = run_command("ps aux")
    if stdout:
        for miner in miner_names:
            if miner.lower() in stdout.lower():
                print_error(f"  Mining process detected: {miner}")

    # Check for high CPU usage
    print_section("High CPU Processes")
    stdout, _, _ = run_command("ps aux --sort=-%cpu | head -6")
    if stdout:
        print_info("Top CPU consumers:")
        print(stdout)

    # Check for mining pool connections
    print_status("Checking for mining pool connections...")
    stdout, _, _ = run_command("ss -tn state established 2>/dev/null")
    if stdout:
        mining_ports = ["3333", "4444", "5555", "7777", "8888", "9999", "14444", "45700"]
        for line in stdout.split("\n"):
            for port in mining_ports:
                if f":{port}" in line:
                    print_error(f"  Possible mining pool connection: {line.strip()}")

    # Check crontab for miners
    print_status("Checking crontab for mining entries...")
    stdout, _, _ = run_command(
        "for user in $(cut -d: -f1 /etc/passwd); do "
        "crontab -u $user -l 2>/dev/null; done"
    )
    if stdout:
        for miner in miner_names:
            if miner.lower() in stdout.lower():
                print_error(f"  Mining cron job found referencing: {miner}")


def scan_backdoors():
    """Scan for common backdoor indicators."""
    print_section("Backdoor Indicator Scan")

    # Check for unauthorized SSH keys
    print_status("Checking SSH authorized_keys files...")
    stdout, _, _ = run_command(
        "find /home /root -name 'authorized_keys' -exec echo '=== {} ===' \\; -exec cat {} \\; 2>/dev/null"
    )
    if stdout:
        print_warning("Authorized keys found:")
        print(stdout)

    # Check for suspicious cron jobs
    print_status("Checking for suspicious cron entries...")
    stdout, _, _ = run_command(
        "for user in $(cut -d: -f1 /etc/passwd); do "
        "crontab -u $user -l 2>/dev/null | grep -E 'curl|wget|nc |ncat|bash -i|/dev/tcp|python.*import'; done"
    )
    if stdout:
        print_error(f"Suspicious cron entries:\n{stdout}")

    # Check for reverse shells in /tmp
    print_status("Checking /tmp for suspicious scripts...")
    stdout, _, _ = run_command(
        "grep -rl '/dev/tcp\\|bash -i\\|nc -e\\|python.*socket' /tmp /var/tmp 2>/dev/null"
    )
    if stdout:
        print_error(f"Files with reverse shell patterns:\n{stdout}")

    # Check for modified PAM modules
    print_status("Checking PAM modules...")
    stdout, _, _ = run_command(
        "find /lib/x86_64-linux-gnu/security/ /lib/security/ -type f -mtime -30 2>/dev/null"
    )
    if stdout:
        print_warning(f"Recently modified PAM modules:\n{stdout}")

    # Check systemd for suspicious services
    print_status("Checking for suspicious systemd services...")
    stdout, _, _ = run_command(
        "systemctl list-unit-files --type=service --no-pager 2>/dev/null | "
        "grep enabled | grep -v -E '(ssh|cron|systemd|network|dbus|rsyslog|ufw|apparmor|docker|snapd)'"
    )
    if stdout:
        print_info("Enabled services (review for suspicious entries):")
        print(stdout)


def process_memory_analysis():
    """Analyze process memory for suspicious content."""
    print_section("Process Memory Analysis")

    require_root("Process memory analysis")

    # List interesting processes
    print_section("Processes of Interest")
    stdout, _, _ = run_command(
        "ps aux | grep -v -E '(\\[.*\\]|grep|ps aux)' | awk '$3>5 || $4>5 {print $0}'"
    )
    if stdout:
        print_info("High resource processes:")
        print(stdout)

    pid = get_user_input("Enter PID to analyze (or 'skip')", "skip")
    if pid == "skip":
        return

    # Process info
    print_section(f"Process {pid} Details")
    stdout, _, _ = run_command(f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '")
    if stdout:
        print_info(f"Command: {stdout}")

    stdout, _, _ = run_command(f"cat /proc/{pid}/status 2>/dev/null | head -20")
    if stdout:
        print_info(f"Status:\n{stdout}")

    stdout, _, _ = run_command(f"ls -la /proc/{pid}/exe 2>/dev/null")
    if stdout:
        print_info(f"Executable: {stdout}")

    stdout, _, _ = run_command(f"ls -la /proc/{pid}/fd 2>/dev/null | head -20")
    if stdout:
        print_info(f"File descriptors:\n{stdout}")

    # Memory maps
    stdout, _, _ = run_command(f"cat /proc/{pid}/maps 2>/dev/null | head -30")
    if stdout:
        print_section("Memory Maps (first 30)")
        print(stdout)

    # Environment variables
    stdout, _, _ = run_command(f"cat /proc/{pid}/environ 2>/dev/null | tr '\\0' '\\n' | head -20")
    if stdout:
        print_section("Environment Variables")
        print(stdout)


def network_forensics():
    """Capture and analyze network state for forensics."""
    print_section("Network Forensics Snapshot")

    output_dir = get_user_input("Output directory", "/tmp/ir_evidence")
    run_command(f"mkdir -p {output_dir}")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Capture all network state
    captures = [
        ("All connections", "ss -tunapl", "connections"),
        ("Established connections", "ss -tn state established", "established"),
        ("Listening ports", "ss -tlnp", "listeners"),
        ("ARP table", "ip neigh show", "arp"),
        ("Routes", "ip route show table all", "routes"),
        ("Interfaces", "ip addr show", "interfaces"),
        ("DNS cache", "resolvectl statistics 2>/dev/null || echo 'N/A'", "dns"),
        ("iptables", "iptables -L -n -v 2>/dev/null || echo 'Need root'", "firewall"),
    ]

    for desc, cmd, name in captures:
        print_status(f"Capturing {desc}...")
        stdout, _, _ = run_command(cmd)
        if stdout:
            filepath = os.path.join(output_dir, f"net_{name}_{timestamp}.txt")
            with open(filepath, "w") as f:
                f.write(f"# {desc} - {datetime.datetime.now().isoformat()}\n")
                f.write(stdout)

    # Packet capture if available
    if check_tool("tcpdump"):
        if confirm_action("Capture 30 seconds of network traffic?"):
            pcap_path = os.path.join(output_dir, f"capture_{timestamp}.pcap")
            print_status("Capturing traffic for 30 seconds...")
            run_command(f"timeout 30 tcpdump -i any -w {pcap_path} -c 1000 2>/dev/null", timeout=35)
            print_info(f"PCAP saved: {pcap_path}")

    print_info(f"Network forensics data saved to: {output_dir}")


def filesystem_forensics():
    """Perform filesystem forensic analysis."""
    print_section("File System Forensics")

    search_path = get_user_input("Search path", "/")

    options = [
        "Recently modified files (last 24h)",
        "Recently accessed files (last 24h)",
        "Recently created files (last 24h)",
        "Deleted but open files",
        "Hidden files and directories",
        "Files with altered timestamps",
    ]

    choice = display_menu("Forensic Search", options, Colors.BLUE)
    if choice == 0:
        return

    if choice == 1:
        print_status("Finding recently modified files...")
        stdout, _, _ = run_command(
            f"find {search_path} -maxdepth 4 -type f -mtime -1 "
            f"-not -path '*/proc/*' -not -path '*/sys/*' "
            f"-printf '%T+ %u:%g %m %s %p\\n' 2>/dev/null | sort -r | head -50",
            timeout=60,
        )
        if stdout:
            print_info("Recently modified files:")
            print(stdout)

    elif choice == 2:
        print_status("Finding recently accessed files...")
        stdout, _, _ = run_command(
            f"find {search_path} -maxdepth 4 -type f -atime -1 "
            f"-not -path '*/proc/*' -not -path '*/sys/*' "
            f"-printf '%A+ %u:%g %m %p\\n' 2>/dev/null | sort -r | head -50",
            timeout=60,
        )
        if stdout:
            print_info("Recently accessed files:")
            print(stdout)

    elif choice == 3:
        print_status("Finding recently created files...")
        stdout, _, _ = run_command(
            f"find {search_path} -maxdepth 4 -type f -ctime -1 "
            f"-not -path '*/proc/*' -not -path '*/sys/*' "
            f"-printf '%C+ %u:%g %m %s %p\\n' 2>/dev/null | sort -r | head -50",
            timeout=60,
        )
        if stdout:
            print_info("Recently created files:")
            print(stdout)

    elif choice == 4:
        print_status("Finding deleted but open files...")
        stdout, _, _ = run_command("lsof 2>/dev/null | grep deleted | head -20")
        if stdout:
            print_warning("Deleted but still open files:")
            print(stdout)
        else:
            print_info("No deleted-but-open files found.")

    elif choice == 5:
        print_status("Finding hidden files and directories...")
        stdout, _, _ = run_command(
            f"find {search_path} -maxdepth 3 -name '.*' "
            f"-not -path '*/proc/*' -not -path '*/sys/*' "
            f"-not -name '.bashrc' -not -name '.profile' -not -name '.bash_history' "
            f"-not -name '.gitignore' -not -name '.git' "
            f"2>/dev/null | head -30",
            timeout=30,
        )
        if stdout:
            print_info("Hidden files/directories:")
            print(stdout)

    elif choice == 6:
        print_status("Finding files with future timestamps...")
        stdout, _, _ = run_command(
            f"find {search_path} -maxdepth 3 -type f -newer /proc/uptime "
            f"-not -path '*/proc/*' -not -path '*/sys/*' "
            f"2>/dev/null | head -20",
            timeout=30,
        )
        if stdout:
            print_warning("Files with unusual timestamps:")
            print(stdout)


def malware_quarantine():
    """Quarantine suspicious files."""
    print_section("Malware Quarantine")

    require_root("Malware quarantine")

    filepath = get_user_input("File path to quarantine")
    if not filepath:
        print_error("No file specified.")
        return

    stdout, _, rc = run_command(f"test -f {filepath} && echo 'exists'")
    if "exists" not in stdout:
        print_error(f"File not found: {filepath}")
        return

    # Show file info first
    stdout, _, _ = run_command(f"file {filepath}")
    print_info(f"File type: {stdout}")
    stdout, _, _ = run_command(f"sha256sum {filepath}")
    print_info(f"SHA256: {stdout}")
    stdout, _, _ = run_command(f"ls -la {filepath}")
    print_info(f"Details: {stdout}")

    # ClamAV scan if available
    if check_tool("clamscan"):
        print_status("Scanning with ClamAV...")
        stdout, _, _ = run_command(f"clamscan {filepath} 2>&1")
        if stdout:
            print_info(f"ClamAV result:\n{stdout}")

    if not confirm_action(f"Quarantine {filepath}?"):
        return

    quarantine_dir = "/tmp/quarantine"
    run_command(f"mkdir -p {quarantine_dir}")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    basename = os.path.basename(filepath)
    quarantine_path = f"{quarantine_dir}/{basename}.{timestamp}.quarantine"

    # Move and strip permissions
    stdout, stderr, rc = run_command(f"cp {filepath} {quarantine_path} && chmod 000 {quarantine_path}")
    if rc == 0:
        print_info(f"File quarantined: {quarantine_path}")
        if confirm_action("Remove original file?"):
            run_command(f"rm -f {filepath}")
            print_info("Original file removed.")
    else:
        print_error(f"Failed to quarantine: {stderr}")


def persistence_scan():
    """Scan for persistence mechanisms."""
    print_section("Persistence Mechanism Scan")

    # Cron jobs
    print_section("Cron-based Persistence")
    stdout, _, _ = run_command(
        "for user in $(cut -d: -f1 /etc/passwd); do "
        "echo \"=== $user ===\"; crontab -u $user -l 2>/dev/null; done"
    )
    if stdout and "no crontab" not in stdout.lower():
        print_info("Cron jobs:")
        print(stdout)

    # System cron
    stdout, _, _ = run_command("cat /etc/crontab 2>/dev/null; ls /etc/cron.d/ 2>/dev/null")
    if stdout:
        print_info(f"System cron:\n{stdout}")

    # Systemd services
    print_section("Systemd Persistence")
    stdout, _, _ = run_command(
        "find /etc/systemd/system /run/systemd/system ~/.config/systemd "
        "-name '*.service' -mtime -30 2>/dev/null"
    )
    if stdout:
        print_warning("Recently modified systemd services:")
        print(stdout)

    # Init scripts
    print_section("Init Script Persistence")
    stdout, _, _ = run_command(
        "find /etc/init.d/ /etc/rc*.d/ -type f -mtime -30 2>/dev/null | head -10"
    )
    if stdout:
        print_warning("Recently modified init scripts:")
        print(stdout)

    # Shell profiles
    print_section("Shell Profile Persistence")
    stdout, _, _ = run_command(
        "find /home /root -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' "
        "-o -name '.bash_login' -o -name '.zshrc' 2>/dev/null | "
        "xargs -I{} sh -c 'echo \"=== {} ===\"; tail -5 {}' 2>/dev/null"
    )
    if stdout:
        print_info("Shell profile tails:")
        print(stdout)

    # SSH keys
    print_section("SSH Key Persistence")
    stdout, _, _ = run_command(
        "find /home /root -name 'authorized_keys' 2>/dev/null | "
        "xargs -I{} sh -c 'echo \"=== {} ===\"; wc -l {}; stat -c \"%y %U\" {}' 2>/dev/null"
    )
    if stdout:
        print_info("SSH authorized_keys:")
        print(stdout)

    # At jobs
    print_section("At Job Persistence")
    stdout, _, _ = run_command("atq 2>/dev/null")
    if stdout:
        print_warning(f"Scheduled at jobs:\n{stdout}")
    else:
        print_info("No at jobs scheduled.")


def evidence_collection():
    """Collect and preserve evidence for incident response."""
    print_section("Evidence Collection & Preservation")

    output_dir = get_user_input("Evidence output directory", "/tmp/ir_evidence")
    run_command(f"mkdir -p {output_dir}")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if not confirm_action("Collect comprehensive evidence? This may take a few minutes."):
        return

    print_status("Collecting evidence...")

    collections = [
        ("System info", "uname -a; cat /etc/os-release; uptime; date -u"),
        ("Users", "cat /etc/passwd; cat /etc/group; last -n 50; lastb -n 50 2>/dev/null"),
        ("Network state", "ss -tunapl; ip addr; ip route; arp -a; cat /etc/resolv.conf; cat /etc/hosts"),
        ("Processes", "ps auxef; top -b -n1 | head -40"),
        ("Open files", "lsof -n 2>/dev/null | head -200"),
        ("Kernel", "uname -a; lsmod; dmesg --level=err,warn 2>/dev/null | tail -50"),
        ("Services", "systemctl list-units --type=service --no-pager"),
        ("Cron", "crontab -l 2>/dev/null; cat /etc/crontab; ls -la /etc/cron.d/"),
        ("SSH", "cat /etc/ssh/sshd_config 2>/dev/null"),
        ("Firewall", "iptables -L -n -v 2>/dev/null; ufw status 2>/dev/null"),
        ("Logs auth", "tail -200 /var/log/auth.log 2>/dev/null"),
        ("Logs syslog", "tail -200 /var/log/syslog 2>/dev/null"),
        ("Disk", "df -h; mount"),
        ("Env", "env; printenv"),
    ]

    for name, cmd in collections:
        print_status(f"  Collecting: {name}...")
        stdout, stderr, _ = run_command(cmd, timeout=30)
        output = stdout if stdout else stderr
        filepath = os.path.join(output_dir, f"{name.replace(' ', '_')}_{timestamp}.txt")
        with open(filepath, "w") as f:
            f.write(f"# Evidence: {name}\n# Collected: {datetime.datetime.now().isoformat()}\n\n")
            f.write(output if output else "No data collected\n")

    # Create hash manifest
    print_status("Creating evidence hash manifest...")
    stdout, _, _ = run_command(f"sha256sum {output_dir}/*.txt 2>/dev/null")
    if stdout:
        manifest_path = os.path.join(output_dir, f"MANIFEST_{timestamp}.sha256")
        with open(manifest_path, "w") as f:
            f.write(f"# Evidence Manifest - {datetime.datetime.now().isoformat()}\n")
            f.write(stdout)
        print_info(f"Manifest: {manifest_path}")

    print_info(f"Evidence collected in: {output_dir}")


def ir_checklist():
    """Display an incident response checklist."""
    print_section("Incident Response Checklist")

    checklist = [
        ("PREPARATION", [
            "Verify IR plan is accessible",
            "Confirm team contacts and escalation paths",
            "Ensure forensic tools are available",
            "Document the initial alert/report",
        ]),
        ("IDENTIFICATION", [
            "Determine scope of the incident",
            "Identify affected systems",
            "Capture volatile evidence (memory, connections, processes)",
            "Review logs (auth, syslog, application)",
            "Determine attack vector and timeline",
        ]),
        ("CONTAINMENT", [
            "Isolate affected systems from network",
            "Block malicious IPs at firewall",
            "Disable compromised accounts",
            "Preserve evidence before changes",
            "Implement temporary fixes",
        ]),
        ("ERADICATION", [
            "Remove malware/backdoors",
            "Patch exploited vulnerabilities",
            "Reset compromised credentials",
            "Remove persistence mechanisms",
            "Verify rootkit removal",
        ]),
        ("RECOVERY", [
            "Restore systems from clean backups",
            "Verify system integrity",
            "Monitor for re-infection",
            "Gradually restore services",
            "Validate security controls",
        ]),
        ("LESSONS LEARNED", [
            "Document incident timeline",
            "Identify root cause",
            "Update IR procedures",
            "Implement preventive measures",
            "Brief stakeholders",
        ]),
    ]

    for phase, items in checklist:
        print_section(phase)
        for i, item in enumerate(items, 1):
            print(f"  [ ] {i}. {item}")
