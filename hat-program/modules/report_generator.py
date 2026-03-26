"""
Report Generator Module - Export security findings to HTML and text reports.
Captures output from scans and audits, generates professional reports.
"""

import os
import json
import datetime

from modules.utils import (
    Colors,
    print_section,
    print_info,
    print_warning,
    print_error,
    print_status,
    run_command,
    get_user_input,
    display_menu,
    confirm_action,
)


class ReportCollector:
    """Collects findings during a session for report generation."""

    def __init__(self):
        self.findings = []
        self.session_start = datetime.datetime.now()
        self.hostname = ""
        self.ip_info = ""
        self._load_system_info()

    def _load_system_info(self):
        stdout, _, _ = run_command("hostname")
        self.hostname = stdout.strip() if stdout else "unknown"
        stdout, _, _ = run_command("hostname -I 2>/dev/null")
        self.ip_info = stdout.strip() if stdout else "N/A"

    def add_finding(self, category, title, severity, description, details=""):
        """Add a finding to the report."""
        self.findings.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "category": category,
            "title": title,
            "severity": severity,
            "description": description,
            "details": details,
        })

    def get_findings_by_severity(self):
        """Group findings by severity."""
        grouped = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for finding in self.findings:
            sev = finding.get("severity", "INFO").upper()
            if sev in grouped:
                grouped[sev].append(finding)
            else:
                grouped["INFO"].append(finding)
        return grouped

    def clear(self):
        """Clear all findings."""
        self.findings = []


# Global report collector instance
report_collector = ReportCollector()


def report_menu():
    """Report generation menu."""
    options = [
        "Quick Security Scan & Report",
        "Generate Report from Current Session",
        "Full System Security Report (comprehensive)",
        "Network Assessment Report",
        "Compliance Summary Report",
        "Export Findings to JSON",
        "View Current Findings",
        "Clear Current Findings",
    ]

    while True:
        choice = display_menu("REPORT GENERATOR", options, Colors.CYAN)
        if choice == 0:
            break
        elif choice == 1:
            quick_security_report()
        elif choice == 2:
            generate_session_report()
        elif choice == 3:
            full_system_report()
        elif choice == 4:
            network_assessment_report()
        elif choice == 5:
            compliance_report()
        elif choice == 6:
            export_json()
        elif choice == 7:
            view_findings()
        elif choice == 8:
            if confirm_action("Clear all findings?"):
                report_collector.clear()
                print_info("Findings cleared.")


def _run_and_capture(title, command, timeout=30):
    """Run a command and return formatted output."""
    stdout, stderr, rc = run_command(command, timeout=timeout)
    output = stdout if stdout else stderr
    return f"\n### {title}\n```\n{output}\n```\n" if output else ""


def quick_security_report():
    """Generate a quick security scan report."""
    print_section("Quick Security Scan & Report")

    output_dir = get_user_input("Output directory", "/tmp")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"quick_security_report_{timestamp}"

    print_status("Running quick security scan...")

    sections = []

    # System info
    print_status("Gathering system information...")
    sections.append(_run_and_capture("System Information", "uname -a"))
    sections.append(_run_and_capture("OS Release", "cat /etc/os-release 2>/dev/null"))
    sections.append(_run_and_capture("Uptime", "uptime"))

    # Network
    print_status("Checking network configuration...")
    sections.append(_run_and_capture("Network Interfaces", "ip addr show 2>/dev/null || ifconfig"))
    sections.append(_run_and_capture("Routing Table", "ip route show 2>/dev/null || route -n"))
    sections.append(_run_and_capture("DNS Configuration", "cat /etc/resolv.conf"))

    # Security checks
    print_status("Running security checks...")
    sections.append(_run_and_capture("Listening Ports", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"))
    sections.append(_run_and_capture("Established Connections", "ss -tn state established 2>/dev/null"))
    sections.append(_run_and_capture("Firewall Status", "ufw status 2>/dev/null || iptables -L -n 2>/dev/null"))
    sections.append(_run_and_capture("Failed Login Attempts", "lastb -n 20 2>/dev/null || echo 'Need root access'"))
    sections.append(_run_and_capture("Users with Login Shells",
                                      "awk -F: '$7 !~ /(nologin|false)/ {print $1,$3,$7}' /etc/passwd"))
    sections.append(_run_and_capture("SUID Binaries", "find /usr -perm -4000 -type f 2>/dev/null | head -20"))
    sections.append(_run_and_capture("Running Services",
                                      "systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -30"))
    sections.append(_run_and_capture("Kernel Security Parameters",
                                      "sysctl net.ipv4.ip_forward net.ipv4.tcp_syncookies "
                                      "net.ipv4.conf.all.accept_redirects 2>/dev/null"))

    # Generate HTML report
    html_content = _build_html_report(
        "Quick Security Scan Report",
        "".join(sections),
        report_collector,
    )

    html_path = os.path.join(output_dir, f"{filename}.html")
    txt_path = os.path.join(output_dir, f"{filename}.txt")

    with open(html_path, "w") as f:
        f.write(html_content)
    print_info(f"HTML report saved: {html_path}")

    # Also save text version
    text_content = _build_text_report("Quick Security Scan Report", "".join(sections))
    with open(txt_path, "w") as f:
        f.write(text_content)
    print_info(f"Text report saved: {txt_path}")


def generate_session_report():
    """Generate report from current session findings."""
    print_section("Session Report Generation")

    if not report_collector.findings:
        print_warning("No findings collected in current session.")
        print_info("Use the tools in Red/Blue/Black hat modules to collect findings.")
        return

    output_dir = get_user_input("Output directory", "/tmp")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    grouped = report_collector.get_findings_by_severity()
    content = "\n## Findings Summary\n\n"

    total = len(report_collector.findings)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = len(grouped[sev])
        if count:
            content += f"- **{sev}**: {count}\n"

    content += f"\n**Total Findings**: {total}\n\n"

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if grouped[sev]:
            content += f"\n## {sev} Findings\n\n"
            for finding in grouped[sev]:
                content += f"### {finding['title']}\n"
                content += f"- **Category**: {finding['category']}\n"
                content += f"- **Time**: {finding['timestamp']}\n"
                content += f"- **Description**: {finding['description']}\n"
                if finding['details']:
                    content += f"\n```\n{finding['details']}\n```\n"
                content += "\n"

    html_content = _build_html_report("Session Security Report", content, report_collector)
    html_path = os.path.join(output_dir, f"session_report_{timestamp}.html")
    with open(html_path, "w") as f:
        f.write(html_content)
    print_info(f"Report saved: {html_path}")


def full_system_report():
    """Generate a comprehensive system security report."""
    print_section("Full System Security Report")
    print_warning("This will take a few minutes to complete...")

    if not confirm_action("Proceed with comprehensive scan?"):
        return

    output_dir = get_user_input("Output directory", "/tmp")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    sections = []

    # 1. System Overview
    print_status("[1/8] System Overview...")
    sections.append("\n## 1. System Overview\n")
    sections.append(_run_and_capture("Kernel & OS", "uname -a"))
    sections.append(_run_and_capture("OS Release", "cat /etc/os-release 2>/dev/null"))
    sections.append(_run_and_capture("System Uptime", "uptime"))
    sections.append(_run_and_capture("CPU Info", "lscpu 2>/dev/null | head -20"))
    sections.append(_run_and_capture("Memory", "free -h"))
    sections.append(_run_and_capture("Disk Usage", "df -h"))

    # 2. User & Authentication
    print_status("[2/8] User & Authentication Audit...")
    sections.append("\n## 2. User & Authentication\n")
    sections.append(_run_and_capture("Login Users",
                                      "awk -F: '$7 !~ /(nologin|false)/ {print $1,$3,$6,$7}' /etc/passwd"))
    sections.append(_run_and_capture("Root-Equivalent Users",
                                      "awk -F: '$3==0 {print $1}' /etc/passwd"))
    sections.append(_run_and_capture("Sudoers", "cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' || echo 'Need root'"))
    sections.append(_run_and_capture("Recent Logins", "last -n 20 2>/dev/null"))
    sections.append(_run_and_capture("Failed Logins", "lastb -n 20 2>/dev/null || echo 'Need root'"))
    sections.append(_run_and_capture("Password Policy",
                                      "grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|ENCRYPT_METHOD)' /etc/login.defs 2>/dev/null"))

    # 3. Network Configuration
    print_status("[3/8] Network Configuration...")
    sections.append("\n## 3. Network Configuration\n")
    sections.append(_run_and_capture("Interfaces", "ip addr show 2>/dev/null || ifconfig"))
    sections.append(_run_and_capture("Routes", "ip route show 2>/dev/null || route -n"))
    sections.append(_run_and_capture("DNS", "cat /etc/resolv.conf"))
    sections.append(_run_and_capture("Hosts File", "cat /etc/hosts"))
    sections.append(_run_and_capture("ARP Table", "arp -a 2>/dev/null || ip neigh show"))

    # 4. Listening Services
    print_status("[4/8] Service & Port Audit...")
    sections.append("\n## 4. Listening Services & Ports\n")
    sections.append(_run_and_capture("TCP Listeners", "ss -tlnp 2>/dev/null"))
    sections.append(_run_and_capture("UDP Listeners", "ss -ulnp 2>/dev/null"))
    sections.append(_run_and_capture("Active Connections", "ss -tn state established 2>/dev/null | head -30"))
    sections.append(_run_and_capture("Running Services",
                                      "systemctl list-units --type=service --state=running --no-pager 2>/dev/null"))

    # 5. Firewall
    print_status("[5/8] Firewall Configuration...")
    sections.append("\n## 5. Firewall\n")
    sections.append(_run_and_capture("UFW Status", "ufw status verbose 2>/dev/null || echo 'UFW not available'"))
    sections.append(_run_and_capture("iptables Rules", "iptables -L -n -v 2>/dev/null || echo 'Need root'"))

    # 6. File System Security
    print_status("[6/8] File System Security...")
    sections.append("\n## 6. File System Security\n")
    sections.append(_run_and_capture("SUID Files", "find /usr /bin /sbin -perm -4000 -type f 2>/dev/null"))
    sections.append(_run_and_capture("SGID Files", "find /usr /bin /sbin -perm -2000 -type f 2>/dev/null"))
    sections.append(_run_and_capture("World-Writable Dirs",
                                      "find / -maxdepth 3 -perm -o+w -type d 2>/dev/null | grep -v proc | head -20"))
    sections.append(_run_and_capture("Mount Points", "mount | column -t 2>/dev/null"))

    # 7. Scheduled Tasks
    print_status("[7/8] Scheduled Tasks...")
    sections.append("\n## 7. Scheduled Tasks\n")
    sections.append(_run_and_capture("Crontab", "crontab -l 2>/dev/null || echo 'No crontab'"))
    sections.append(_run_and_capture("System Cron", "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null"))
    sections.append(_run_and_capture("Systemd Timers", "systemctl list-timers --no-pager 2>/dev/null"))

    # 8. Security Hardening
    print_status("[8/8] Security Hardening Checks...")
    sections.append("\n## 8. Security Hardening\n")
    sections.append(_run_and_capture("Kernel Parameters",
                                      "sysctl net.ipv4.ip_forward net.ipv4.tcp_syncookies "
                                      "net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects "
                                      "net.ipv4.conf.all.rp_filter kernel.randomize_va_space 2>/dev/null"))
    sections.append(_run_and_capture("SSH Config (security-relevant)",
                                      "grep -E '(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|X11Forwarding|MaxAuthTries|Protocol)' "
                                      "/etc/ssh/sshd_config 2>/dev/null || echo 'Cannot read SSH config'"))

    # Check if lynis is available
    stdout, _, _ = run_command("which lynis 2>/dev/null")
    if stdout:
        sections.append(_run_and_capture("Lynis Quick Audit", "lynis audit system --quick --no-colors 2>/dev/null | tail -40", timeout=120))

    # Build report
    all_content = "".join(sections)
    html = _build_html_report("Comprehensive System Security Report", all_content, report_collector)

    html_path = os.path.join(output_dir, f"full_security_report_{timestamp}.html")
    txt_path = os.path.join(output_dir, f"full_security_report_{timestamp}.txt")

    with open(html_path, "w") as f:
        f.write(html)
    print_info(f"HTML report: {html_path}")

    text = _build_text_report("Comprehensive System Security Report", all_content)
    with open(txt_path, "w") as f:
        f.write(text)
    print_info(f"Text report: {txt_path}")


def network_assessment_report():
    """Generate a network-focused assessment report."""
    print_section("Network Assessment Report")

    target = get_user_input("Target network or host (e.g., 192.168.1.0/24)")
    if not target:
        print_error("No target specified.")
        return

    output_dir = get_user_input("Output directory", "/tmp")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    sections = []
    sections.append(f"\n## Target: {target}\n")

    print_status("Running network assessment...")

    sections.append(_run_and_capture("Host Discovery", f"nmap -sn {target} 2>/dev/null || ping -c 2 {target}", timeout=120))
    sections.append(_run_and_capture("Port Scan", f"nmap -sV --top-ports 200 {target} 2>/dev/null || echo 'nmap not available'", timeout=180))
    sections.append(_run_and_capture("Traceroute", f"traceroute -m 15 {target} 2>/dev/null || tracepath {target} 2>/dev/null"))

    # If it's a domain, do DNS
    if not target[0].isdigit():
        sections.append(_run_and_capture("DNS Records", f"dig +short ANY {target} 2>/dev/null"))
        sections.append(_run_and_capture("WHOIS", f"whois {target} 2>/dev/null | head -40"))

    all_content = "".join(sections)
    html = _build_html_report(f"Network Assessment: {target}", all_content, report_collector)

    html_path = os.path.join(output_dir, f"network_assessment_{timestamp}.html")
    with open(html_path, "w") as f:
        f.write(html)
    print_info(f"Report saved: {html_path}")


def compliance_report():
    """Generate a compliance-focused summary report."""
    print_section("Compliance Summary Report")

    output_dir = get_user_input("Output directory", "/tmp")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    checks = []
    passed = 0
    failed = 0
    total = 0

    def check(name, command, expect_in=None, expect_not_in=None, expect_rc=0):
        nonlocal passed, failed, total
        total += 1
        stdout, _, rc = run_command(command, timeout=10)
        result = False

        if expect_in:
            result = expect_in.lower() in stdout.lower()
        elif expect_not_in:
            result = expect_not_in.lower() not in stdout.lower()
        else:
            result = (rc == expect_rc)

        status = "PASS" if result else "FAIL"
        if result:
            passed += 1
        else:
            failed += 1
        checks.append({"name": name, "status": status, "output": stdout[:200]})
        return result

    print_status("Running compliance checks...")

    # Authentication
    check("Password hashing uses strong algorithm", "grep -c 'SHA512\\|yescrypt' /etc/login.defs 2>/dev/null")
    check("Shadow file exists", "test -f /etc/shadow")
    check("No empty password accounts", "awk -F: '$2==\"\"' /etc/shadow 2>/dev/null", expect_not_in=":")
    check("Only root has UID 0", "awk -F: '$3==0{print $1}' /etc/passwd | wc -l", expect_in="1")

    # Network
    check("IP forwarding disabled", "sysctl net.ipv4.ip_forward 2>/dev/null", expect_in="= 0")
    check("SYN cookies enabled", "sysctl net.ipv4.tcp_syncookies 2>/dev/null", expect_in="= 1")
    check("ICMP redirects disabled", "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null", expect_in="= 0")
    check("Source routing disabled", "sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null", expect_in="= 0")

    # Services
    check("No telnet service", "ss -tlnp 2>/dev/null | grep ':23 '", expect_rc=1)
    check("No rsh service", "ss -tlnp 2>/dev/null | grep ':514 '", expect_rc=1)

    # SSH
    check("SSH root login disabled", "grep -i 'PermitRootLogin no' /etc/ssh/sshd_config 2>/dev/null")
    check("SSH password auth consideration", "grep -i 'PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null")

    # File permissions
    check("No world-writable files in /etc", "find /etc -perm -o+w -type f 2>/dev/null | wc -l", expect_in="0")

    # Build content
    content = f"\n## Compliance Check Results\n\n"
    content += f"**Passed**: {passed}/{total}  |  **Failed**: {failed}/{total}  |  "
    score = (passed / total * 100) if total > 0 else 0
    content += f"**Score**: {score:.0f}%\n\n"
    content += "| # | Check | Status |\n|---|-------|--------|\n"
    for i, c in enumerate(checks, 1):
        status_icon = "PASS" if c["status"] == "PASS" else "**FAIL**"
        content += f"| {i} | {c['name']} | {status_icon} |\n"

    html = _build_html_report("Compliance Summary Report", content, report_collector)
    html_path = os.path.join(output_dir, f"compliance_report_{timestamp}.html")
    with open(html_path, "w") as f:
        f.write(html)
    print_info(f"Report saved: {html_path}")
    print_info(f"Compliance Score: {score:.0f}% ({passed}/{total} checks passed)")


def export_json():
    """Export findings to JSON format."""
    print_section("Export Findings to JSON")

    if not report_collector.findings:
        print_warning("No findings to export.")
        return

    output_dir = get_user_input("Output directory", "/tmp")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"findings_{timestamp}.json")

    data = {
        "generated": datetime.datetime.now().isoformat(),
        "hostname": report_collector.hostname,
        "session_start": report_collector.session_start.isoformat(),
        "total_findings": len(report_collector.findings),
        "findings": report_collector.findings,
    }

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    print_info(f"JSON export saved: {filepath}")


def view_findings():
    """View current session findings."""
    print_section("Current Session Findings")

    if not report_collector.findings:
        print_warning("No findings collected yet.")
        return

    grouped = report_collector.get_findings_by_severity()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if grouped[sev]:
            print_section(f"{sev} ({len(grouped[sev])})")
            for f in grouped[sev]:
                print_info(f"  [{f['category']}] {f['title']}: {f['description']}")


def _build_html_report(title, content, collector):
    """Build a styled HTML report."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = collector.hostname if collector else "unknown"

    # Convert markdown-ish content to HTML
    html_body = content
    html_body = html_body.replace("```\n", "<pre>").replace("\n```", "</pre>")
    html_body = html_body.replace("## ", "<h2>").replace("\n\n", "</h2>\n", 1) if "## " in html_body else html_body

    # Simple markdown table to HTML
    lines = html_body.split("\n")
    processed = []
    in_table = False
    for line in lines:
        if line.strip().startswith("|") and "|" in line[1:]:
            if "---" in line:
                continue
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if not in_table:
                processed.append("<table class='report-table'>")
                processed.append("<tr>" + "".join(f"<th>{c}</th>" for c in cells) + "</tr>")
                in_table = True
            else:
                processed.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
        else:
            if in_table:
                processed.append("</table>")
                in_table = False
            if line.startswith("## "):
                processed.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                processed.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith("- **"):
                processed.append(f"<li>{line[2:]}</li>")
            else:
                processed.append(line)
    if in_table:
        processed.append("</table>")

    html_body = "\n".join(processed)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #0a0a0a; color: #e0e0e0; padding: 20px;
    line-height: 1.6;
  }}
  .header {{
    background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460);
    border: 1px solid #333; border-radius: 10px; padding: 30px;
    margin-bottom: 20px; text-align: center;
  }}
  .header h1 {{ color: #00d4ff; font-size: 2em; margin-bottom: 10px; }}
  .header .meta {{ color: #888; font-size: 0.9em; }}
  .section {{ background: #111; border: 1px solid #222; border-radius: 8px;
    padding: 20px; margin-bottom: 15px; }}
  h2 {{ color: #00d4ff; border-bottom: 2px solid #333; padding-bottom: 8px;
    margin: 20px 0 10px 0; }}
  h3 {{ color: #4ecdc4; margin: 15px 0 8px 0; }}
  pre {{ background: #1a1a1a; border: 1px solid #333; border-radius: 5px;
    padding: 15px; overflow-x: auto; font-family: 'Courier New', monospace;
    font-size: 0.85em; color: #b0b0b0; margin: 10px 0; }}
  .report-table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
  .report-table th {{ background: #1a1a2e; color: #00d4ff; padding: 10px;
    text-align: left; border: 1px solid #333; }}
  .report-table td {{ padding: 8px 10px; border: 1px solid #222; }}
  .report-table tr:nth-child(even) {{ background: #151515; }}
  li {{ margin-left: 20px; padding: 2px 0; }}
  .severity-critical {{ color: #ff4444; font-weight: bold; }}
  .severity-high {{ color: #ff8800; font-weight: bold; }}
  .severity-medium {{ color: #ffcc00; }}
  .severity-low {{ color: #44aaff; }}
  .severity-info {{ color: #888; }}
  .footer {{ text-align: center; color: #555; margin-top: 30px; padding: 20px;
    border-top: 1px solid #222; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="header">
  <h1>{title}</h1>
  <div class="meta">
    Generated: {now} | Host: {hostname}
  </div>
</div>
<div class="section">
{html_body}
</div>
<div class="footer">
  Generated by Hat Program - Red/Black/Blue Hat Cybersecurity Toolkit
</div>
</body>
</html>"""


def _build_text_report(title, content):
    """Build a plain text report."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = f"""{'=' * 70}
  {title}
  Generated: {now}
{'=' * 70}
"""
    # Strip HTML-ish tags
    text = content.replace("<pre>", "").replace("</pre>", "")
    text = text.replace("```", "")
    return header + text + f"\n{'=' * 70}\nGenerated by Hat Program\n"
