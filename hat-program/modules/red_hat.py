"""
Red Hat Module - Offensive Security / Penetration Testing Tools
Uses Linux networking and scanning utilities for reconnaissance and assessment.
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
    validate_ip,
    validate_port,
    display_menu,
    confirm_action,
    check_required_tools,
)


def red_hat_menu():
    """Main menu for Red Hat operations."""
    options = [
        "Network Discovery (ARP Scan)",
        "Port Scanner",
        "Service Banner Grabbing",
        "DNS Enumeration",
        "OS Fingerprinting (ping-based TTL)",
        "Traceroute Analysis",
        "WHOIS Lookup",
        "HTTP Header Inspection",
        "SSL/TLS Certificate Analysis",
        "Subdomain Enumeration (DNS brute force)",
        "Check Available Red Team Tools",
    ]

    while True:
        choice = display_menu("RED HAT - Offensive Security", options, Colors.RED)
        if choice == 0:
            break
        elif choice == 1:
            network_discovery()
        elif choice == 2:
            port_scanner()
        elif choice == 3:
            banner_grabbing()
        elif choice == 4:
            dns_enumeration()
        elif choice == 5:
            os_fingerprint()
        elif choice == 6:
            traceroute_analysis()
        elif choice == 7:
            whois_lookup()
        elif choice == 8:
            http_header_inspection()
        elif choice == 9:
            ssl_cert_analysis()
        elif choice == 10:
            subdomain_enum()
        elif choice == 11:
            check_red_tools()


def network_discovery():
    """Discover hosts on the local network using ARP or ping sweep."""
    print_section("Network Discovery")

    # Try multiple approaches
    target = get_user_input("Enter target network (e.g., 192.168.1.0/24)")
    if not target:
        print_error("No target specified.")
        return

    if check_tool("nmap"):
        print_status(f"Running nmap host discovery on {target}...")
        require_root("nmap ARP scan")
        stdout, stderr, rc = run_command(f"nmap -sn {target}", timeout=120)
        if rc == 0:
            print_info("Scan Results:")
            print(stdout)
        else:
            print_error(f"Scan failed: {stderr}")
    elif check_tool("arp-scan"):
        print_status(f"Running arp-scan on {target}...")
        require_root("arp-scan")
        stdout, stderr, rc = run_command(f"arp-scan {target}", timeout=120)
        if rc == 0:
            print_info("Scan Results:")
            print(stdout)
        else:
            print_error(f"Scan failed: {stderr}")
    else:
        print_warning("Neither nmap nor arp-scan found. Using ping sweep...")
        # Extract base IP from CIDR
        base_ip = target.split("/")[0]
        parts = base_ip.split(".")
        if len(parts) == 4:
            network = ".".join(parts[:3])
            print_status(f"Pinging {network}.1-254 ...")
            stdout, stderr, rc = run_command(
                f"for i in $(seq 1 254); do "
                f"(ping -c 1 -W 1 {network}.$i &>/dev/null && "
                f"echo \"Host {network}.$i is up\") & done; wait",
                timeout=120,
            )
            if stdout:
                print_info("Live hosts found:")
                print(stdout)
            else:
                print_warning("No hosts responded to ping.")
        else:
            print_error("Invalid network format.")


def port_scanner():
    """Scan ports on a target host."""
    print_section("Port Scanner")

    target = get_user_input("Enter target IP or hostname")
    if not target:
        print_error("No target specified.")
        return

    scan_type = get_user_input(
        "Scan type - (1) Common ports (2) Full scan (3) Custom range", "1"
    )

    if check_tool("nmap"):
        if scan_type == "1":
            cmd = f"nmap -sV --top-ports 100 {target}"
        elif scan_type == "2":
            cmd = f"nmap -sV -p- {target}"
            print_warning("Full port scan may take several minutes...")
        else:
            port_range = get_user_input("Enter port range (e.g., 1-1000)", "1-1000")
            cmd = f"nmap -sV -p {port_range} {target}"

        print_status(f"Scanning {target}...")
        stdout, stderr, rc = run_command(cmd, timeout=300)
        if rc == 0:
            print_info("Scan Results:")
            print(stdout)
        else:
            print_error(f"Scan failed: {stderr}")
    else:
        print_warning("nmap not found. Using bash-based port scanner...")
        port_range = get_user_input("Enter port range (e.g., 1-1000)", "1-1000")
        start, end = port_range.split("-")
        print_status(f"Scanning {target} ports {start}-{end}...")
        stdout, stderr, rc = run_command(
            f"for port in $(seq {start} {end}); do "
            f"(echo >/dev/tcp/{target}/$port 2>/dev/null && "
            f"echo \"Port $port is OPEN\") & done; wait",
            timeout=120,
        )
        if stdout:
            print_info("Open ports found:")
            print(stdout)
        else:
            print_warning("No open ports found in the specified range.")


def banner_grabbing():
    """Grab service banners from open ports."""
    print_section("Service Banner Grabbing")

    target = get_user_input("Enter target IP or hostname")
    port = get_user_input("Enter port number", "80")

    if not target:
        print_error("No target specified.")
        return

    if not validate_port(port):
        print_error("Invalid port number.")
        return

    print_status(f"Grabbing banner from {target}:{port}...")

    if check_tool("nc") or check_tool("ncat") or check_tool("netcat"):
        nc_cmd = "nc" if check_tool("nc") else ("ncat" if check_tool("ncat") else "netcat")
        stdout, stderr, rc = run_command(
            f"echo '' | {nc_cmd} -w 5 {target} {port}", timeout=15
        )
        if stdout:
            print_info("Banner received:")
            print(stdout)
        elif stderr:
            print_info("Response:")
            print(stderr)
        else:
            print_warning("No banner received.")
    else:
        # Fallback using /dev/tcp
        stdout, stderr, rc = run_command(
            f"exec 3<>/dev/tcp/{target}/{port} 2>/dev/null; "
            f"echo -e 'HEAD / HTTP/1.1\\r\\nHost: {target}\\r\\n\\r\\n' >&3; "
            f"timeout 5 cat <&3; exec 3>&-",
            timeout=15,
        )
        if stdout:
            print_info("Response:")
            print(stdout)
        else:
            print_warning("Could not grab banner.")


def dns_enumeration():
    """Enumerate DNS records for a domain."""
    print_section("DNS Enumeration")

    domain = get_user_input("Enter target domain (e.g., example.com)")
    if not domain:
        print_error("No domain specified.")
        return

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

    if check_tool("dig"):
        print_status(f"Enumerating DNS records for {domain}...")
        for rtype in record_types:
            stdout, stderr, rc = run_command(f"dig +short {rtype} {domain}")
            if stdout:
                print_info(f"{rtype} Records:")
                for line in stdout.split("\n"):
                    print(f"    {line}")
    elif check_tool("nslookup"):
        print_status(f"Looking up {domain}...")
        stdout, stderr, rc = run_command(f"nslookup -type=any {domain}")
        if rc == 0:
            print_info("DNS Records:")
            print(stdout)
        else:
            print_error(f"Lookup failed: {stderr}")
    elif check_tool("host"):
        print_status(f"Looking up {domain}...")
        stdout, stderr, rc = run_command(f"host -a {domain}")
        if rc == 0:
            print_info("DNS Records:")
            print(stdout)
        else:
            print_error(f"Lookup failed: {stderr}")
    else:
        print_error("No DNS tools found (dig, nslookup, host). Install dnsutils.")


def os_fingerprint():
    """Attempt to identify remote OS using TTL analysis."""
    print_section("OS Fingerprinting (TTL-based)")

    target = get_user_input("Enter target IP or hostname")
    if not target:
        print_error("No target specified.")
        return

    print_status(f"Pinging {target} to analyze TTL...")
    stdout, stderr, rc = run_command(f"ping -c 4 {target}", timeout=30)

    if rc == 0 and stdout:
        print_info("Ping output:")
        print(stdout)

        # Parse TTL
        for line in stdout.split("\n"):
            if "ttl=" in line.lower():
                ttl_start = line.lower().index("ttl=") + 4
                ttl_str = ""
                for ch in line[ttl_start:]:
                    if ch.isdigit():
                        ttl_str += ch
                    else:
                        break
                if ttl_str:
                    ttl = int(ttl_str)
                    print_section("TTL Analysis")
                    if ttl <= 64:
                        print_info(f"TTL={ttl} -> Likely Linux/Unix/macOS (default TTL=64)")
                    elif ttl <= 128:
                        print_info(f"TTL={ttl} -> Likely Windows (default TTL=128)")
                    elif ttl <= 255:
                        print_info(f"TTL={ttl} -> Likely Network Device/Solaris (default TTL=255)")
                    else:
                        print_info(f"TTL={ttl} -> Unknown OS")
                break
    else:
        print_error(f"Could not ping target: {stderr}")


def traceroute_analysis():
    """Perform traceroute to map network path."""
    print_section("Traceroute Analysis")

    target = get_user_input("Enter target IP or hostname")
    if not target:
        print_error("No target specified.")
        return

    if check_tool("traceroute"):
        print_status(f"Tracing route to {target}...")
        stdout, stderr, rc = run_command(f"traceroute -m 20 {target}", timeout=120)
        if rc == 0:
            print_info("Route:")
            print(stdout)
        else:
            print_error(f"Traceroute failed: {stderr}")
    elif check_tool("tracepath"):
        print_status(f"Tracing path to {target}...")
        stdout, stderr, rc = run_command(f"tracepath {target}", timeout=120)
        if rc == 0:
            print_info("Path:")
            print(stdout)
        else:
            print_error(f"Tracepath failed: {stderr}")
    else:
        print_warning("No traceroute tool found. Using ping with increasing TTL...")
        for ttl in range(1, 21):
            stdout, stderr, rc = run_command(
                f"ping -c 1 -t {ttl} -W 2 {target} 2>&1 | head -2"
            )
            if stdout:
                print(f"  Hop {ttl:2d}: {stdout.split(chr(10))[0]}")
            if "time=" in stdout:
                print_info(f"Reached {target} at hop {ttl}")
                break


def whois_lookup():
    """Perform WHOIS lookup on a domain or IP."""
    print_section("WHOIS Lookup")

    target = get_user_input("Enter domain or IP address")
    if not target:
        print_error("No target specified.")
        return

    if check_tool("whois"):
        print_status(f"Looking up WHOIS for {target}...")
        stdout, stderr, rc = run_command(f"whois {target}", timeout=30)
        if rc == 0:
            print_info("WHOIS Data:")
            print(stdout)
        else:
            print_error(f"WHOIS lookup failed: {stderr}")
    else:
        print_error("whois command not found. Install with: sudo apt install whois")


def http_header_inspection():
    """Inspect HTTP headers from a web server."""
    print_section("HTTP Header Inspection")

    url = get_user_input("Enter URL (e.g., https://example.com)")
    if not url:
        print_error("No URL specified.")
        return

    if not url.startswith("http"):
        url = "https://" + url

    if check_tool("curl"):
        print_status(f"Fetching headers from {url}...")
        stdout, stderr, rc = run_command(
            f"curl -s -I -L --max-time 10 {url}", timeout=20
        )
        if stdout:
            print_info("HTTP Headers:")
            print(stdout)

            # Security header analysis
            print_section("Security Header Analysis")
            headers_lower = stdout.lower()
            security_headers = {
                "strict-transport-security": "HSTS",
                "content-security-policy": "CSP",
                "x-frame-options": "X-Frame-Options",
                "x-content-type-options": "X-Content-Type-Options",
                "x-xss-protection": "X-XSS-Protection",
                "referrer-policy": "Referrer-Policy",
                "permissions-policy": "Permissions-Policy",
            }
            for header, name in security_headers.items():
                if header in headers_lower:
                    print_info(f"{name}: Present")
                else:
                    print_warning(f"{name}: MISSING")
        else:
            print_error(f"Failed to fetch headers: {stderr}")
    else:
        print_error("curl not found. Install with: sudo apt install curl")


def ssl_cert_analysis():
    """Analyze SSL/TLS certificate of a remote host."""
    print_section("SSL/TLS Certificate Analysis")

    host = get_user_input("Enter hostname (e.g., example.com)")
    port = get_user_input("Enter port", "443")

    if not host:
        print_error("No hostname specified.")
        return

    if check_tool("openssl"):
        print_status(f"Analyzing certificate for {host}:{port}...")
        stdout, stderr, rc = run_command(
            f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | "
            f"openssl x509 -noout -text 2>/dev/null | "
            f"head -30",
            timeout=15,
        )
        if stdout:
            print_info("Certificate Details:")
            print(stdout)

        # Check expiry
        stdout2, stderr2, rc2 = run_command(
            f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | "
            f"openssl x509 -noout -dates 2>/dev/null",
            timeout=15,
        )
        if stdout2:
            print_section("Certificate Validity")
            print(stdout2)
    else:
        print_error("openssl not found. Install with: sudo apt install openssl")


def subdomain_enum():
    """Enumerate subdomains using DNS brute force."""
    print_section("Subdomain Enumeration")

    domain = get_user_input("Enter target domain (e.g., example.com)")
    if not domain:
        print_error("No domain specified.")
        return

    common_subdomains = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
        "dns", "mx", "admin", "api", "dev", "staging", "test", "beta", "portal",
        "vpn", "remote", "ssh", "git", "gitlab", "jenkins", "ci", "cd",
        "monitor", "grafana", "kibana", "elastic", "log", "logs", "db",
        "database", "mysql", "postgres", "redis", "cache", "cdn", "static",
        "assets", "media", "images", "img", "files", "docs", "wiki", "blog",
        "shop", "store", "app", "mobile", "m", "status", "health",
    ]

    print_status(f"Checking {len(common_subdomains)} common subdomains for {domain}...")
    found = []

    for sub in common_subdomains:
        fqdn = f"{sub}.{domain}"
        stdout, stderr, rc = run_command(f"dig +short A {fqdn}", timeout=5)
        if stdout and "NXDOMAIN" not in stderr:
            found.append((fqdn, stdout.replace("\n", ", ")))
            print_info(f"Found: {fqdn} -> {stdout.replace(chr(10), ', ')}")

    print_section("Summary")
    if found:
        print_info(f"Found {len(found)} subdomains:")
        for fqdn, ips in found:
            print(f"    {fqdn:40s} {ips}")
    else:
        print_warning("No subdomains found with common names.")


def check_red_tools():
    """Check availability of common red team tools."""
    print_section("Red Team Tool Availability Check")

    tools = [
        "nmap", "masscan", "nikto", "dirb", "gobuster", "sqlmap",
        "hydra", "john", "hashcat", "metasploit", "msfconsole",
        "burpsuite", "wireshark", "tcpdump", "responder",
        "enum4linux", "smbclient", "rpcclient", "crackmapexec",
        "evil-winrm", "impacket-secretsdump", "bloodhound",
        "nc", "ncat", "socat", "curl", "wget", "dig", "whois",
        "openssl", "ssh", "sshpass", "arp-scan", "netdiscover",
    ]

    check_required_tools(tools)
