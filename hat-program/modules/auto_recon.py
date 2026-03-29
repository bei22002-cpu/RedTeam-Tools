"""
Auto-Reconnaissance Module - Automated full reconnaissance pipeline.
Runs multiple recon tools in sequence and compiles results.
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
    get_user_input,
    display_menu,
    confirm_action,
)


def auto_recon_menu():
    """Auto-reconnaissance menu."""
    options = [
        "Full Target Recon (domain/IP)",
        "Quick Passive Recon (no active scanning)",
        "Infrastructure Recon",
        "Person/Organization OSINT Recon",
        "Custom Recon Pipeline",
    ]

    while True:
        choice = display_menu("AUTO-RECONNAISSANCE", options, Colors.RED)
        if choice == 0:
            break
        elif choice == 1:
            full_target_recon()
        elif choice == 2:
            passive_recon()
        elif choice == 3:
            infrastructure_recon()
        elif choice == 4:
            person_osint_recon()
        elif choice == 5:
            custom_pipeline()


def full_target_recon():
    """Run comprehensive reconnaissance on a target."""
    print_section("Full Target Reconnaissance")

    target = get_user_input("Enter target (domain or IP)")
    if not target:
        print_error("No target specified.")
        return

    output_dir = get_user_input("Output directory", "/tmp/recon_{}".format(
        target.replace(".", "_").replace("/", "_")
    ))
    run_command("mkdir -p {}".format(output_dir))

    if not confirm_action("Run full recon on {}? This will make active connections.".format(target)):
        return

    results = {}
    total_steps = 10
    step = 0

    # 1. WHOIS
    step += 1
    print_status("[{}/{}] WHOIS lookup...".format(step, total_steps))
    if check_tool("whois"):
        stdout, _, _ = run_command("whois {} 2>/dev/null".format(target), timeout=15)
        if stdout:
            results["whois"] = stdout
            _save_result(output_dir, "01_whois.txt", stdout)
            print_info("  WHOIS data collected.")

    # 2. DNS Enumeration
    step += 1
    print_status("[{}/{}] DNS enumeration...".format(step, total_steps))
    dns_output = ""
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]:
        stdout, _, _ = run_command("dig +short {} {} 2>/dev/null".format(rtype, target))
        if stdout:
            dns_output += "{}: {}\n".format(rtype, stdout.strip())
    if dns_output:
        results["dns"] = dns_output
        _save_result(output_dir, "02_dns.txt", dns_output)
        print_info("  DNS records collected.")

    # 3. Reverse DNS
    step += 1
    print_status("[{}/{}] Reverse DNS...".format(step, total_steps))
    stdout, _, _ = run_command("dig +short -x {} 2>/dev/null".format(target))
    if stdout:
        results["rdns"] = stdout
        print_info("  Reverse DNS: {}".format(stdout.strip()))

    # 4. Subdomain enumeration
    step += 1
    print_status("[{}/{}] Subdomain enumeration...".format(step, total_steps))
    if not target[0].isdigit():
        subs_found = []
        common_subs = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "vpn", "remote", "git", "jenkins", "ci", "cd", "monitor", "status",
            "blog", "shop", "store", "app", "portal", "docs", "wiki", "support",
            "cdn", "static", "media", "img", "assets", "ns1", "ns2", "mx",
        ]
        for sub in common_subs:
            fqdn = "{}.{}".format(sub, target)
            stdout, _, _ = run_command("dig +short A {} 2>/dev/null".format(fqdn))
            if stdout:
                subs_found.append("{} -> {}".format(fqdn, stdout.strip()))

        # Also try crt.sh
        if check_tool("curl"):
            stdout, _, _ = run_command(
                "curl -s 'https://crt.sh/?q=%25.{}&output=json' 2>/dev/null | "
                "python3 -c \"import sys,json; "
                "data=json.load(sys.stdin); "
                "names=sorted(set(e.get('name_value','') for e in data)); "
                "[print(n) for n in names[:30]]\" 2>/dev/null".format(target),
                timeout=15,
            )
            if stdout:
                for line in stdout.strip().split("\n"):
                    entry = "{} (from crt.sh)".format(line.strip())
                    if entry not in subs_found:
                        subs_found.append(entry)

        if subs_found:
            sub_text = "\n".join(subs_found)
            results["subdomains"] = sub_text
            _save_result(output_dir, "04_subdomains.txt", sub_text)
            print_info("  Found {} subdomains.".format(len(subs_found)))

    # 5. Port Scan
    step += 1
    print_status("[{}/{}] Port scanning...".format(step, total_steps))
    if check_tool("nmap"):
        stdout, _, _ = run_command(
            "nmap -sV --top-ports 1000 -T4 {} 2>&1".format(target),
            timeout=180,
        )
    else:
        # Fallback: bash port scan
        stdout = ""
        common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        for port in common_ports:
            result, _, rc = run_command(
                "timeout 2 bash -c 'echo >/dev/tcp/{}/{} 2>/dev/null' && echo 'OPEN: {}'".format(
                    target, port, port
                )
            )
            if "OPEN" in result:
                stdout += "Port {} - OPEN\n".format(port)
    if stdout:
        results["ports"] = stdout
        _save_result(output_dir, "05_ports.txt", stdout)
        print_info("  Port scan complete.")

    # 6. HTTP Headers
    step += 1
    print_status("[{}/{}] HTTP header analysis...".format(step, total_steps))
    if check_tool("curl"):
        for scheme in ["https", "http"]:
            url = "{}://{}".format(scheme, target)
            stdout, _, _ = run_command(
                "curl -s -I -L --max-time 10 '{}' 2>/dev/null".format(url)
            )
            if stdout:
                results["http_headers_{}".format(scheme)] = stdout
                _save_result(output_dir, "06_http_{}.txt".format(scheme), stdout)
                print_info("  {} headers collected.".format(scheme.upper()))

    # 7. SSL/TLS
    step += 1
    print_status("[{}/{}] SSL/TLS analysis...".format(step, total_steps))
    if check_tool("openssl"):
        stdout, _, _ = run_command(
            "echo | openssl s_client -connect {}:443 -servername {} 2>/dev/null | "
            "openssl x509 -noout -text 2>/dev/null".format(target, target)
        )
        if stdout:
            results["ssl"] = stdout
            _save_result(output_dir, "07_ssl.txt", stdout)
            print_info("  SSL certificate analyzed.")

    # 8. Traceroute
    step += 1
    print_status("[{}/{}] Traceroute...".format(step, total_steps))
    stdout, _, _ = run_command(
        "traceroute -m 20 {} 2>/dev/null || tracepath {} 2>/dev/null".format(target, target),
        timeout=60,
    )
    if stdout:
        results["traceroute"] = stdout
        _save_result(output_dir, "08_traceroute.txt", stdout)
        print_info("  Traceroute complete.")

    # 9. Technology fingerprinting
    step += 1
    print_status("[{}/{}] Technology fingerprinting...".format(step, total_steps))
    if check_tool("curl"):
        stdout, _, _ = run_command(
            "curl -s -L --max-time 15 'https://{}' 2>/dev/null | head -300".format(target),
            timeout=20,
        )
        if stdout:
            techs = []
            tech_sigs = {
                "wp-content": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
                "react": "React", "vue": "Vue.js", "angular": "Angular",
                "jquery": "jQuery", "bootstrap": "Bootstrap",
                "nginx": "Nginx", "apache": "Apache",
            }
            for sig, tech in tech_sigs.items():
                if sig.lower() in stdout.lower():
                    techs.append(tech)
            if techs:
                tech_text = "Detected: " + ", ".join(techs)
                results["tech"] = tech_text
                _save_result(output_dir, "09_technology.txt", tech_text)
                print_info("  Technologies: {}".format(", ".join(techs)))

    # 10. Geolocation
    step += 1
    print_status("[{}/{}] Geolocation...".format(step, total_steps))
    if check_tool("curl"):
        stdout, _, _ = run_command(
            "curl -s 'http://ip-api.com/json/{}' 2>/dev/null".format(target),
            timeout=10,
        )
        if stdout:
            results["geo"] = stdout
            _save_result(output_dir, "10_geolocation.txt", stdout)
            print_info("  Geolocation data collected.")

    # Summary
    print_section("Recon Summary")
    print_info("Target: {}".format(target))
    print_info("Modules completed: {}".format(len(results)))
    print_info("Results saved to: {}".format(output_dir))

    # Generate summary file
    summary = "# Recon Summary for {}\n".format(target)
    summary += "Date: {}\n\n".format(datetime.datetime.now().isoformat())
    for key, val in results.items():
        summary += "## {}\n{}\n\n".format(key.upper(), val[:500])
    _save_result(output_dir, "00_SUMMARY.txt", summary)


def passive_recon():
    """Run passive reconnaissance (no active connections to target)."""
    print_section("Passive Reconnaissance")

    target = get_user_input("Enter target domain")
    if not target:
        print_error("No target specified.")
        return

    output_dir = get_user_input("Output directory", "/tmp/passive_recon")
    run_command("mkdir -p {}".format(output_dir))

    # DNS only (passive)
    print_status("DNS Records...")
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        stdout, _, _ = run_command("dig +short {} {} 2>/dev/null".format(rtype, target))
        if stdout:
            print_info("  {}: {}".format(rtype, stdout.strip().replace("\n", ", ")))

    # WHOIS
    print_status("WHOIS...")
    if check_tool("whois"):
        stdout, _, _ = run_command("whois {} 2>/dev/null | head -30".format(target))
        if stdout:
            print(stdout)

    # Certificate transparency
    print_status("Certificate Transparency (crt.sh)...")
    if check_tool("curl"):
        stdout, _, _ = run_command(
            "curl -s 'https://crt.sh/?q=%25.{}&output=json' 2>/dev/null | "
            "python3 -c \"import sys,json; "
            "data=json.load(sys.stdin); "
            "names=sorted(set(e.get('name_value','') for e in data)); "
            "[print(n) for n in names[:20]]\" 2>/dev/null".format(target),
            timeout=15,
        )
        if stdout:
            print_info("Subdomains from CT logs:")
            print(stdout)

    # Search engine resources
    print_section("OSINT Resources")
    print_info("Search resources:")
    encoded = target.replace(".", "%2E")
    print("    Google: https://www.google.com/search?q=site:{}".format(target))
    print("    Shodan: https://www.shodan.io/search?query={}".format(target))
    print("    Censys: https://search.censys.io/search?q={}".format(target))
    print("    SecurityTrails: https://securitytrails.com/domain/{}/dns".format(target))
    print("    DNSDumpster: https://dnsdumpster.com/ (manual)".format())
    print("    BuiltWith: https://builtwith.com/{}".format(target))


def infrastructure_recon():
    """Reconnaissance focused on infrastructure."""
    print_section("Infrastructure Reconnaissance")

    target = get_user_input("Enter target IP or CIDR range")
    if not target:
        print_error("No target specified.")
        return

    # Host discovery
    print_section("Host Discovery")
    if check_tool("nmap"):
        print_status("Running host discovery...")
        stdout, _, _ = run_command(
            "nmap -sn {} 2>&1".format(target), timeout=120
        )
        if stdout:
            print(stdout)
    else:
        print_status("Running ping sweep (nmap not available)...")
        if "/" not in target:
            stdout, _, _ = run_command("ping -c 2 -W 2 {} 2>&1".format(target))
            if stdout:
                print(stdout)

    # OS detection
    print_section("OS Detection")
    if check_tool("nmap"):
        print_status("Running OS fingerprinting...")
        stdout, _, _ = run_command(
            "nmap -O --top-ports 100 {} 2>&1".format(target), timeout=120
        )
        if stdout:
            print(stdout)
    else:
        # TTL-based fingerprint
        stdout, _, _ = run_command("ping -c 1 -W 3 {} 2>/dev/null".format(target))
        if stdout and "ttl=" in stdout.lower():
            import re
            ttl_match = re.search(r'ttl=(\d+)', stdout.lower())
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    print_info("TTL={} - Likely Linux/Unix".format(ttl))
                elif ttl <= 128:
                    print_info("TTL={} - Likely Windows".format(ttl))
                else:
                    print_info("TTL={} - Likely Network device".format(ttl))

    # Service enumeration
    print_section("Service Enumeration")
    if check_tool("nmap"):
        print_status("Running service detection...")
        stdout, _, _ = run_command(
            "nmap -sV --top-ports 200 {} 2>&1".format(target), timeout=180
        )
        if stdout:
            print(stdout)

    # Geolocation
    print_section("IP Geolocation")
    ip_target = target.split("/")[0]
    if check_tool("curl"):
        stdout, _, _ = run_command(
            "curl -s 'http://ip-api.com/json/{}' 2>/dev/null".format(ip_target),
            timeout=10,
        )
        if stdout:
            try:
                import json
                data = json.loads(stdout)
                for k in ["country", "regionName", "city", "isp", "org", "as"]:
                    if k in data:
                        print_info("  {}: {}".format(k, data[k]))
            except Exception:
                print(stdout)


def person_osint_recon():
    """OSINT reconnaissance on a person or organization."""
    print_section("Person/Organization OSINT Recon")

    name = get_user_input("Enter person or organization name")
    if not name:
        print_error("No name provided.")
        return

    encoded = name.replace(" ", "+")

    # Social media
    print_section("Social Media Search")
    platforms = [
        ("LinkedIn", "https://www.linkedin.com/search/results/all/?keywords={}"),
        ("Twitter/X", "https://x.com/search?q={}"),
        ("GitHub", "https://github.com/search?q={}&type=users"),
        ("Reddit", "https://www.reddit.com/search/?q={}"),
        ("Facebook", "https://www.facebook.com/search/top?q={}"),
    ]
    for platform, url_tmpl in platforms:
        print_info("  {}: {}".format(platform, url_tmpl.format(encoded)))

    # Google dorks
    print_section("Google Dork Queries")
    dorks = [
        ("\"{}\"".format(name), "Exact name match"),
        ("\"{}\" site:linkedin.com".format(name), "LinkedIn profiles"),
        ("\"{}\" site:github.com".format(name), "GitHub profiles"),
        ("\"{}\" filetype:pdf".format(name), "PDF documents"),
        ("\"{}\" email".format(name), "Email references"),
        ("\"{}\" phone OR tel".format(name), "Phone numbers"),
        ("\"{}\" resume OR CV".format(name), "Resumes"),
    ]
    for dork, desc in dorks:
        url = "https://www.google.com/search?q={}".format(dork.replace(" ", "+").replace("\"", "%22"))
        print_info("  {} - {}".format(desc, dork))

    # Email discovery
    print_section("Email Discovery Resources")
    print_info("  Hunter.io: https://hunter.io/search/{}".format(encoded))
    print_info("  Phonebook.cz: https://phonebook.cz/")
    print_info("  EmailHippo: https://tools.emailhippo.com/")


def custom_pipeline():
    """Build a custom recon pipeline."""
    print_section("Custom Recon Pipeline")

    target = get_user_input("Enter target")
    if not target:
        print_error("No target specified.")
        return

    modules = [
        ("WHOIS Lookup", "whois"),
        ("DNS Enumeration", "dns"),
        ("Port Scan (top 100)", "portscan"),
        ("HTTP Headers", "http"),
        ("SSL Certificate", "ssl"),
        ("Traceroute", "trace"),
        ("Geolocation", "geo"),
        ("Subdomain Enum", "subs"),
    ]

    print_info("Select modules to include:")
    selected = []
    for name, key in modules:
        if confirm_action("  Include {}?".format(name)):
            selected.append((name, key))

    if not selected:
        print_warning("No modules selected.")
        return

    output_dir = get_user_input("Output directory", "/tmp/custom_recon")
    run_command("mkdir -p {}".format(output_dir))

    print_status("Running {} selected modules...".format(len(selected)))

    for i, (name, key) in enumerate(selected, 1):
        print_status("[{}/{}] {}...".format(i, len(selected), name))

        if key == "whois" and check_tool("whois"):
            stdout, _, _ = run_command("whois {} 2>/dev/null".format(target), timeout=15)
            if stdout:
                _save_result(output_dir, "{}_whois.txt".format(i), stdout)
                print_info("  Done.")

        elif key == "dns":
            output = ""
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
                stdout, _, _ = run_command("dig +short {} {} 2>/dev/null".format(rtype, target))
                if stdout:
                    output += "{}: {}\n".format(rtype, stdout.strip())
            if output:
                _save_result(output_dir, "{}_dns.txt".format(i), output)
                print_info("  Done.")

        elif key == "portscan":
            if check_tool("nmap"):
                stdout, _, _ = run_command(
                    "nmap --top-ports 100 -T4 {} 2>&1".format(target), timeout=120
                )
            else:
                stdout = ""
                for port in [21, 22, 25, 53, 80, 443, 3306, 3389, 8080]:
                    r, _, rc = run_command(
                        "timeout 2 bash -c 'echo >/dev/tcp/{}/{}' 2>/dev/null && echo 'Port {} OPEN'".format(
                            target, port, port
                        )
                    )
                    if "OPEN" in r:
                        stdout += r + "\n"
            if stdout:
                _save_result(output_dir, "{}_ports.txt".format(i), stdout)
                print_info("  Done.")

        elif key == "http" and check_tool("curl"):
            stdout, _, _ = run_command(
                "curl -s -I -L --max-time 10 'https://{}' 2>/dev/null".format(target)
            )
            if stdout:
                _save_result(output_dir, "{}_http.txt".format(i), stdout)
                print_info("  Done.")

        elif key == "ssl" and check_tool("openssl"):
            stdout, _, _ = run_command(
                "echo | openssl s_client -connect {}:443 -servername {} 2>/dev/null | "
                "openssl x509 -noout -subject -issuer -dates 2>/dev/null".format(target, target)
            )
            if stdout:
                _save_result(output_dir, "{}_ssl.txt".format(i), stdout)
                print_info("  Done.")

        elif key == "trace":
            stdout, _, _ = run_command(
                "traceroute -m 15 {} 2>/dev/null || tracepath {} 2>/dev/null".format(target, target),
                timeout=45,
            )
            if stdout:
                _save_result(output_dir, "{}_traceroute.txt".format(i), stdout)
                print_info("  Done.")

        elif key == "geo" and check_tool("curl"):
            stdout, _, _ = run_command(
                "curl -s 'http://ip-api.com/json/{}' 2>/dev/null".format(target),
                timeout=10,
            )
            if stdout:
                _save_result(output_dir, "{}_geo.txt".format(i), stdout)
                print_info("  Done.")

        elif key == "subs" and not target[0].isdigit():
            subs = []
            for sub in ["www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn"]:
                fqdn = "{}.{}".format(sub, target)
                stdout, _, _ = run_command("dig +short A {} 2>/dev/null".format(fqdn))
                if stdout:
                    subs.append("{} -> {}".format(fqdn, stdout.strip()))
            if subs:
                _save_result(output_dir, "{}_subdomains.txt".format(i), "\n".join(subs))
                print_info("  Found {} subdomains.".format(len(subs)))

    print_section("Pipeline Complete")
    print_info("Results saved to: {}".format(output_dir))


def _save_result(output_dir, filename, content):
    """Save a result to file."""
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w") as f:
        f.write("# Generated: {}\n\n".format(datetime.datetime.now().isoformat()))
        f.write(content)
