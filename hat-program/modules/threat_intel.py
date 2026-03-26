"""
Threat Intelligence Module - IP reputation, OSINT, threat feeds, and intelligence gathering.
Provides threat context for security operations.
"""

import datetime
import json

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


def threat_intel_menu():
    """Threat intelligence menu."""
    options = [
        "IP Reputation Lookup",
        "Domain Intelligence",
        "Email OSINT",
        "Username OSINT",
        "Threat Feed Check",
        "Geolocation Lookup",
        "Abuse Contact Lookup",
        "Dark Web Mention Check (Tor required)",
        "Social Media Footprint",
        "Data Breach Check (HIBP API)",
    ]

    while True:
        choice = display_menu("THREAT INTELLIGENCE", options, Colors.MAGENTA)
        if choice == 0:
            break
        elif choice == 1:
            ip_reputation()
        elif choice == 2:
            domain_intel()
        elif choice == 3:
            email_osint()
        elif choice == 4:
            username_osint()
        elif choice == 5:
            threat_feed_check()
        elif choice == 6:
            geolocation_lookup()
        elif choice == 7:
            abuse_contact_lookup()
        elif choice == 8:
            dark_web_check()
        elif choice == 9:
            social_media_footprint()
        elif choice == 10:
            breach_check()


def ip_reputation():
    """Check IP reputation across multiple sources."""
    print_section("IP Reputation Lookup")

    ip = get_user_input("Enter IP address")
    if not ip:
        print_error("No IP provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required for reputation lookups.")
        return

    # AbuseIPDB (free tier)
    print_section("IP Information")

    # WHOIS
    print_status("WHOIS lookup...")
    if check_tool("whois"):
        stdout, _, _ = run_command("whois {} 2>/dev/null | head -30".format(ip))
        if stdout:
            print_info("WHOIS Data:")
            print(stdout)

    # Reverse DNS
    print_status("Reverse DNS...")
    stdout, _, _ = run_command("dig +short -x {} 2>/dev/null".format(ip))
    if stdout:
        print_info("Reverse DNS: {}".format(stdout))
    else:
        print_info("No reverse DNS record found.")

    # Check against public blocklists via DNS
    print_section("Blocklist Checks (DNS-based)")
    reversed_ip = ".".join(ip.split(".")[::-1])

    blocklists = [
        ("zen.spamhaus.org", "Spamhaus"),
        ("bl.spamcop.net", "SpamCop"),
        ("dnsbl.sorbs.net", "SORBS"),
        ("b.barracudacentral.org", "Barracuda"),
    ]

    for bl_domain, bl_name in blocklists:
        query = "{}.{}".format(reversed_ip, bl_domain)
        stdout, _, rc = run_command("dig +short {} 2>/dev/null".format(query))
        if stdout and stdout.strip():
            print_error("  LISTED on {}: {}".format(bl_name, stdout.strip()))
        else:
            print_info("  Clean on {}".format(bl_name))

    # ipinfo.io (free tier)
    print_section("IP Geolocation & ASN")
    stdout, _, _ = run_command(
        "curl -s 'https://ipinfo.io/{}?token=' 2>/dev/null".format(ip),
        timeout=10,
    )
    if stdout:
        try:
            data = json.loads(stdout)
            for key in ["ip", "city", "region", "country", "org", "timezone"]:
                if key in data:
                    print_info("  {}: {}".format(key.capitalize(), data[key]))
        except json.JSONDecodeError:
            print_info(stdout)


def domain_intel():
    """Gather intelligence on a domain."""
    print_section("Domain Intelligence")

    domain = get_user_input("Enter domain (e.g., example.com)")
    if not domain:
        print_error("No domain provided.")
        return

    # DNS records
    print_section("DNS Records")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    for rtype in record_types:
        stdout, _, _ = run_command("dig +short {} {} 2>/dev/null".format(rtype, domain))
        if stdout:
            print_info("  {}: {}".format(rtype, stdout.replace("\n", ", ")))

    # WHOIS
    print_section("WHOIS Information")
    if check_tool("whois"):
        stdout, _, _ = run_command("whois {} 2>/dev/null | head -40".format(domain))
        if stdout:
            print(stdout)

    # Certificate transparency
    print_section("Certificate Transparency Logs")
    if check_tool("curl"):
        stdout, _, _ = run_command(
            "curl -s 'https://crt.sh/?q=%25.{}&output=json' 2>/dev/null | "
            "python3 -c \"import sys,json; "
            "data=json.load(sys.stdin); "
            "[print(e.get('name_value','')) for e in data[:20]]\" 2>/dev/null".format(domain),
            timeout=15,
        )
        if stdout:
            # Deduplicate
            names = sorted(set(stdout.strip().split("\n")))
            print_info("Certificates found ({} unique):".format(len(names)))
            for name in names[:20]:
                print("    {}".format(name))

    # Subdomain enumeration
    print_section("Common Subdomains")
    common_subs = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging",
        "vpn", "remote", "git", "jenkins", "monitor", "status",
    ]
    for sub in common_subs:
        fqdn = "{}.{}".format(sub, domain)
        stdout, _, _ = run_command("dig +short A {} 2>/dev/null".format(fqdn))
        if stdout:
            print_info("  {} -> {}".format(fqdn, stdout.replace("\n", ", ")))

    # HTTP headers
    print_section("Web Server Info")
    if check_tool("curl"):
        stdout, _, _ = run_command(
            "curl -s -I -L --max-time 10 https://{} 2>/dev/null | head -15".format(domain)
        )
        if stdout:
            print(stdout)


def email_osint():
    """Gather OSINT on an email address."""
    print_section("Email OSINT")

    email = get_user_input("Enter email address")
    if not email or "@" not in email:
        print_error("Invalid email address.")
        return

    domain = email.split("@")[1]

    # Check MX records
    print_section("Email Domain Analysis")
    stdout, _, _ = run_command("dig +short MX {} 2>/dev/null".format(domain))
    if stdout:
        print_info("MX Records: {}".format(stdout.replace("\n", ", ")))

    # SPF record
    stdout, _, _ = run_command("dig +short TXT {} 2>/dev/null | grep spf".format(domain))
    if stdout:
        print_info("SPF: {}".format(stdout))
    else:
        print_warning("No SPF record found (domain may be spoofable).")

    # DMARC
    stdout, _, _ = run_command("dig +short TXT _dmarc.{} 2>/dev/null".format(domain))
    if stdout:
        print_info("DMARC: {}".format(stdout))
    else:
        print_warning("No DMARC record found.")

    # DKIM (common selectors)
    print_section("DKIM Check")
    selectors = ["default", "google", "selector1", "selector2", "k1", "mail"]
    for sel in selectors:
        stdout, _, _ = run_command(
            "dig +short TXT {}._domainkey.{} 2>/dev/null".format(sel, domain)
        )
        if stdout:
            print_info("  DKIM selector '{}': Found".format(sel))

    print_section("OSINT Resources")
    print_info("Manual lookup resources:")
    print("    https://haveibeenpwned.com/account/{}".format(email))
    print("    https://hunter.io/email-verifier/{}".format(email))
    print("    https://emailrep.io/{}".format(email))


def username_osint():
    """Check username presence across platforms."""
    print_section("Username OSINT")

    username = get_user_input("Enter username to investigate")
    if not username:
        print_error("No username provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    # Check common platforms
    print_section("Platform Presence Check")
    platforms = [
        ("GitHub", "https://github.com/{}", 200),
        ("GitLab", "https://gitlab.com/{}", 200),
        ("Twitter/X", "https://x.com/{}", 200),
        ("Reddit", "https://www.reddit.com/user/{}", 200),
        ("Instagram", "https://www.instagram.com/{}/", 200),
        ("LinkedIn", "https://www.linkedin.com/in/{}/", 200),
        ("Pinterest", "https://www.pinterest.com/{}/", 200),
        ("Medium", "https://medium.com/@{}", 200),
        ("Keybase", "https://keybase.io/{}", 200),
        ("HackerOne", "https://hackerone.com/{}", 200),
    ]

    for platform, url_template, expected_code in platforms:
        url = url_template.format(username)
        stdout, _, _ = run_command(
            "curl -s -o /dev/null -w '%{{http_code}}' -L --max-time 8 '{}'".format(url),
            timeout=12,
        )
        if stdout and stdout.strip() == str(expected_code):
            print_warning("  {} - FOUND: {}".format(platform, url))
        elif stdout and stdout.strip() == "404":
            print_info("  {} - Not found".format(platform))
        else:
            print_status("  {} - Unknown (HTTP {})".format(platform, stdout.strip() if stdout else "timeout"))

    # Sherlock suggestion
    print_section("Advanced Tools")
    if check_tool("sherlock"):
        if confirm_action("Run Sherlock for comprehensive username search?"):
            stdout, _, _ = run_command("sherlock {} 2>&1 | head -40".format(username), timeout=60)
            if stdout:
                print(stdout)
    else:
        print_info("Install Sherlock for comprehensive search: pip3 install sherlock-project")


def threat_feed_check():
    """Check indicators against public threat feeds."""
    print_section("Threat Feed Check")

    indicator = get_user_input("Enter indicator (IP, domain, or hash)")
    if not indicator:
        print_error("No indicator provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    # VirusTotal (if API key available)
    print_section("Public Threat Intelligence")
    print_info("Check these resources manually:")
    print("    VirusTotal: https://www.virustotal.com/gui/search/{}".format(indicator))
    print("    OTX AlienVault: https://otx.alienvault.com/indicator/search/{}".format(indicator))
    print("    Shodan: https://www.shodan.io/search?query={}".format(indicator))
    print("    Censys: https://search.censys.io/search?q={}".format(indicator))
    print("    GreyNoise: https://viz.greynoise.io/ip/{}".format(indicator))
    print("    URLhaus: https://urlhaus.abuse.ch/browse.php?search={}".format(indicator))

    # ThreatFox API (free)
    print_section("ThreatFox IOC Lookup")
    stdout, _, _ = run_command(
        "curl -s -X POST 'https://threatfox-api.abuse.ch/api/v1/' "
        "-H 'Content-Type: application/json' "
        "-d '{{\"query\": \"search_ioc\", \"search_term\": \"{}\"}}' 2>/dev/null".format(indicator),
        timeout=10,
    )
    if stdout:
        try:
            data = json.loads(stdout)
            status = data.get("query_status", "")
            if status == "ok" and data.get("data"):
                print_warning("Found in ThreatFox!")
                for entry in data["data"][:5]:
                    print_error("  Type: {}, Malware: {}, Confidence: {}".format(
                        entry.get("ioc_type", "N/A"),
                        entry.get("malware_printable", "N/A"),
                        entry.get("confidence_level", "N/A"),
                    ))
            else:
                print_info("Not found in ThreatFox database.")
        except json.JSONDecodeError:
            print_status("Could not parse ThreatFox response.")

    # URLhaus check
    print_section("URLhaus Check")
    if "." in indicator:
        stdout, _, _ = run_command(
            "curl -s -X POST 'https://urlhaus-api.abuse.ch/v1/host/' "
            "-d 'host={}' 2>/dev/null".format(indicator),
            timeout=10,
        )
        if stdout:
            try:
                data = json.loads(stdout)
                if data.get("urls_online", 0) > 0:
                    print_error("  Active malicious URLs: {}".format(data["urls_online"]))
                else:
                    print_info("  No active malicious URLs found.")
            except json.JSONDecodeError:
                pass


def geolocation_lookup():
    """Look up IP geolocation information."""
    print_section("Geolocation Lookup")

    ip = get_user_input("Enter IP address")
    if not ip:
        print_error("No IP provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    # ip-api.com (free)
    print_status("Looking up geolocation...")
    stdout, _, _ = run_command(
        "curl -s 'http://ip-api.com/json/{}' 2>/dev/null".format(ip),
        timeout=10,
    )
    if stdout:
        try:
            data = json.loads(stdout)
            if data.get("status") == "success":
                fields = [
                    ("IP", "query"), ("Country", "country"), ("Region", "regionName"),
                    ("City", "city"), ("ZIP", "zip"), ("Latitude", "lat"),
                    ("Longitude", "lon"), ("Timezone", "timezone"),
                    ("ISP", "isp"), ("Organization", "org"), ("AS", "as"),
                ]
                for label, key in fields:
                    if key in data:
                        print_info("  {}: {}".format(label, data[key]))

                lat = data.get("lat", "")
                lon = data.get("lon", "")
                if lat and lon:
                    print_info("  Map: https://www.google.com/maps?q={},{}".format(lat, lon))
            else:
                print_error("Lookup failed: {}".format(data.get("message", "unknown error")))
        except json.JSONDecodeError:
            print_error("Could not parse response.")


def abuse_contact_lookup():
    """Look up abuse contact for an IP or domain."""
    print_section("Abuse Contact Lookup")

    target = get_user_input("Enter IP or domain")
    if not target:
        print_error("No target provided.")
        return

    # WHOIS abuse info
    if check_tool("whois"):
        print_status("Looking up abuse contacts...")
        stdout, _, _ = run_command(
            "whois {} 2>/dev/null | grep -i 'abuse'".format(target)
        )
        if stdout:
            print_info("Abuse contacts found:")
            print(stdout)
        else:
            print_warning("No abuse contact found in WHOIS data.")

    # Full WHOIS for network info
    if check_tool("whois"):
        stdout, _, _ = run_command(
            "whois {} 2>/dev/null | grep -iE '(OrgName|NetRange|CIDR|Country|abuse)'".format(target)
        )
        if stdout:
            print_section("Network Information")
            print(stdout)


def dark_web_check():
    """Check for dark web mentions (requires Tor)."""
    print_section("Dark Web Mention Check")
    print_warning("This feature requires Tor to be installed and running.")

    if not check_tool("tor"):
        print_error("Tor is not installed.")
        print_info("Install with: sudo apt install tor")
        return

    # Check if tor is running
    stdout, _, _ = run_command("systemctl is-active tor 2>/dev/null")
    if "active" not in stdout:
        print_warning("Tor service is not running.")
        print_info("Start with: sudo systemctl start tor")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    # Test tor connectivity
    print_status("Testing Tor connectivity...")
    stdout, _, _ = run_command(
        "curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null",
        timeout=30,
    )
    if stdout:
        print_info("Tor connection: {}".format(stdout))
    else:
        print_error("Could not connect through Tor.")

    print_info("For comprehensive dark web monitoring, consider:")
    print("    - Ahmia.fi (Tor search engine)")
    print("    - OnionScan (onion site scanner)")
    print("    - IntelligenceX (https://intelx.io)")


def social_media_footprint():
    """Analyze social media footprint for a person or organization."""
    print_section("Social Media Footprint Analysis")

    name = get_user_input("Enter person/organization name")
    if not name:
        print_error("No name provided.")
        return

    encoded = name.replace(" ", "+")

    print_section("Search Resources")
    print_info("Search across platforms:")
    print("    Google: https://www.google.com/search?q=\"{}\"".format(encoded))
    print("    Google Images: https://www.google.com/search?tbm=isch&q={}".format(encoded))
    print("    LinkedIn: https://www.linkedin.com/search/results/all/?keywords={}".format(encoded))
    print("    Twitter/X: https://x.com/search?q={}".format(encoded))
    print("    Facebook: https://www.facebook.com/search/top?q={}".format(encoded))
    print("    GitHub: https://github.com/search?q={}".format(encoded))
    print("    Reddit: https://www.reddit.com/search/?q={}".format(encoded))

    # Google dorking suggestions
    print_section("Google Dork Suggestions")
    dorks = [
        ('site:linkedin.com "{}"'.format(name), "LinkedIn profiles"),
        ('site:github.com "{}"'.format(name), "GitHub activity"),
        ('site:pastebin.com "{}"'.format(name), "Pastebin mentions"),
        ('"{}" filetype:pdf'.format(name), "PDF documents"),
        ('"{}" email OR contact'.format(name), "Contact info"),
    ]
    for dork, desc in dorks:
        print_info("  {} - {}".format(desc, dork))


def breach_check():
    """Check for data breaches using public resources."""
    print_section("Data Breach Check")

    email = get_user_input("Enter email address to check")
    if not email or "@" not in email:
        print_error("Invalid email address.")
        return

    print_section("Breach Check Resources")
    print_info("Check these resources:")
    print("    Have I Been Pwned: https://haveibeenpwned.com/account/{}".format(email))
    print("    DeHashed: https://dehashed.com/search?query={}".format(email))
    print("    LeakCheck: https://leakcheck.io/")
    print("    IntelligenceX: https://intelx.io/?s={}".format(email))

    domain = email.split("@")[1]
    print_section("Domain Breach Check")
    print_info("Check domain breaches:")
    print("    HIBP Domain: https://haveibeenpwned.com/DomainSearch/{}".format(domain))

    # Check if the domain has been in known breaches via DNS
    print_section("Domain Security Posture")
    stdout, _, _ = run_command("dig +short TXT _dmarc.{} 2>/dev/null".format(domain))
    if stdout:
        print_info("DMARC: {}".format(stdout))
    else:
        print_warning("No DMARC - domain may be vulnerable to email spoofing.")

    stdout, _, _ = run_command("dig +short TXT {} 2>/dev/null | grep spf".format(domain))
    if stdout:
        print_info("SPF: {}".format(stdout))
    else:
        print_warning("No SPF record found.")
