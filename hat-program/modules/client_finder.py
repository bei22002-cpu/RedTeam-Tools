"""
Client Finder Module - Discover potential clients who could benefit from
cybersecurity services by identifying organizations with weak security postures.

Uses passive and non-intrusive techniques to identify businesses that may need:
- Web security hardening
- SSL/TLS configuration
- Security header implementation
- General cybersecurity consulting

IMPORTANT: All scanning is passive or minimally intrusive (HTTP HEAD/GET only).
Never perform unauthorized penetration testing or vulnerability exploitation.
"""

import csv
import datetime
import json
import os
import re

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


# Prospect data store for the session
_prospects = []


def client_finder_menu():
    """Client finder menu."""
    options = [
        "Scan Website Security Posture",
        "Bulk Domain Security Audit",
        "Find Businesses with Expired SSL Certs",
        "Find Businesses Missing Security Headers",
        "Local Business Discovery (by industry/location)",
        "Technology Stack Profiler",
        "Generate Prospect Report",
        "View Current Prospects",
        "Export Prospects to CSV",
        "Cold Outreach Email Generator",
    ]

    while True:
        choice = display_menu("CLIENT FINDER", options, Colors.YELLOW)
        if choice == 0:
            break
        elif choice == 1:
            scan_website_posture()
        elif choice == 2:
            bulk_domain_audit()
        elif choice == 3:
            find_expired_ssl()
        elif choice == 4:
            find_missing_headers()
        elif choice == 5:
            local_business_discovery()
        elif choice == 6:
            tech_stack_profiler()
        elif choice == 7:
            generate_prospect_report()
        elif choice == 8:
            view_prospects()
        elif choice == 9:
            export_prospects_csv()
        elif choice == 10:
            cold_outreach_generator()


def _add_prospect(domain, issues, score, details=None):
    """Add a prospect to the session list."""
    prospect = {
        "domain": domain,
        "issues": issues,
        "score": score,
        "details": details or {},
        "timestamp": datetime.datetime.now().isoformat(),
    }
    # Don't add duplicates
    for p in _prospects:
        if p["domain"] == domain:
            p.update(prospect)
            return
    _prospects.append(prospect)


def _assess_domain(domain):
    """Assess a single domain's security posture. Returns (score, issues, details)."""
    issues = []
    details = {}
    score = 100  # Start at 100, deduct for issues

    if not check_tool("curl"):
        return score, ["curl not available"], details

    # 1. Check SSL certificate
    print_status("  Checking SSL/TLS...")
    stdout, _, _ = run_command(
        "echo | openssl s_client -connect {}:443 -servername {} 2>/dev/null | "
        "openssl x509 -noout -dates -subject 2>/dev/null".format(domain, domain),
        timeout=10,
    )
    if stdout:
        details["ssl"] = "present"
        # Check expiry
        not_after_match = re.search(r'notAfter=(.*)', stdout)
        if not_after_match:
            expiry_str = not_after_match.group(1).strip()
            details["ssl_expiry"] = expiry_str
            try:
                # Parse the date - OpenSSL format: Mon DD HH:MM:SS YYYY GMT
                from email.utils import parsedate_to_datetime
                expiry = parsedate_to_datetime(expiry_str.replace("GMT", "+0000"))
                now = datetime.datetime.now(datetime.timezone.utc)
                days_left = (expiry - now).days
                details["ssl_days_left"] = days_left
                if days_left < 0:
                    issues.append("SSL certificate EXPIRED ({} days ago)".format(abs(days_left)))
                    score -= 30
                elif days_left < 30:
                    issues.append("SSL certificate expiring soon ({} days)".format(days_left))
                    score -= 15
            except Exception:
                pass
    else:
        # Try HTTP
        stdout_http, _, _ = run_command(
            "curl -s -o /dev/null -w '%{{http_code}}' --max-time 8 'http://{}' 2>/dev/null".format(domain),
            timeout=12,
        )
        if stdout_http and stdout_http.strip() in ("200", "301", "302"):
            issues.append("No SSL/TLS - site runs on HTTP only")
            score -= 25
            details["ssl"] = "missing"
        else:
            details["ssl"] = "unreachable"

    # 2. Check security headers
    print_status("  Checking security headers...")
    stdout, _, _ = run_command(
        "curl -s -I -L --max-time 10 'https://{}' 2>/dev/null || "
        "curl -s -I -L --max-time 10 'http://{}' 2>/dev/null".format(domain, domain),
        timeout=15,
    )
    if stdout:
        headers_lower = stdout.lower()
        details["reachable"] = True

        critical_headers = {
            "strict-transport-security": ("HSTS", 10),
            "content-security-policy": ("Content-Security-Policy", 10),
            "x-frame-options": ("X-Frame-Options", 5),
            "x-content-type-options": ("X-Content-Type-Options", 5),
            "referrer-policy": ("Referrer-Policy", 3),
            "permissions-policy": ("Permissions-Policy", 3),
        }

        missing_headers = []
        for header, (name, penalty) in critical_headers.items():
            if header not in headers_lower:
                missing_headers.append(name)
                score -= penalty

        if missing_headers:
            issues.append("Missing security headers: {}".format(", ".join(missing_headers)))
            details["missing_headers"] = missing_headers

        # Check for info leakage
        if "x-powered-by" in headers_lower:
            powered_match = re.search(r'x-powered-by:\s*(.*)', stdout, re.IGNORECASE)
            if powered_match:
                issues.append("Server technology exposed: {}".format(powered_match.group(1).strip()))
                score -= 3
                details["tech_exposed"] = powered_match.group(1).strip()

        # Extract server header
        server_match = re.search(r'^server:\s*(.*)', stdout, re.IGNORECASE | re.MULTILINE)
        if server_match:
            details["server"] = server_match.group(1).strip()

    else:
        details["reachable"] = False

    # 3. Check HTTPS redirect
    print_status("  Checking HTTPS redirect...")
    stdout, _, _ = run_command(
        "curl -s -o /dev/null -w '%{{http_code}} %{{redirect_url}}' --max-time 8 'http://{}' 2>/dev/null".format(domain),
        timeout=12,
    )
    if stdout:
        parts = stdout.strip().split()
        code = parts[0] if parts else ""
        redirect_url = parts[1] if len(parts) > 1 else ""
        if code in ("301", "302") and "https" in redirect_url:
            details["https_redirect"] = True
        elif code == "200":
            issues.append("HTTP does not redirect to HTTPS")
            score -= 8
            details["https_redirect"] = False

    # 4. Check DNS security (SPF/DMARC for email security)
    print_status("  Checking email security (SPF/DMARC)...")
    stdout, _, _ = run_command("dig +short TXT {} 2>/dev/null | grep spf".format(domain))
    if not stdout:
        issues.append("No SPF record - email spoofing possible")
        score -= 5
        details["spf"] = False
    else:
        details["spf"] = True

    stdout, _, _ = run_command("dig +short TXT _dmarc.{} 2>/dev/null".format(domain))
    if not stdout:
        issues.append("No DMARC record - email not authenticated")
        score -= 5
        details["dmarc"] = False
    else:
        details["dmarc"] = True

    # Clamp score
    score = max(0, min(100, score))

    return score, issues, details


def scan_website_posture():
    """Scan a single website's security posture for prospecting."""
    print_section("Website Security Posture Scan")
    print_info("This performs a passive, non-intrusive security assessment.")

    domain = get_user_input("Enter domain (e.g., example.com)")
    if not domain:
        print_error("No domain provided.")
        return

    # Clean domain
    domain = domain.replace("https://", "").replace("http://", "").strip("/")

    print_status("Scanning {}...".format(domain))
    score, issues, details = _assess_domain(domain)

    # Display results
    print_section("Security Posture: {}".format(domain))

    if score >= 80:
        print_info("  Score: {}/100 - GOOD (low prospect value)".format(score))
    elif score >= 50:
        print_warning("  Score: {}/100 - MODERATE (potential client)".format(score))
    else:
        print_error("  Score: {}/100 - POOR (high-value prospect)".format(score))

    if issues:
        print_section("Issues Found ({})".format(len(issues)))
        for issue in issues:
            print_warning("  - {}".format(issue))
    else:
        print_info("  No significant issues found.")

    if details.get("server"):
        print_info("  Server: {}".format(details["server"]))
    if details.get("ssl_days_left") is not None:
        print_info("  SSL expires in: {} days".format(details["ssl_days_left"]))

    # Offer to add as prospect
    if issues and score < 80:
        if confirm_action("Add {} as a prospect?".format(domain)):
            _add_prospect(domain, issues, score, details)
            print_info("Added to prospects list.")


def bulk_domain_audit():
    """Audit multiple domains at once."""
    print_section("Bulk Domain Security Audit")

    print_info("Enter domains one per line, or provide a file path.")
    print_info("Options:")
    print("  1. Enter domains manually")
    print("  2. Load from file (one domain per line)")

    choice = get_user_input("Choose option", "1")

    domains = []
    if choice == "2":
        filepath = get_user_input("File path")
        if filepath:
            try:
                with open(filepath, "r") as f:
                    domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except FileNotFoundError:
                print_error("File not found.")
                return
    else:
        print_info("Enter domains (one per line, empty line to finish):")
        while True:
            domain = get_user_input("Domain (or empty to finish)", "")
            if not domain:
                break
            domain = domain.replace("https://", "").replace("http://", "").strip("/")
            domains.append(domain)

    if not domains:
        print_error("No domains provided.")
        return

    print_status("Auditing {} domains...".format(len(domains)))
    results = []

    for i, domain in enumerate(domains, 1):
        print_section("[{}/{}] {}".format(i, len(domains), domain))
        score, issues, details = _assess_domain(domain)
        results.append((domain, score, issues, details))

        if score < 80 and issues:
            _add_prospect(domain, issues, score, details)

    # Summary
    print_section("Bulk Audit Summary")
    print_info("{:30s} {:>6s}  {}".format("Domain", "Score", "Top Issue"))
    print("-" * 70)

    results.sort(key=lambda x: x[1])  # Sort by score (worst first)
    for domain, score, issues, _ in results:
        top_issue = issues[0] if issues else "No issues"
        if score < 50:
            color = Colors.RED
        elif score < 80:
            color = Colors.YELLOW
        else:
            color = Colors.GREEN
        print("  {}{:30s}{} {:>4d}/100  {}".format(
            color, domain[:30], Colors.RESET, score, top_issue[:40]
        ))

    # Count prospects
    high_value = sum(1 for _, s, _, _ in results if s < 50)
    moderate = sum(1 for _, s, _, _ in results if 50 <= s < 80)
    print_section("Prospect Summary")
    print_error("  High-value prospects (score < 50): {}".format(high_value))
    print_warning("  Moderate prospects (score 50-79): {}".format(moderate))
    print_info("  Good security (score 80+): {}".format(
        sum(1 for _, s, _, _ in results if s >= 80)
    ))


def find_expired_ssl():
    """Find businesses with expired or expiring SSL certificates."""
    print_section("Find Businesses with SSL Issues")

    print_info("Enter domains to check for SSL certificate issues.")
    print_info("Enter domains one per line (empty line to finish):")

    domains = []
    while True:
        domain = get_user_input("Domain (or empty to finish)", "")
        if not domain:
            break
        domain = domain.replace("https://", "").replace("http://", "").strip("/")
        domains.append(domain)

    if not domains:
        print_error("No domains provided.")
        return

    print_status("Checking SSL certificates for {} domains...".format(len(domains)))
    ssl_issues = []

    for domain in domains:
        print_status("  Checking {}...".format(domain))
        stdout, _, _ = run_command(
            "echo | openssl s_client -connect {}:443 -servername {} 2>/dev/null | "
            "openssl x509 -noout -dates -subject 2>/dev/null".format(domain, domain),
            timeout=10,
        )
        if stdout:
            not_after_match = re.search(r'notAfter=(.*)', stdout)
            subject_match = re.search(r'subject.*CN\s*=\s*(.*)', stdout)
            cn = subject_match.group(1).strip() if subject_match else domain

            if not_after_match:
                expiry_str = not_after_match.group(1).strip()
                try:
                    from email.utils import parsedate_to_datetime
                    expiry = parsedate_to_datetime(expiry_str.replace("GMT", "+0000"))
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_left = (expiry - now).days

                    if days_left < 0:
                        ssl_issues.append((domain, cn, "EXPIRED", days_left))
                        print_error("  {} - EXPIRED ({} days ago)".format(domain, abs(days_left)))
                        _add_prospect(domain,
                                      ["SSL certificate expired {} days ago".format(abs(days_left))],
                                      20, {"ssl": "expired", "ssl_days_left": days_left})
                    elif days_left < 30:
                        ssl_issues.append((domain, cn, "EXPIRING SOON", days_left))
                        print_warning("  {} - Expiring in {} days".format(domain, days_left))
                        _add_prospect(domain,
                                      ["SSL certificate expiring in {} days".format(days_left)],
                                      50, {"ssl": "expiring", "ssl_days_left": days_left})
                    elif days_left < 90:
                        ssl_issues.append((domain, cn, "EXPIRING", days_left))
                        print_status("  {} - Expires in {} days".format(domain, days_left))
                    else:
                        print_info("  {} - Valid ({} days remaining)".format(domain, days_left))
                except Exception:
                    print_status("  {} - Could not parse expiry date".format(domain))
        else:
            ssl_issues.append((domain, domain, "NO SSL", 0))
            print_error("  {} - No SSL certificate found".format(domain))
            _add_prospect(domain, ["No SSL/TLS certificate"], 30, {"ssl": "missing"})

    if ssl_issues:
        print_section("SSL Issues Found: {}".format(len(ssl_issues)))
        for domain, cn, status, days in ssl_issues:
            print_warning("  {} ({}) - {}".format(domain, cn, status))


def find_missing_headers():
    """Find businesses missing critical security headers."""
    print_section("Find Businesses Missing Security Headers")

    print_info("Enter domains to check (empty line to finish):")
    domains = []
    while True:
        domain = get_user_input("Domain (or empty to finish)", "")
        if not domain:
            break
        domain = domain.replace("https://", "").replace("http://", "").strip("/")
        domains.append(domain)

    if not domains:
        print_error("No domains provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    critical_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
    ]

    print_status("Scanning {} domains for missing headers...".format(len(domains)))
    results = []

    for domain in domains:
        print_status("  Scanning {}...".format(domain))
        stdout, _, _ = run_command(
            "curl -s -I -L --max-time 10 'https://{}' 2>/dev/null || "
            "curl -s -I -L --max-time 10 'http://{}' 2>/dev/null".format(domain, domain),
            timeout=15,
        )
        if stdout:
            headers_lower = stdout.lower()
            missing = [h for h in critical_headers if h not in headers_lower]
            if missing:
                results.append((domain, missing))
                _add_prospect(
                    domain,
                    ["Missing headers: {}".format(", ".join(missing))],
                    max(30, 100 - len(missing) * 15),
                    {"missing_headers": missing},
                )

    if results:
        print_section("Domains Missing Critical Headers")
        for domain, missing in sorted(results, key=lambda x: -len(x[1])):
            print_warning("  {} - Missing {} header(s):".format(domain, len(missing)))
            for h in missing:
                print("    - {}".format(h))
    else:
        print_info("All scanned domains have critical headers in place.")


def local_business_discovery():
    """Help discover local businesses that might need cybersecurity services."""
    print_section("Local Business Discovery")

    print_info("This module helps you identify potential clients by industry and location.")
    print_info("It generates search queries and provides research strategies.")

    industry = get_user_input("Target industry (e.g., healthcare, legal, finance, retail)", "small business")
    location = get_user_input("Location (city, state, or region)", "")

    search_base = "{} {}".format(industry, location).strip()
    encoded = search_base.replace(" ", "+")

    print_section("Search Strategies for: {}".format(search_base))

    # Google search queries
    print_section("Google Search Queries")
    queries = [
        ('"{}" site:yelp.com'.format(search_base), "Find businesses on Yelp"),
        ('"{}" site:bbb.org'.format(search_base), "Better Business Bureau listings"),
        ('"{}" "contact" "email"'.format(search_base), "Find contact info"),
        ('"{}" inurl:http -inurl:https'.format(search_base), "HTTP-only sites (no SSL)"),
        ('"{}" site:chamberofcommerce.com'.format(search_base), "Chamber of Commerce"),
    ]
    for query, desc in queries:
        url = "https://www.google.com/search?q={}".format(query.replace(" ", "+").replace('"', "%22"))
        print_info("  {} - {}".format(desc, query))

    # Industry-specific tips
    print_section("Industry-Specific Prospecting Tips")
    industry_tips = {
        "healthcare": [
            "HIPAA compliance is mandatory - check if they mention it on their site",
            "Look for medical practices, dental offices, clinics, pharmacies",
            "Healthcare data breaches are expensive ($429/record avg cost)",
            "Check for patient portal security (login pages, form encryption)",
        ],
        "legal": [
            "Law firms handle extremely sensitive client data",
            "Attorney-client privilege requires strong data protection",
            "Check for client portals, document sharing systems",
            "Bar associations have ethics rules around data security",
        ],
        "finance": [
            "PCI-DSS compliance required for payment processing",
            "Check for online banking, payment pages, financial portals",
            "SOX compliance for publicly traded companies",
            "Insurance companies, credit unions, investment firms",
        ],
        "retail": [
            "PCI-DSS compliance for credit card processing",
            "E-commerce sites need strong checkout security",
            "Look for shopping carts, payment processing pages",
            "Customer data protection (CCPA/GDPR if applicable)",
        ],
        "education": [
            "FERPA compliance for student data protection",
            "Check school district and university websites",
            "Student portals and learning management systems",
            "Research data protection for universities",
        ],
    }

    matched = False
    for key, tips in industry_tips.items():
        if key in industry.lower():
            print_info("Tips for {} industry:".format(key))
            for tip in tips:
                print("    - {}".format(tip))
            matched = True
            break

    if not matched:
        print_info("General prospecting tips:")
        print("    - Look for businesses handling sensitive customer data")
        print("    - Check if they process payments online")
        print("    - Small businesses often lack dedicated IT security staff")
        print("    - Recently breached companies in the industry are receptive")

    # Outreach channels
    print_section("Outreach Channels")
    print_info("  LinkedIn: https://www.linkedin.com/search/results/companies/?keywords={}".format(encoded))
    print_info("  Google Maps: https://www.google.com/maps/search/{}".format(encoded))
    print_info("  Yelp: https://www.yelp.com/search?find_desc={}".format(encoded))
    print_info("  BBB: https://www.bbb.org/search?find_text={}".format(encoded))

    print_section("Lead Qualification Checklist")
    print_info("When you find a potential client, check:")
    print("    [ ] Do they have a website?")
    print("    [ ] Is the site using HTTPS?")
    print("    [ ] Do they handle sensitive data (PII, financial, health)?")
    print("    [ ] Do they have a privacy policy?")
    print("    [ ] Are they in a regulated industry?")
    print("    [ ] What is their approximate company size?")
    print("    [ ] Do they have existing IT staff/MSP?")


def tech_stack_profiler():
    """Profile a business's technology stack to tailor your pitch."""
    print_section("Technology Stack Profiler")

    domain = get_user_input("Enter domain")
    if not domain:
        print_error("No domain provided.")
        return

    domain = domain.replace("https://", "").replace("http://", "").strip("/")

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    print_status("Profiling technology stack for {}...".format(domain))

    tech = {
        "web_server": None,
        "language": None,
        "cms": None,
        "cdn": None,
        "analytics": [],
        "frameworks": [],
        "hosting": None,
    }

    # Headers analysis
    stdout, _, _ = run_command(
        "curl -s -I -L --max-time 10 'https://{}' 2>/dev/null || "
        "curl -s -I -L --max-time 10 'http://{}' 2>/dev/null".format(domain, domain),
        timeout=15,
    )
    if stdout:
        headers_lower = stdout.lower()

        # Web server
        server_match = re.search(r'^server:\s*(.*)', stdout, re.IGNORECASE | re.MULTILINE)
        if server_match:
            tech["web_server"] = server_match.group(1).strip()

        # Language
        powered_match = re.search(r'x-powered-by:\s*(.*)', stdout, re.IGNORECASE)
        if powered_match:
            tech["language"] = powered_match.group(1).strip()

        # CDN
        cdn_indicators = {
            "cf-ray": "Cloudflare",
            "x-amz-cf": "AWS CloudFront",
            "x-cache: hit from cloudfront": "AWS CloudFront",
            "x-fastly": "Fastly",
            "x-varnish": "Varnish/CDN",
            "akamai": "Akamai",
        }
        for indicator, cdn_name in cdn_indicators.items():
            if indicator in headers_lower:
                tech["cdn"] = cdn_name
                break

    # Content analysis
    stdout, _, _ = run_command(
        "curl -s -L --max-time 10 'https://{}' 2>/dev/null | head -500".format(domain),
        timeout=15,
    )
    if stdout:
        content_lower = stdout.lower()

        # CMS
        cms_sigs = {
            "wp-content": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
            "shopify": "Shopify",
            "squarespace": "Squarespace",
            "wix.com": "Wix",
            "weebly": "Weebly",
            "ghost": "Ghost",
        }
        for sig, name in cms_sigs.items():
            if sig in content_lower:
                tech["cms"] = name
                break

        # Frameworks
        fw_sigs = {
            "react": "React",
            "vue.js": "Vue.js",
            "angular": "Angular",
            "jquery": "jQuery",
            "bootstrap": "Bootstrap",
            "tailwind": "Tailwind CSS",
            "next.js": "Next.js",
        }
        for sig, name in fw_sigs.items():
            if sig in content_lower:
                tech["frameworks"].append(name)

        # Analytics
        analytics_sigs = {
            "google-analytics": "Google Analytics",
            "gtag": "Google Tag Manager",
            "facebook.com/tr": "Facebook Pixel",
            "hotjar": "Hotjar",
            "hubspot": "HubSpot",
        }
        for sig, name in analytics_sigs.items():
            if sig in content_lower:
                tech["analytics"].append(name)

    # Hosting (DNS check)
    stdout, _, _ = run_command("dig +short A {} 2>/dev/null".format(domain))
    if stdout:
        ip = stdout.strip().split("\n")[0]
        # Check hosting provider via reverse DNS / IP
        ip_stdout, _, _ = run_command(
            "curl -s 'http://ip-api.com/json/{}' 2>/dev/null".format(ip),
            timeout=10,
        )
        if ip_stdout:
            try:
                data = json.loads(ip_stdout)
                tech["hosting"] = data.get("org", data.get("isp", "Unknown"))
            except json.JSONDecodeError:
                pass

    # Display results
    print_section("Technology Profile: {}".format(domain))

    profile_items = [
        ("Web Server", tech["web_server"]),
        ("Language/Runtime", tech["language"]),
        ("CMS", tech["cms"]),
        ("CDN", tech["cdn"]),
        ("Hosting", tech["hosting"]),
        ("Frontend Frameworks", ", ".join(tech["frameworks"]) if tech["frameworks"] else None),
        ("Analytics/Marketing", ", ".join(tech["analytics"]) if tech["analytics"] else None),
    ]

    for label, value in profile_items:
        if value:
            print_info("  {:22s} {}".format(label + ":", value))

    # Sales angle suggestions
    print_section("Sales Angles Based on Stack")
    if tech["cms"] == "WordPress":
        print_info("  WordPress sites are frequent targets - offer plugin audits, WAF setup")
        print_info("  40% of the web runs WordPress, making it the #1 CMS target")
    if tech["cms"] in ("Shopify", "Wix", "Squarespace"):
        print_info("  Managed platform - focus on business email security, phishing training")
    if not tech["cdn"]:
        print_info("  No CDN detected - offer DDoS protection and performance consulting")
    if tech["language"] and "php" in tech["language"].lower():
        print_info("  PHP applications need regular security updates and code audits")
    if not tech["cms"]:
        print_info("  Custom-built site - likely needs custom security assessment")


def generate_prospect_report():
    """Generate a formatted report of all prospects found."""
    print_section("Prospect Report Generator")

    if not _prospects:
        print_warning("No prospects collected yet. Run scans first.")
        return

    output_dir = get_user_input("Output directory", "/tmp")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(output_dir, "prospect_report_{}.html".format(timestamp))
    text_path = os.path.join(output_dir, "prospect_report_{}.txt".format(timestamp))

    # Sort by score (worst first = best prospects)
    sorted_prospects = sorted(_prospects, key=lambda p: p["score"])

    # Generate HTML report
    html = """<!DOCTYPE html>
<html><head><title>Cybersecurity Prospect Report</title>
<style>
body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
h1 {{ color: #e94560; }}
h2 {{ color: #0f3460; background: #16213e; padding: 10px; border-radius: 5px; color: #eee; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
th {{ background: #0f3460; color: #eee; padding: 10px; text-align: left; }}
td {{ padding: 8px; border-bottom: 1px solid #333; }}
.high {{ color: #e94560; font-weight: bold; }}
.moderate {{ color: #f0a500; }}
.low {{ color: #4ecca3; }}
.issue {{ color: #f0a500; font-size: 0.9em; }}
.summary {{ background: #16213e; padding: 15px; border-radius: 5px; margin: 10px 0; }}
</style></head><body>
<h1>Cybersecurity Prospect Report</h1>
<p>Generated: {}</p>
<p>Total Prospects: {}</p>

<div class="summary">
<h3>Summary</h3>
<p><span class="high">High-Value (score &lt; 50):</span> {}</p>
<p><span class="moderate">Moderate (score 50-79):</span> {}</p>
</div>

<h2>Prospect Details</h2>
<table>
<tr><th>#</th><th>Domain</th><th>Score</th><th>Priority</th><th>Issues</th></tr>
""".format(
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        len(sorted_prospects),
        sum(1 for p in sorted_prospects if p["score"] < 50),
        sum(1 for p in sorted_prospects if 50 <= p["score"] < 80),
    )

    for i, p in enumerate(sorted_prospects, 1):
        if p["score"] < 50:
            priority_class = "high"
            priority = "HIGH"
        elif p["score"] < 80:
            priority_class = "moderate"
            priority = "MODERATE"
        else:
            priority_class = "low"
            priority = "LOW"

        issues_html = "<br>".join("- {}".format(iss) for iss in p["issues"])

        html += '<tr><td>{}</td><td><strong>{}</strong></td><td>{}/100</td>'.format(i, p["domain"], p["score"])
        html += '<td class="{}">{}</td>'.format(priority_class, priority)
        html += '<td class="issue">{}</td></tr>\n'.format(issues_html)

    html += """</table>
<h2>Recommended Actions</h2>
<ol>
<li>Prioritize HIGH-value prospects (score below 50)</li>
<li>Prepare customized pitches based on specific issues found</li>
<li>Research each prospect's industry for compliance requirements</li>
<li>Draft personalized outreach emails highlighting their specific vulnerabilities</li>
<li>Offer a free mini-assessment as a conversation starter</li>
</ol>
</body></html>"""

    with open(html_path, "w") as f:
        f.write(html)

    # Text report
    text_lines = [
        "CYBERSECURITY PROSPECT REPORT",
        "=" * 50,
        "Generated: {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")),
        "Total Prospects: {}".format(len(sorted_prospects)),
        "",
    ]
    for i, p in enumerate(sorted_prospects, 1):
        text_lines.append("{}. {} (Score: {}/100)".format(i, p["domain"], p["score"]))
        for issue in p["issues"]:
            text_lines.append("   - {}".format(issue))
        text_lines.append("")

    with open(text_path, "w") as f:
        f.write("\n".join(text_lines))

    print_info("HTML report: {}".format(html_path))
    print_info("Text report: {}".format(text_path))


def view_prospects():
    """View all collected prospects."""
    print_section("Current Prospects ({})".format(len(_prospects)))

    if not _prospects:
        print_warning("No prospects collected yet.")
        return

    sorted_prospects = sorted(_prospects, key=lambda p: p["score"])

    for i, p in enumerate(sorted_prospects, 1):
        if p["score"] < 50:
            color = Colors.RED
            label = "HIGH-VALUE"
        elif p["score"] < 80:
            color = Colors.YELLOW
            label = "MODERATE"
        else:
            color = Colors.GREEN
            label = "LOW"

        print("  {}{}. {:30s} Score: {:3d}/100  [{}]{}".format(
            color, i, p["domain"], p["score"], label, Colors.RESET
        ))
        for issue in p["issues"][:3]:
            print("     - {}".format(issue))
        print()


def export_prospects_csv():
    """Export prospects to CSV file."""
    print_section("Export Prospects to CSV")

    if not _prospects:
        print_warning("No prospects to export.")
        return

    output_dir = get_user_input("Output directory", "/tmp")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(output_dir, "prospects_{}.csv".format(timestamp))

    sorted_prospects = sorted(_prospects, key=lambda p: p["score"])

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Domain", "Score", "Priority", "Issues",
            "SSL Status", "Missing Headers", "Has SPF", "Has DMARC",
            "Server", "Scan Date",
        ])
        for p in sorted_prospects:
            priority = "HIGH" if p["score"] < 50 else "MODERATE" if p["score"] < 80 else "LOW"
            details = p.get("details", {})
            writer.writerow([
                p["domain"],
                p["score"],
                priority,
                "; ".join(p["issues"]),
                details.get("ssl", "unknown"),
                "; ".join(details.get("missing_headers", [])),
                "Yes" if details.get("spf") else "No",
                "Yes" if details.get("dmarc") else "No",
                details.get("server", ""),
                p["timestamp"],
            ])

    print_info("Exported {} prospects to: {}".format(len(sorted_prospects), csv_path))


def cold_outreach_generator():
    """Generate personalized cold outreach email templates based on findings."""
    print_section("Cold Outreach Email Generator")

    if not _prospects:
        print_warning("No prospects found yet. Run scans first to collect prospect data.")
        domain = get_user_input("Or enter a domain to generate a generic template", "")
        if domain:
            _generate_email_template(domain, [], {})
        return

    print_info("Select a prospect:")
    sorted_prospects = sorted(_prospects, key=lambda p: p["score"])
    for i, p in enumerate(sorted_prospects, 1):
        print("  {}. {} (Score: {}/100)".format(i, p["domain"], p["score"]))

    choice = get_user_input("Select prospect number", "1")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(sorted_prospects):
            p = sorted_prospects[idx]
            _generate_email_template(p["domain"], p["issues"], p.get("details", {}))
        else:
            print_error("Invalid selection.")
    except ValueError:
        print_error("Invalid input.")


def _generate_email_template(domain, issues, details):
    """Generate email templates based on specific findings."""
    company = get_user_input("Company name (or press enter for domain)", domain.split(".")[0].capitalize())
    your_name = get_user_input("Your name", "Security Consultant")
    your_company = get_user_input("Your company name", "")

    print_section("Email Template: Initial Outreach")

    # Build issue-specific paragraph
    issue_paragraph = ""
    if issues:
        issue_points = []
        for issue in issues[:3]:
            if "ssl" in issue.lower() or "https" in issue.lower():
                issue_points.append(
                    "Your website's SSL/TLS configuration could expose visitor data in transit"
                )
            elif "header" in issue.lower():
                issue_points.append(
                    "Some standard web security protections (security headers) "
                    "are not configured, which can leave your site vulnerable to common attacks"
                )
            elif "spf" in issue.lower() or "dmarc" in issue.lower():
                issue_points.append(
                    "Your email domain lacks authentication records, making it "
                    "possible for attackers to send emails that appear to come from your organization"
                )
            elif "expired" in issue.lower():
                issue_points.append(
                    "Your SSL certificate needs attention, which may be causing "
                    "browser warnings for your visitors"
                )
            else:
                issue_points.append(issue)

        issue_paragraph = "\n".join("  - {}".format(p) for p in issue_points)

    from_line = your_company if your_company else your_name

    template = """
Subject: Quick security observation about {domain}

Hi {company} Team,

My name is {name}{company_line}, and I specialize in helping businesses
like yours strengthen their online security posture.

I recently came across your website ({domain}) and noticed a few areas
where your security could be improved:

{issues}

These are common issues that many businesses face, and they can often be
resolved quickly. The good news is that addressing them can significantly
reduce your risk of data breaches, improve customer trust, and help with
compliance requirements.

I'd love to offer a complimentary 15-minute security review of your
website to walk you through the findings and discuss simple steps to
improve your protection.

Would you have time for a brief call this week?

Best regards,
{name}
{from_line}
""".format(
        domain=domain,
        company=company,
        name=your_name,
        company_line=" from {}".format(your_company) if your_company else "",
        issues=issue_paragraph if issue_paragraph else "  - Several common security configurations could be strengthened",
        from_line=from_line,
    )

    print(template)

    # Follow-up template
    print_section("Email Template: Follow-Up")
    followup = """
Subject: Re: Security review for {domain}

Hi {company} Team,

I wanted to follow up on my previous email about the security
observations I found on your website.

With cyber attacks increasing by over 30% year-over-year, businesses
in your industry are increasingly being targeted. A quick security
review could help identify and address vulnerabilities before they
become costly incidents.

I'm offering a free initial assessment with no obligation. It typically
takes about 15 minutes and provides actionable recommendations.

Would any day this week work for a quick chat?

Best regards,
{name}
""".format(domain=domain, company=company, name=your_name)

    print(followup)

    # Save templates
    if confirm_action("Save templates to file?"):
        output_dir = get_user_input("Output directory", "/tmp")
        filepath = os.path.join(output_dir, "outreach_{}.txt".format(
            domain.replace(".", "_")
        ))
        with open(filepath, "w") as f:
            f.write("=== INITIAL OUTREACH ===\n")
            f.write(template)
            f.write("\n\n=== FOLLOW-UP ===\n")
            f.write(followup)
        print_info("Templates saved to: {}".format(filepath))
