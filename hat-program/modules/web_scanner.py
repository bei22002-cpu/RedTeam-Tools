"""
Web Application Scanner Module - Directory brute force, technology fingerprinting,
XSS/SQLi detection, and web security assessment.
"""

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
    check_required_tools,
)


def web_scanner_menu():
    """Web application scanner menu."""
    options = [
        "Technology Fingerprinting",
        "Directory / Path Discovery",
        "Security Header Audit",
        "Cookie Security Analysis",
        "Form & Input Discovery",
        "JavaScript File Analysis",
        "Robots.txt & Sitemap Analysis",
        "WAF Detection",
        "CMS Detection",
        "Full Web Reconnaissance",
    ]

    while True:
        choice = display_menu("WEB APPLICATION SCANNER", options, Colors.RED)
        if choice == 0:
            break
        elif choice == 1:
            tech_fingerprint()
        elif choice == 2:
            directory_discovery()
        elif choice == 3:
            security_header_audit()
        elif choice == 4:
            cookie_analysis()
        elif choice == 5:
            form_discovery()
        elif choice == 6:
            js_analysis()
        elif choice == 7:
            robots_sitemap()
        elif choice == 8:
            waf_detection()
        elif choice == 9:
            cms_detection()
        elif choice == 10:
            full_web_recon()


def _ensure_url(url):
    """Ensure URL has a scheme."""
    if not url:
        return None
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip("/")


def tech_fingerprint():
    """Fingerprint web technologies used by a target."""
    print_section("Technology Fingerprinting")

    url = _ensure_url(get_user_input("Enter target URL"))
    if not url:
        print_error("No URL provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    # Get headers
    print_status("Analyzing HTTP headers...")
    stdout, _, _ = run_command(
        "curl -s -I -L --max-time 15 '{}' 2>/dev/null".format(url)
    )
    if not stdout:
        print_error("Could not connect to target.")
        return

    headers_lower = stdout.lower()
    print_section("Response Headers")
    print(stdout)

    # Detect technologies from headers
    print_section("Detected Technologies")
    tech_signatures = {
        "server: apache": "Apache HTTP Server",
        "server: nginx": "Nginx",
        "server: microsoft-iis": "Microsoft IIS",
        "server: cloudflare": "Cloudflare",
        "server: litespeed": "LiteSpeed",
        "x-powered-by: php": "PHP",
        "x-powered-by: asp.net": "ASP.NET",
        "x-powered-by: express": "Express.js (Node.js)",
        "x-powered-by: next.js": "Next.js",
        "x-generator: wordpress": "WordPress",
        "x-generator: drupal": "Drupal",
        "x-drupal": "Drupal",
        "x-shopify": "Shopify",
        "x-wix": "Wix",
        "x-vercel": "Vercel",
        "x-amz": "Amazon AWS",
        "cf-ray": "Cloudflare CDN",
        "x-cache": "CDN/Cache Layer",
        "x-varnish": "Varnish Cache",
        "x-fastly": "Fastly CDN",
    }

    detected = []
    for sig, tech in tech_signatures.items():
        if sig in headers_lower:
            detected.append(tech)
            print_info("  {} (from header)".format(tech))

    # Get page content for deeper analysis
    print_status("Analyzing page content...")
    stdout, _, _ = run_command(
        "curl -s -L --max-time 15 '{}' 2>/dev/null | head -500".format(url),
        timeout=20,
    )
    if stdout:
        content_lower = stdout.lower()

        content_signatures = {
            "wp-content": "WordPress",
            "wp-includes": "WordPress",
            "drupal.js": "Drupal",
            "joomla": "Joomla",
            "shopify.com": "Shopify",
            "react": "React.js",
            "vue.js": "Vue.js",
            "angular": "Angular",
            "jquery": "jQuery",
            "bootstrap": "Bootstrap",
            "tailwind": "Tailwind CSS",
            "font-awesome": "Font Awesome",
            "google-analytics": "Google Analytics",
            "gtag": "Google Tag Manager",
            "recaptcha": "Google reCAPTCHA",
        }

        for sig, tech in content_signatures.items():
            if sig in content_lower and tech not in detected:
                detected.append(tech)
                print_info("  {} (from content)".format(tech))

    if not detected:
        print_info("No specific technologies detected from headers/content.")

    # WhatWeb if available
    if check_tool("whatweb"):
        print_section("WhatWeb Analysis")
        stdout, _, _ = run_command("whatweb -a 3 {} 2>&1".format(url), timeout=30)
        if stdout:
            print(stdout)


def directory_discovery():
    """Discover hidden directories and files on a web server."""
    print_section("Directory / Path Discovery")

    url = _ensure_url(get_user_input("Enter target URL"))
    if not url:
        print_error("No URL provided.")
        return

    # Use gobuster/dirb/ffuf if available
    if check_tool("gobuster"):
        wordlist = get_user_input(
            "Wordlist path",
            "/usr/share/wordlists/dirb/common.txt",
        )
        print_status("Running gobuster...")
        stdout, _, _ = run_command(
            "gobuster dir -u {} -w {} -t 20 --no-error 2>&1 | head -50".format(url, wordlist),
            timeout=120,
        )
        if stdout:
            print(stdout)
        return

    if check_tool("dirb"):
        print_status("Running dirb...")
        stdout, _, _ = run_command(
            "dirb {} -S 2>&1 | head -50".format(url),
            timeout=120,
        )
        if stdout:
            print(stdout)
        return

    # Fallback: built-in path check
    if not check_tool("curl"):
        print_error("curl is required for fallback directory check.")
        return

    print_status("Using built-in path check (install gobuster/dirb for better results)...")

    common_paths = [
        "/admin", "/login", "/wp-admin", "/wp-login.php", "/administrator",
        "/phpmyadmin", "/cpanel", "/webmail", "/api", "/api/v1",
        "/swagger", "/docs", "/graphql", "/.git", "/.git/HEAD",
        "/.env", "/.htaccess", "/.htpasswd", "/backup", "/backups",
        "/config", "/configuration", "/database", "/db", "/debug",
        "/dump", "/info.php", "/phpinfo.php", "/server-status",
        "/server-info", "/status", "/health", "/metrics", "/console",
        "/shell", "/uploads", "/images", "/files", "/static",
        "/assets", "/js", "/css", "/fonts", "/media",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/favicon.ico", "/.well-known/security.txt",
    ]

    found = []
    for path in common_paths:
        full_url = url + path
        stdout, _, _ = run_command(
            "curl -s -o /dev/null -w '%{{http_code}} %{{size_download}}' --max-time 5 '{}'".format(full_url),
            timeout=8,
        )
        if stdout:
            parts = stdout.strip().split()
            code = parts[0] if parts else ""
            size = parts[1] if len(parts) > 1 else ""
            if code == "200":
                print_warning("  [200] {} ({} bytes)".format(path, size))
                found.append(path)
            elif code in ("301", "302"):
                print_info("  [{}] {} (redirect)".format(code, path))
            elif code == "403":
                print_status("  [403] {} (forbidden)".format(path))

    if found:
        print_section("Summary: {} paths found".format(len(found)))
    else:
        print_info("No accessible paths found with built-in wordlist.")


def security_header_audit():
    """Comprehensive security header audit."""
    print_section("Security Header Audit")

    url = _ensure_url(get_user_input("Enter target URL"))
    if not url:
        print_error("No URL provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    stdout, _, _ = run_command(
        "curl -s -I -L --max-time 15 '{}' 2>/dev/null".format(url)
    )
    if not stdout:
        print_error("Could not connect.")
        return

    headers_lower = stdout.lower()
    score = 0
    max_score = 0

    checks = [
        ("strict-transport-security", "HSTS", 15,
         "Forces HTTPS connections. Prevents downgrade attacks."),
        ("content-security-policy", "Content Security Policy", 15,
         "Prevents XSS and injection attacks by controlling resource loading."),
        ("x-frame-options", "X-Frame-Options", 10,
         "Prevents clickjacking by controlling iframe embedding."),
        ("x-content-type-options", "X-Content-Type-Options", 10,
         "Prevents MIME-type sniffing attacks."),
        ("referrer-policy", "Referrer-Policy", 10,
         "Controls how much referrer info is sent with requests."),
        ("permissions-policy", "Permissions-Policy", 10,
         "Controls browser feature access (camera, mic, geolocation, etc)."),
        ("x-xss-protection", "X-XSS-Protection", 5,
         "Legacy XSS filter (mostly superseded by CSP)."),
        ("cross-origin-opener-policy", "COOP", 5,
         "Isolates browsing context from cross-origin documents."),
        ("cross-origin-resource-policy", "CORP", 5,
         "Protects resources from being loaded by other origins."),
        ("cross-origin-embedder-policy", "COEP", 5,
         "Prevents loading cross-origin resources without permission."),
    ]

    negative_checks = [
        ("x-powered-by", "X-Powered-By", -5,
         "Leaks server technology. Remove this header."),
        ("server:", "Server (detailed)", -3,
         "Reveals server software. Minimize or remove."),
    ]

    print_section("Header Analysis")
    for header, name, points, desc in checks:
        max_score += points
        if header in headers_lower:
            score += points
            print_info("  [+{}] {} - Present".format(points, name))
        else:
            print_warning("  [+0] {} - MISSING".format(name))
            print("        {}".format(desc))

    for header, name, penalty, desc in negative_checks:
        if header in headers_lower:
            score += penalty
            print_error("  [{}] {} - EXPOSED".format(penalty, name))
            print("        {}".format(desc))

    # Score
    pct = (score / max_score * 100) if max_score > 0 else 0
    print_section("Security Header Score: {}/{} ({:.0f}%)".format(score, max_score, pct))

    if pct >= 80:
        print_info("Rating: GOOD")
    elif pct >= 50:
        print_warning("Rating: MODERATE - Several headers missing")
    else:
        print_error("Rating: POOR - Many security headers missing")


def cookie_analysis():
    """Analyze cookie security settings."""
    print_section("Cookie Security Analysis")

    url = _ensure_url(get_user_input("Enter target URL"))
    if not url:
        print_error("No URL provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    stdout, _, _ = run_command(
        "curl -s -I -L --max-time 15 -c - '{}' 2>/dev/null".format(url)
    )
    if not stdout:
        print_error("Could not connect.")
        return

    # Parse Set-Cookie headers
    stdout_headers, _, _ = run_command(
        "curl -s -D - -o /dev/null -L --max-time 15 '{}' 2>/dev/null | grep -i 'set-cookie'".format(url)
    )
    if not stdout_headers:
        print_info("No cookies set by the server.")
        return

    print_section("Cookie Analysis")
    cookies = stdout_headers.strip().split("\n")

    for cookie_line in cookies:
        cookie_lower = cookie_line.lower()
        name = cookie_line.split(":")[1].split("=")[0].strip() if "=" in cookie_line else "unknown"

        print_info("Cookie: {}".format(name))

        # Check flags
        if "secure" in cookie_lower:
            print_info("    Secure: Yes")
        else:
            print_warning("    Secure: NO - Cookie sent over HTTP")

        if "httponly" in cookie_lower:
            print_info("    HttpOnly: Yes")
        else:
            print_warning("    HttpOnly: NO - Accessible via JavaScript")

        if "samesite" in cookie_lower:
            if "samesite=strict" in cookie_lower:
                print_info("    SameSite: Strict")
            elif "samesite=lax" in cookie_lower:
                print_info("    SameSite: Lax")
            elif "samesite=none" in cookie_lower:
                print_warning("    SameSite: None (cross-site allowed)")
        else:
            print_warning("    SameSite: NOT SET")

        if "expires" in cookie_lower or "max-age" in cookie_lower:
            print_info("    Persistent: Yes (has expiry)")
        else:
            print_info("    Session: Yes (no expiry)")
        print()


def form_discovery():
    """Discover forms and input fields on a web page."""
    print_section("Form & Input Discovery")

    url = _ensure_url(get_user_input("Enter target URL"))
    if not url:
        print_error("No URL provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    print_status("Fetching page and analyzing forms...")
    stdout, _, _ = run_command(
        "curl -s -L --max-time 15 '{}' 2>/dev/null".format(url),
        timeout=20,
    )
    if not stdout:
        print_error("Could not fetch page.")
        return

    # Find forms
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
    action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
    method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
    name_pattern = re.compile(r'name=["\']([^"\']*)["\']', re.IGNORECASE)
    type_pattern = re.compile(r'type=["\']([^"\']*)["\']', re.IGNORECASE)

    forms = form_pattern.findall(stdout)
    if not forms:
        print_info("No forms found on the page.")
        return

    print_info("Found {} form(s)".format(len(forms)))

    for i, form_html in enumerate(forms, 1):
        # Get form attributes from surrounding context
        form_tag_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', stdout, re.IGNORECASE)
        action = ""
        if form_tag_match:
            action = form_tag_match.group(1)

        print_section("Form #{}".format(i))
        action_match = action_pattern.search(stdout.split(form_html)[0][-200:] if form_html in stdout else "")
        method_match = method_pattern.search(stdout.split(form_html)[0][-200:] if form_html in stdout else "")

        if action:
            print_info("  Action: {}".format(action))
        if method_match:
            print_info("  Method: {}".format(method_match.group(1)))

        inputs = input_pattern.findall(form_html)
        if inputs:
            print_info("  Inputs:")
            for inp in inputs:
                inp_name = name_pattern.search(inp)
                inp_type = type_pattern.search(inp)
                n = inp_name.group(1) if inp_name else "unnamed"
                t = inp_type.group(1) if inp_type else "text"
                print("    - {} (type: {})".format(n, t))

                # Flag interesting inputs
                if t == "password":
                    print_warning("      Password field detected")
                if t == "hidden":
                    print_status("      Hidden field - check value")


def js_analysis():
    """Analyze JavaScript files for sensitive information."""
    print_section("JavaScript File Analysis")

    url = _ensure_url(get_user_input("Enter target URL"))
    if not url:
        print_error("No URL provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    # Fetch page and extract JS URLs
    print_status("Fetching page and extracting JS references...")
    stdout, _, _ = run_command(
        "curl -s -L --max-time 15 '{}' 2>/dev/null".format(url),
        timeout=20,
    )
    if not stdout:
        print_error("Could not fetch page.")
        return

    # Find script sources
    js_pattern = re.compile(r'src=["\']([^"\']*\.js[^"\']*)["\']', re.IGNORECASE)
    js_files = js_pattern.findall(stdout)

    if not js_files:
        print_info("No external JavaScript files found.")
        return

    # Deduplicate
    js_files = list(set(js_files))
    print_info("Found {} JavaScript file(s)".format(len(js_files)))

    for js_url in js_files[:10]:
        # Make absolute URL
        if js_url.startswith("//"):
            js_url = "https:" + js_url
        elif js_url.startswith("/"):
            js_url = url + js_url
        elif not js_url.startswith("http"):
            js_url = url + "/" + js_url

        print_section("JS: {}".format(js_url[-60:]))

        # Fetch and analyze
        js_stdout, _, _ = run_command(
            "curl -s --max-time 10 '{}' 2>/dev/null | head -500".format(js_url),
            timeout=15,
        )
        if not js_stdout:
            continue

        # Check for sensitive patterns
        sensitive = [
            (r'api[_-]?key', "API Key reference"),
            (r'secret', "Secret reference"),
            (r'password', "Password reference"),
            (r'token', "Token reference"),
            (r'aws[_-]?access', "AWS credential reference"),
            (r'firebase', "Firebase configuration"),
            (r'googleapis\.com', "Google API endpoint"),
            (r'\.s3\.amazonaws\.com', "S3 bucket reference"),
            (r'mongodb://', "MongoDB connection string"),
            (r'mysql://', "MySQL connection string"),
        ]

        for pattern, desc in sensitive:
            matches = re.findall(pattern, js_stdout, re.IGNORECASE)
            if matches:
                print_warning("  {} ({} occurrences)".format(desc, len(matches)))


def robots_sitemap():
    """Analyze robots.txt and sitemap.xml."""
    print_section("Robots.txt & Sitemap Analysis")

    url = _ensure_url(get_user_input("Enter target URL"))
    if not url:
        print_error("No URL provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    # Robots.txt
    print_section("robots.txt")
    stdout, _, _ = run_command(
        "curl -s --max-time 10 '{}/robots.txt' 2>/dev/null".format(url),
        timeout=15,
    )
    if stdout and "<!doctype" not in stdout.lower()[:50]:
        print_info("robots.txt content:")
        print(stdout)

        # Look for interesting disallows
        for line in stdout.split("\n"):
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if any(kw in path.lower() for kw in ["admin", "login", "api", "private", "secret", "backup"]):
                    print_warning("  Interesting disallow: {}".format(path))
    else:
        print_info("No robots.txt found or returned HTML.")

    # Sitemap
    print_section("sitemap.xml")
    stdout, _, _ = run_command(
        "curl -s --max-time 10 '{}/sitemap.xml' 2>/dev/null | head -50".format(url),
        timeout=15,
    )
    if stdout and "<?xml" in stdout[:50]:
        # Count URLs
        url_count = stdout.count("<loc>")
        print_info("Sitemap found ({} URLs in first portion)".format(url_count))

        # Extract URLs
        loc_pattern = re.compile(r'<loc>(.*?)</loc>')
        urls = loc_pattern.findall(stdout)
        if urls:
            print_info("Sample URLs:")
            for u in urls[:15]:
                print("    {}".format(u))
    else:
        print_info("No sitemap.xml found.")

    # security.txt
    print_section("security.txt")
    for path in ["/.well-known/security.txt", "/security.txt"]:
        stdout, _, _ = run_command(
            "curl -s --max-time 10 '{}{}' 2>/dev/null".format(url, path),
            timeout=10,
        )
        if stdout and "contact:" in stdout.lower():
            print_info("security.txt found at {}:".format(path))
            print(stdout)
            break
    else:
        print_info("No security.txt found.")


def waf_detection():
    """Detect Web Application Firewall."""
    print_section("WAF Detection")

    url = _ensure_url(get_user_input("Enter target URL"))
    if not url:
        print_error("No URL provided.")
        return

    # wafw00f if available
    if check_tool("wafw00f"):
        print_status("Running wafw00f...")
        stdout, _, _ = run_command("wafw00f {} 2>&1".format(url), timeout=30)
        if stdout:
            print(stdout)
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    # Manual WAF detection
    print_status("Checking for WAF indicators...")

    # Normal request headers
    stdout, _, _ = run_command(
        "curl -s -I --max-time 10 '{}' 2>/dev/null".format(url)
    )
    if not stdout:
        print_error("Could not connect.")
        return

    headers_lower = stdout.lower()

    waf_indicators = {
        "cf-ray": "Cloudflare",
        "x-sucuri": "Sucuri",
        "x-cdn: imperva": "Imperva/Incapsula",
        "akamai": "Akamai",
        "x-fw-protection": "Generic WAF",
        "x-waf": "Generic WAF",
        "server: awselb": "AWS ELB",
        "x-amz-cf-id": "AWS CloudFront",
        "server: bigip": "F5 BIG-IP",
        "x-webknight": "WebKnight WAF",
        "x-dotdefender": "dotDefender",
    }

    detected = False
    for indicator, waf_name in waf_indicators.items():
        if indicator in headers_lower:
            print_warning("  WAF Detected: {} (indicator: {})".format(waf_name, indicator))
            detected = True

    if not detected:
        # Try a suspicious request to trigger WAF
        print_status("Sending test request to trigger WAF response...")
        stdout, _, _ = run_command(
            "curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 "
            "'{}/?test=<script>alert(1)</script>' 2>/dev/null".format(url)
        )
        if stdout and stdout.strip() in ("403", "406", "429", "503"):
            print_warning("  Possible WAF detected (blocked test request with HTTP {})".format(stdout.strip()))
        else:
            print_info("No WAF detected (note: absence of detection is not proof of absence).")


def cms_detection():
    """Detect Content Management System."""
    print_section("CMS Detection")

    url = _ensure_url(get_user_input("Enter target URL"))
    if not url:
        print_error("No URL provided.")
        return

    if not check_tool("curl"):
        print_error("curl is required.")
        return

    # WPScan for WordPress
    if check_tool("wpscan"):
        print_status("Running WPScan...")
        stdout, _, _ = run_command(
            "wpscan --url {} --no-banner --no-update 2>&1 | head -40".format(url),
            timeout=60,
        )
        if stdout:
            print(stdout)

    # Fetch page for analysis
    stdout, _, _ = run_command(
        "curl -s -L --max-time 15 '{}' 2>/dev/null".format(url),
        timeout=20,
    )
    if not stdout:
        print_error("Could not fetch page.")
        return

    content_lower = stdout.lower()

    # CMS signatures
    cms_checks = [
        ("wp-content", "WordPress", ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"]),
        ("drupal", "Drupal", ["/user/login", "/core/misc/drupal.js"]),
        ("joomla", "Joomla", ["/administrator/", "/media/jui/"]),
        ("magento", "Magento", ["/skin/frontend/", "/js/mage/"]),
        ("shopify", "Shopify", ["/admin"]),
        ("ghost", "Ghost CMS", ["/ghost/"]),
        ("typo3", "TYPO3", ["/typo3/"]),
        ("prestashop", "PrestaShop", ["/modules/ps_"]),
    ]

    detected = False
    for sig, name, extra_paths in cms_checks:
        if sig in content_lower:
            print_warning("  CMS Detected: {}".format(name))
            detected = True

            # Check extra paths
            for path in extra_paths:
                check_stdout, _, _ = run_command(
                    "curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 '{}{}'".format(url, path)
                )
                if check_stdout and check_stdout.strip() in ("200", "301", "302"):
                    print_info("    Found: {} (HTTP {})".format(path, check_stdout.strip()))
            break

    if not detected:
        print_info("No common CMS detected.")

    # Check meta generator tag
    gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']', stdout, re.IGNORECASE)
    if gen_match:
        print_info("  Generator meta tag: {}".format(gen_match.group(1)))


def full_web_recon():
    """Run a comprehensive web reconnaissance."""
    print_section("Full Web Reconnaissance")

    url = _ensure_url(get_user_input("Enter target URL"))
    if not url:
        print_error("No URL provided.")
        return

    if not confirm_action("Run full web recon on {}?".format(url)):
        return

    print_status("Starting full web reconnaissance...")
    print_warning("This will make many requests to the target.")

    # Technology fingerprinting
    print_section("[1/6] Technology Fingerprinting")
    if check_tool("curl"):
        stdout, _, _ = run_command(
            "curl -s -I -L --max-time 15 '{}' 2>/dev/null | grep -iE '(server|x-powered|x-generator)'".format(url)
        )
        if stdout:
            print(stdout)

    # Security headers
    print_section("[2/6] Security Headers")
    critical_headers = [
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options",
    ]
    stdout, _, _ = run_command(
        "curl -s -I -L --max-time 15 '{}' 2>/dev/null".format(url)
    )
    if stdout:
        for hdr in critical_headers:
            if hdr in stdout.lower():
                print_info("  {} - Present".format(hdr))
            else:
                print_warning("  {} - MISSING".format(hdr))

    # Robots/sitemap
    print_section("[3/6] robots.txt")
    stdout, _, _ = run_command(
        "curl -s --max-time 10 '{}/robots.txt' 2>/dev/null | head -20".format(url)
    )
    if stdout and "<!doctype" not in stdout.lower()[:50]:
        print(stdout[:500])
    else:
        print_info("No robots.txt found.")

    # Key paths
    print_section("[4/6] Key Path Check")
    key_paths = [
        "/.git/HEAD", "/.env", "/wp-admin/", "/admin/",
        "/api/", "/graphql", "/swagger", "/.well-known/security.txt",
    ]
    for path in key_paths:
        stdout, _, _ = run_command(
            "curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 '{}{}'".format(url, path)
        )
        if stdout and stdout.strip() in ("200", "301"):
            print_warning("  [{}] {}".format(stdout.strip(), path))

    # SSL check
    print_section("[5/6] SSL/TLS")
    if url.startswith("https"):
        domain = url.split("//")[1].split("/")[0]
        stdout, _, _ = run_command(
            "echo | openssl s_client -connect {}:443 -servername {} 2>/dev/null | "
            "openssl x509 -noout -subject -dates 2>/dev/null".format(domain, domain)
        )
        if stdout:
            print(stdout)

    # WAF detection
    print_section("[6/6] WAF Check")
    if check_tool("curl"):
        stdout, _, _ = run_command(
            "curl -s -I --max-time 10 '{}' 2>/dev/null | grep -iE '(cf-ray|x-sucuri|akamai|cloudflare)'".format(url)
        )
        if stdout:
            print_warning("WAF indicators found:")
            print(stdout)
        else:
            print_info("No obvious WAF detected.")

    print_section("Recon Complete")
