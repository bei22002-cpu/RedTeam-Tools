"""
Bluetooth Scanner Module - Advanced Bluetooth & BLE Security Assessment
Supports classic Bluetooth, BLE, OBEX, RFCOMM, and device fingerprinting.
"""

import os
import time
from modules.utils import (
    run_command, check_tool, check_root, require_root,
    print_info, print_warning, print_error, print_status,
    print_section, print_banner, get_user_input, confirm_action,
    display_menu, Colors
)


def bluetooth_scanner():
    """Bluetooth & BLE Security Scanner."""
    while True:
        choice = display_menu("Bluetooth & BLE Scanner", [
            "Scan for classic Bluetooth devices",
            "Scan for BLE (Low Energy) devices",
            "Device information lookup",
            "Bluetooth service enumeration (SDP)",
            "RFCOMM channel scanner",
            "OBEX file browser",
            "Bluetooth signal strength monitor",
            "L2CAP ping (l2ping)",
            "Bluetooth interface info",
            "Check available Bluetooth tools",
        ], Colors.MAGENTA)
        if choice == 0: break
        elif choice == 1: _scan_classic()
        elif choice == 2: _scan_ble()
        elif choice == 3: _device_info()
        elif choice == 4: _sdp_enum()
        elif choice == 5: _rfcomm_scan()
        elif choice == 6: _obex_browse()
        elif choice == 7: _signal_monitor()
        elif choice == 8: _l2ping()
        elif choice == 9: _bt_interface_info()
        elif choice == 10: _check_bt_tools()


def _scan_classic():
    """Scan for classic Bluetooth devices."""
    if not check_tool("hcitool"):
        print_error("hcitool required. Install: sudo apt install bluez")
        return
    require_root("Bluetooth scanning")
    duration = get_user_input("Scan duration (seconds)", "10")
    print_status("Scanning for classic Bluetooth devices...")
    stdout, stderr, rc = run_command("hcitool scan --flush 2>&1", timeout=int(duration) + 5)
    if stdout:
        lines = stdout.strip().split("\n")
        print_section("Discovered Devices")
        devices = []
        for line in lines:
            if "\t" in line:
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    addr, name = parts[0], parts[1] if len(parts) > 1 else "Unknown"
                    devices.append((addr, name))
                    print_info("  %s  %s" % (addr, name))
        if not devices:
            print_info("No devices found. Make sure Bluetooth adapter is enabled.")
        else:
            print_info("Found %d device(s)" % len(devices))
            if confirm_action("Enumerate services for discovered devices?"):
                for addr, name in devices:
                    print_section("Services for %s (%s)" % (name, addr))
                    sout, _, _ = run_command("sdptool browse %s 2>&1 | head -50" % addr, timeout=15)
                    if sout: print(sout)
    else:
        print_error("Scan failed: %s" % (stderr or "No output"))
    # Also try bluetoothctl as fallback
    if check_tool("bluetoothctl"):
        print_section("Bluetoothctl Scan (5 seconds)")
        stdout, _, _ = run_command("timeout 5 bluetoothctl scan on 2>&1 & sleep 5 && bluetoothctl devices 2>&1", timeout=10)
        if stdout: print(stdout)


def _scan_ble():
    """Scan for BLE (Bluetooth Low Energy) devices."""
    if not check_tool("hcitool"):
        print_error("hcitool required. Install: sudo apt install bluez")
        return
    require_root("BLE scanning")
    duration = get_user_input("Scan duration (seconds)", "10")
    try:
        dur = int(duration)
    except ValueError:
        dur = 10
    print_status("Scanning for BLE devices (%ds)..." % dur)
    # Use hcitool lescan with timeout
    stdout, stderr, _ = run_command("timeout %d hcitool lescan 2>&1" % dur, timeout=dur + 5)
    if stdout:
        print_section("BLE Devices Discovered")
        seen = set()
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if line and "LE Scan" not in line and line not in seen:
                seen.add(line)
                print_info("  %s" % line)
        print_info("Found %d unique BLE device(s)" % len(seen))
    else:
        print_error("BLE scan failed: %s" % (stderr or "No BLE devices found"))
    # Also try btmgmt for newer systems
    if check_tool("btmgmt"):
        print_section("BLE via btmgmt")
        stdout, _, _ = run_command("timeout %d btmgmt find -l 2>&1" % dur, timeout=dur + 5)
        if stdout: print(stdout[:2000])


def _device_info():
    """Get detailed information about a Bluetooth device."""
    addr = get_user_input("Bluetooth MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    if not addr:
        return
    print_section("Device Info: %s" % addr)
    if check_tool("hcitool"):
        print_status("Getting device name...")
        stdout, _, _ = run_command("hcitool name %s 2>&1" % addr, timeout=10)
        if stdout: print_info("Name: %s" % stdout.strip())
        print_status("Getting device info...")
        stdout, _, _ = run_command("hcitool info %s 2>&1" % addr, timeout=10)
        if stdout: print(stdout)
        print_status("Getting clock offset...")
        stdout, _, _ = run_command("hcitool clock %s 2>&1" % addr, timeout=10)
        if stdout: print(stdout)
    if check_tool("sdptool"):
        print_section("SDP Services")
        stdout, _, _ = run_command("sdptool browse %s 2>&1" % addr, timeout=15)
        if stdout: print(stdout[:3000])
    # OUI lookup for manufacturer
    oui = addr.replace(":", "")[:6].upper()
    print_info("OUI prefix: %s" % oui)
    stdout, _, _ = run_command("curl -s 'https://api.macvendors.com/%s' 2>&1" % addr, timeout=5)
    if stdout and "errors" not in stdout.lower():
        print_info("Manufacturer: %s" % stdout.strip())


def _sdp_enum():
    """Enumerate Bluetooth services via SDP."""
    if not check_tool("sdptool"):
        print_error("sdptool required. Install: sudo apt install bluez")
        return
    addr = get_user_input("Target Bluetooth MAC (or 'local' for this device)", "local")
    if addr == "local":
        print_status("Browsing local SDP services...")
        stdout, _, _ = run_command("sdptool browse local 2>&1", timeout=15)
    else:
        print_status("Browsing SDP services on %s..." % addr)
        stdout, _, _ = run_command("sdptool browse %s 2>&1" % addr, timeout=20)
    if stdout:
        print_section("SDP Service Records")
        print(stdout[:5000])
        # Count services
        count = stdout.count("Service Name:")
        print_info("Total services found: %d" % count)
    else:
        print_error("No SDP services found or device unreachable.")


def _rfcomm_scan():
    """Scan RFCOMM channels on a Bluetooth device."""
    if not check_tool("rfcomm"):
        print_error("rfcomm required. Install: sudo apt install bluez")
        return
    require_root("RFCOMM scanning")
    addr = get_user_input("Target Bluetooth MAC address")
    if not addr:
        return
    print_status("Scanning RFCOMM channels on %s..." % addr)
    print_section("RFCOMM Channel Scan")
    open_channels = []
    for channel in range(1, 31):
        stdout, stderr, rc = run_command(
            "timeout 3 rfcomm connect /dev/rfcomm0 %s %d 2>&1" % (addr, channel), timeout=5)
        output = stdout + stderr
        if "Connection refused" not in output and "error" not in output.lower():
            print_info("  Channel %d: OPEN" % channel)
            open_channels.append(channel)
        else:
            print_status("  Channel %d: closed" % channel)
        run_command("rfcomm release /dev/rfcomm0 2>/dev/null", timeout=2)
    print_info("Open RFCOMM channels: %s" % (open_channels if open_channels else "None found"))


def _obex_browse():
    """Browse files via OBEX on a Bluetooth device."""
    if not check_tool("obexftp"):
        print_error("obexftp required. Install: sudo apt install obexftp")
        return
    addr = get_user_input("Target Bluetooth MAC address")
    if not addr:
        return
    channel = get_user_input("OBEX channel", "10")
    print_status("Browsing OBEX filesystem on %s channel %s..." % (addr, channel))
    stdout, stderr, _ = run_command(
        "obexftp -b %s -B %s -l / 2>&1" % (addr, channel), timeout=15)
    if stdout:
        print_section("OBEX File Listing")
        print(stdout[:3000])
    else:
        print_error("OBEX browse failed: %s" % (stderr or "Connection refused"))


def _signal_monitor():
    """Monitor Bluetooth signal strength (RSSI)."""
    if not check_tool("hcitool"):
        print_error("hcitool required.")
        return
    require_root("RSSI monitoring")
    addr = get_user_input("Target Bluetooth MAC address")
    if not addr:
        return
    duration = get_user_input("Monitor duration (seconds)", "10")
    try:
        dur = int(duration)
    except ValueError:
        dur = 10
    print_status("Monitoring RSSI for %s (%ds)..." % (addr, dur))
    print_section("Signal Strength Monitor")
    for i in range(dur):
        stdout, _, _ = run_command("hcitool rssi %s 2>&1" % addr, timeout=3)
        if stdout and "RSSI" in stdout:
            rssi = stdout.strip()
            bar_val = min(max(int(rssi.split()[-1]) + 100, 0), 50)
            bar = "#" * bar_val + "." * (50 - bar_val)
            print_info("  [%s] %s" % (bar, rssi))
        else:
            print_status("  No RSSI data (device may not be connected)")
        time.sleep(1)
    print_info("Monitoring complete.")


def _l2ping():
    """L2CAP ping to test Bluetooth connectivity."""
    if not check_tool("l2ping"):
        print_error("l2ping required. Install: sudo apt install bluez")
        return
    require_root("l2ping")
    addr = get_user_input("Target Bluetooth MAC address")
    if not addr:
        return
    count = get_user_input("Ping count", "5")
    size = get_user_input("Packet size (bytes)", "44")
    print_status("L2CAP ping %s (count=%s, size=%s)..." % (addr, count, size))
    stdout, stderr, _ = run_command(
        "l2ping -c %s -s %s %s 2>&1" % (count, size, addr), timeout=30)
    output = stdout if stdout else stderr
    if output:
        print(output)
    else:
        print_error("l2ping failed - device may be out of range.")


def _bt_interface_info():
    """Show Bluetooth interface information."""
    print_section("Bluetooth Interface Info")
    if check_tool("hciconfig"):
        stdout, _, _ = run_command("hciconfig -a 2>&1")
        if stdout:
            print(stdout)
        else:
            print_error("No Bluetooth interfaces found.")
    if check_tool("bluetoothctl"):
        print_section("Bluetoothctl Status")
        stdout, _, _ = run_command("bluetoothctl show 2>&1", timeout=5)
        if stdout: print(stdout)
    if check_tool("rfkill"):
        print_section("RF Kill Status")
        stdout, _, _ = run_command("rfkill list bluetooth 2>&1")
        if stdout: print(stdout)
    # Check if adapter exists
    stdout, _, _ = run_command("ls /sys/class/bluetooth/ 2>&1")
    if stdout and "No such file" not in stdout:
        print_info("Bluetooth adapters: %s" % stdout.strip())
    else:
        print_warning("No Bluetooth adapters detected in /sys/class/bluetooth/")


def _check_bt_tools():
    """Check available Bluetooth tools."""
    print_section("Bluetooth Tool Availability")
    tools = {
        "hcitool": "Classic BT scanning & device info",
        "hciconfig": "BT interface configuration",
        "sdptool": "Service Discovery Protocol browser",
        "rfcomm": "RFCOMM serial port tool",
        "l2ping": "L2CAP layer ping",
        "bluetoothctl": "Modern BT management CLI",
        "btmgmt": "BT management interface",
        "obexftp": "OBEX file transfer",
        "gatttool": "BLE GATT tool (deprecated)",
        "btmon": "BT monitor/sniffer",
        "hcidump": "HCI packet dumper",
        "blueranger": "BT device locator",
        "spooftooph": "BT address spoofing",
        "redfang": "Hidden BT device finder",
        "ubertooth-scan": "Ubertooth BLE sniffer",
        "bettercap": "Network/BT/BLE attack framework",
        "crackle": "BLE encryption cracker",
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
    if missing and confirm_action("Install common Bluetooth tools?"):
        run_command("sudo apt install -y bluez bluez-tools obexftp 2>&1", timeout=60)
        print_info("Installation complete. Re-run tool check.")
