
import requests
from urllib.parse import urlparse
from payloads import SQLI_PAYLOADS, XSS_PAYLOADS, LFI_PAYLOADS

class Scanner:
    def __init__(self):
        self.vulnerabilities = []

    def scan_url(self, url):
        parsed = urlparse(url)
        params = {k: v for k, v in [param.split('=') for param in parsed.query.split('&')] if '=' in parsed.query} \
            if parsed.query else None

        if not params:
            return

        print(f"[+] Scanning {url}")

        if self.test_sqli(url, params):
            self.vulnerabilities.append((url, "SQL Injection"))

        if self.test_xss(url, params):
            self.vulnerabilities.append((url, "Cross Site Scripting (XSS)"))

        if self.test_lfi(url, params):
            self.vulnerabilities.append((url, "Local File Inclusion (LFI)"))

    def test_sqli(self, url, params):
        for payload in SQLI_PAYLOADS:
            data = {k: payload for k in params.keys()}
            r = requests.get(url.split('?')[0], params=data)
            if any(x in r.text.lower() for x in ["sql", "database", "syntax error"]):
                print(f"[!] SQL Injection detected at {url}")
                return True
        return False

    def test_xss(self, url, params):
        for payload in XSS_PAYLOADS:
            data = {k: payload for k in params.keys()}
            r = requests.get(url.split('?')[0], params=data)
            if payload in r.text:
                print(f"[!] XSS detected at {url}")
                return True
        return False

    def test_lfi(self, url, params):
        for payload in LFI_PAYLOADS:
            data = {k: payload for k in params.keys()}
            r = requests.get(url.split('?')[0], params=data)
            if "root:" in r.text or "[extensions]" in r.text:
                print(f"[!] Local File Inclusion detected at {url}")
                return True
        return False
