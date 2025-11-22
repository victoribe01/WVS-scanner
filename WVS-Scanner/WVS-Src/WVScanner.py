

import requests
from urllib.parse import urlparse, parse_qs
from payloads import SQLI_PAYLOADS, XSS_PAYLOADS, LFI_PAYLOADS
from severity import get_severity
from colors import severity_color


class Scanner:
    def __init__(self):
        pass

    def scan_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return []

        print(f"[+] Scanning {url}")

        findings = []

        if self.test_sqli(url, params):
            findings.append("SQL Injection")
            self.print_finding(url, "SQL Injection")

        if self.test_xss(url, params):
            findings.append("Cross-Site Scripting (XSS)")
            self.print_finding(url, "Cross-Site Scripting (XSS)")

        if self.test_lfi(url, params):
            findings.append("Local File Inclusion (LFI)")
            self.print_finding(url, "Local File Inclusion (LFI)")

        return findings


    # ------------------------- TEST FUNCTIONS -------------------------

    def test_sqli(self, url, params):
        for payload in SQLI_PAYLOADS:
            data = {k: payload for k in params.keys()}
            r = requests.get(url.split('?')[0], params=data)

            if any(x in r.text.lower() for x in ["sql", "database", "syntax error"]):
                return True
        return False


    def test_xss(self, url, params):
        for payload in XSS_PAYLOADS:
            data = {k: payload for k in params.keys()}
            r = requests.get(url.split('?')[0], params=data)

            if payload in r.text:
                return True
        return False


    def test_lfi(self, url, params):
        for payload in LFI_PAYLOADS:
            data = {k: payload for k in params.keys()}
            r = requests.get(url.split('?')[0], params=data)

            if "root:" in r.text or "[extensions]" in r.text:
                return True
        return False


    # ------------------------- PRINTING -------------------------

    def print_finding(self, url, vuln):
        severity = get_severity(vuln)
        sev_colored = severity_color(severity)
        print(f"[FOUND] {vuln} ({sev_colored}) at {url}")

    
