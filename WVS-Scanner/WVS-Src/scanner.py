# scanner.py
import requests
from urllib.parse import urlparse, parse_qs, urljoin
from colorama import Fore
import socket, ssl, json
import datetime

class ScanResult:
    def __init__(self, url, severity, check, detail):
        self.url = url
        self.severity = severity
        self.check = check
        self.detail = detail

    def to_dict(self):
        return {"url": self.url, "severity": self.severity, "check": self.check, "detail": self.detail}


class Scanner:
    def __init__(self, timeout=6, headers=None):
        self.timeout = timeout
        self.headers = headers or {"User-Agent": "SafeScanner/1.0"}
        # common file names to probe (non-destructive existence checks)
        self.common_files = [
            ".env", ".git/config", "backup.zip", "backup.tar.gz", "db_backup.sql", "config.php~",
            "wp-config.php.bak", "index.old", "sitemap.xml", "robots.txt"
        ]
        # methods to test that are potentially risky - we only detect support, not exploit
        self.methods_to_test = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"]

    # --- PASSIVE CHECKS ---
    def passive_checks(self, url):
        results = []
        try:
            r = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            # unreachable is not an error we list as vulnerability
            print(Fore.YELLOW + f"[!] passive_checks: {url} unreachable: {e}")
            return results

        headers = {k.title(): v for k, v in r.headers.items()}

        # 1. Missing security headers
        for h, sev in [("Strict-Transport-Security", "MEDIUM"), ("Content-Security-Policy", "MEDIUM"),
                       ("X-Frame-Options", "MEDIUM"), ("X-Content-Type-Options", "MEDIUM"),
                       ("Referrer-Policy", "LOW")]:
            if h not in headers:
                results.append(ScanResult(url, sev, f"MissingHeader:{h}", f"{h} not present"))

        # 2. Cookies without secure/httponly flags
        if "Set-Cookie" in headers:
            cookies = headers["Set-Cookie"]
            if "secure" not in cookies.lower():
                results.append(ScanResult(url, "LOW", "Cookie:Secure", "Set-Cookie missing Secure flag (might be over HTTP)"))
            if "httponly" not in cookies.lower():
                results.append(ScanResult(url, "LOW", "Cookie:HttpOnly", "Set-Cookie missing HttpOnly"))

        # 3. Directory listing detection (simple)
        if "<title>Index of" in r.text or "Directory listing for" in r.text:
            results.append(ScanResult(url, "HIGH", "DirectoryIndex", "Directory listing content found"))

        # 4. Exposed server banner analysis (very simple heuristics)
        server = headers.get("Server", "")
        if server:
            # crude outdated lookups
            if any(x in server.lower() for x in ["apache/2.", "nginx/1.14", "nginx/1.10"]):
                results.append(ScanResult(url, "LOW", "ServerBanner", f"Server header: {server}"))

        # 5. Parameter presence (informational)
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            results.append(ScanResult(url, "LOW", "URLParameters", f"Parameters found: {list(params.keys())}"))

        return results

    # --- SAFE ACTIVE CHECKS (non-exploitative) ---
    def active_checks(self, url):
        results = []
        parsed = urlparse(url)
        host = parsed.hostname
        scheme = parsed.scheme or "http"
        port = parsed.port or (443 if scheme == "https" else 80)

        # 1. TLS certificate expiry (only for https)
        if scheme == "https":
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        if "notAfter" in cert:
                            expires = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                            days = (expires - datetime.datetime.utcnow()).days
                            if days < 30:
                                results.append(ScanResult(url, "MEDIUM", "TLS:CertExpiry", f"Certificate expires in {days} days"))
                        else:
                            results.append(ScanResult(url, "LOW", "TLS:Cert", "Unable to parse certificate expiry"))
            except Exception as e:
                results.append(ScanResult(url, "LOW", "TLS:Connect", f"TLS connection failed: {e}"))

        # 2. HTTP methods allowed (we'll do an OPTIONS or custom request)
        try:
            r = requests.options(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            allow = r.headers.get("Allow", "")
            if allow:
                for m in ["PUT", "DELETE", "TRACE", "PATCH"]:
                    if m in allow.upper():
                        results.append(ScanResult(url, "MEDIUM", f"HTTPMethod:{m}", f"Method {m} allowed by server"))
        except Exception as e:
            results.append(ScanResult(url, "LOW", "HTTP:OPTIONS", f"OPTIONS request failed: {e}"))

        # 3. Probe for common backup/config files (non intrusive - HEAD then GET if HEAD 200)
        for fname in self.common_files:
            probe = urljoin(url + "/", fname) if not url.endswith("/") else urljoin(url, fname)
            try:
                head = requests.head(probe, headers=self.headers, timeout=4, allow_redirects=True)
                if head.status_code == 200:
                    results.append(ScanResult(url, "HIGH", "ExposedFile", f"{probe} returned 200"))
                elif head.status_code in (403, 401):
                    # discovered but protected
                    results.append(ScanResult(url, "LOW", "ExposedFile:Protected", f"{probe} returned {head.status_code}"))
            except Exception:
                continue

        # 4. Reflection smoke-test for parameters (non-exploitative) - look for echoed param value
        if parsed.query:
            try:
                r = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
                for k, vals in parse_qs(parsed.query).items():
                    for v in vals:
                        if v and v in r.text:
                            results.append(ScanResult(url, "LOW", "ParameterReflection", f"Parameter '{k}' value appears in response"))
            except Exception:
                pass

        return results

    # helper to run according to mode
    def scan(self, url, mode="passive"):
        mode = mode.lower()
        results = []
        if mode in ("passive", "both"):
            results.extend(self.passive_checks(url))
        if mode in ("active", "both"):
            results.extend(self.active_checks(url))
        return [r.to_dict() for r in results]
