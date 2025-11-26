# Web Application Vulnerability Scanner (WVS)

This is a web vulnerability analyzer that scans websites for common misconfigurations, weak headers, sensitive exposure, and reflection-based issues using passive and limited active modes.

## Features
Web Vulnerability Scanner Framework.

It is designed to:

✔ Crawl a website

✔ Analyze pages

✔ Detect potential vulnerabilities

✔ Generate a report

✔ Support both passive and active scanning modes (active
 


## Installation

```bash

git clone https://github.com/<your_username>/wvs-scanner.git

cd WVS-scanner

pip install -r requirements.txt

cd WVS-Src

python WVS-Main.py

```

```less

Enter the target URL (include scheme, e.g. https://example.com): https://example.com
Scan mode (/passive/active/both): active

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃         WEB VULNERABILITY SCANNER            ┃
┃             Passive & Active                 ┃
┃         Author: VICTOR @cyber_fox            ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Modes: passive | active | both               ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

[*] Target: https://example.com
[*] Mode: active
[*] Crawling for pages (passive)...
[*] 1 pages discovered
[~] Scanning: https://example.com/
[✓] Report saved to scan_report.txt

```



# **What this covers (detection list)**

Missing/weak security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)

Cookie flags (Secure, HttpOnly)

Directory indexing detection

Exposed common backup/config files (.env, .git/config, wp-config.php.bak, etc.)

URL parameter presence and basic reflection detection

Server banner observations (simple heuristics)

TLS certificate expiry checks (HTTPS only)

HTTP methods allowed (OPTIONS / Allow header detection)

robots.txt and sitemap existence via common file probes (robots.txt included in common files)

Exposed protected files returning 401/403 vs 200 (informational)
