
from crawler import Crawler
from WVScanner import Scanner
from WVReport import Reporter

# ==========================================
#                ADVANCED BANNER
# ==========================================
BANNER = r"""
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃         WEB VULNERABILITY SCANNER            ┃
┃        (Passive & Non-Intrusive Mode)        ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃  [•] Analyzer: HTTP Response Heuristics      ┃
┃  [•] Severity Levels: LOW / MEDIUM / HIGH    ┃
┃  [•] Target: URL Structure & Parameter Logic ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
"""
# ==========================================


def run_scanner(target):
    print(BANNER)  # show banner
    print(f"[*] Starting scan on: {target}")

# example: ("http://site.com/page?id=1", "SQL Injection")


    print("[*] Starting scan...")
    crawler = Crawler(target)
    crawler.crawl()
    links = crawler.get_links()

    scanner = Scanner()
    for link in links:
        scanner.scan_url(link)

    reporter = Reporter(vulnerabilities, target)
    reporter.generate_report()


if __name__ == "__main__":
    target = input("Enter the target URL (e.g. http://testphp.vulnweb.com): ").strip()
    run_scanner(target)
