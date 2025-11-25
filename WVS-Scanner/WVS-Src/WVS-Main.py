# scanner_main.py

from colorama import Fore, Style, init
from crawler import Crawler
from scanner import Scanner
from reporter import Reporter

init(autoreset=True)

BANNER = r"""
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃          WEB VULNERABILITY SCANNER           ┃
┃              Passive & Active                ┃
┃         Author: Victor @cyber_fox1           ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Modes: passive | active | both               ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
"""

def run_scanner(target, mode="passive"):
    print(Fore.BLUE + BANNER)
    print(Fore.CYAN + f"[*] Target: {target}")
    print(Fore.CYAN + f"[*] Mode: {mode}")

    # Crawl (passive)
    crawler = Crawler(target, max_pages=200, delay=0.15)
    print(Fore.CYAN + "[*] Crawling for pages (passive)...")
    crawler.crawl()
    links = crawler.get_links()
    print(Fore.CYAN + f"[*] {len(links)} pages discovered")

    scanner = Scanner()
    all_findings = []

    # If user chose pure active and no links found, scan base url at least
    if mode.lower() == "active" and not links:
        links = [target]

    for link in links:
        print(Fore.YELLOW + f"[~] Scanning: {link}")
        try:
            findings = scanner.scan(link, mode=mode)
            if findings:
                for f in findings:
                    all_findings.append(f)
                    sev = f.get("severity", "INFO")
                    check = f.get("check")
                    print(Fore.RED if sev == "HIGH" else Fore.MAGENTA if sev == "MEDIUM" else Fore.YELLOW,
                          f"[{sev}] {check} - {f.get('detail')}")
        except Exception as e:
            print(Fore.RED + f"[!] Error scanning {link}: {e}")

    reporter = Reporter(all_findings, target)
    reporter.generate_report(txtfile="scan_report.txt", jsonfile="scan_report.json")
    print(Fore.GREEN + "[✓] Scan finished (limited active). Remember: no exploit payloads were used.")
