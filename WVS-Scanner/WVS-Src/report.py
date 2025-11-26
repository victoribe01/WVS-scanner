#!/bin/python

# reporter.py
import json
from colorama import Fore

class Reporter:
    def __init__(self, vulnerabilities, target):
        self.vulns = vulnerabilities or []
        self.target = target

    def generate_report(self, txtfile="scan_report.txt", jsonfile="scan_report.json"):
        # TXT
        try:
            with open(txtfile, "w", encoding="utf-8") as f:
                f.write("PASSIVE/ACTIVE SCAN REPORT\n")
                f.write("=========================\n")
                f.write(f"Target: {self.target}\n\n")
                if not self.vulns:
                    f.write("No findings (passive/active limited checks only).\n")
                else:
                    for v in self.vulns:
                        f.write(f"[{v.get('severity')}] {v.get('check')} - {v.get('detail')} - {v.get('url')}\n")
            print(Fore.GREEN + f"[✓] TXT report saved to {txtfile}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to write TXT report: {e}")

        # JSON
        try:
            with open(jsonfile, "w", encoding="utf-8") as f:
                json.dump({"target": self.target, "results": self.vulns}, f, indent=2)
            print(Fore.GREEN + f"[✓] JSON report saved to {jsonfile}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to write JSON report: {e}")
