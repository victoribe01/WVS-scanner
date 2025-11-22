import os
from urllib.parse import urlparse

class Reporter:
    def __init__(self, vulnerabilities, target_url):
        self.vulnerabilities = vulnerabilities
        self.target_url = target_url

    def generate_report(self):
        # Extract domain name from URL
        parsed = urlparse(self.target_url)
        domain = parsed.netloc

        # Build directory path: reports/<domain>/
        directory = os.path.join("reports", domain)

        # Create directory if not exists
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Final report file path
        filename = os.path.join(directory, "report.txt")

        # Write the report
        with open(filename, 'w') as f:
            f.write("=== Web Vulnerability Scan Report ===\n")
            f.write(f"Target: {self.target_url}\n\n")

            if not self.vulnerabilities:
                f.write("No vulnerabilities found.\n")
            else:
                for url, vuln in self.vulnerabilities:
                    f.write(f"[{vuln}] found at {url}\n")

        print(f"Report saved to {filename}")
