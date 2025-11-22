def get_severity(vulnerability):
    severity_map = {
        "SQL Injection": "HIGH",
        "XSS": "MEDIUM",
        "Insecure Headers": "LOW",
        "Missing HTTPS": "LOW",
    }
    return severity_map.get(vulnerability, "UNKNOWN")
