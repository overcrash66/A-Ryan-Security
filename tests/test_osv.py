# test_osv.py
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from security_modules.vuln_checker import scan_vulnerabilities

if __name__ == "__main__":
    vulns, osv_data = scan_vulnerabilities()
    print("Vulnerabilities by package:")
    for package, count in vulns.items():
        print(f"  {package}: {count} vulnerabilities")
    
    print("\nRaw OSV data:")
    print(json.dumps(osv_data, indent=2))