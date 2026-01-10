import requests
import re
import os
import sys

def audit_headers(url):
    print(f"\n[+] Auditing Security Headers: {url}")
    try:
        response = requests.get(url)
        headers = response.headers
        
        checks = {
            "Content-Security-Policy": "PROTECTED (Mitigates XSS)",
            "Strict-Transport-Security": "PROTECTED (Forces HTTPS)",
            "X-Frame-Options": "PROTECTED (Blocks Clickjacking)",
            "X-Content-Type-Options": "PROTECTED (Prevents MIME Sniffing)"
        }
        
        for header, description in checks.items():
            if header in headers:
                print(f"  [✓] {header}: {headers[header][:50]}...")
            else:
                print(f"  [✗] MISSING: {header} ({description})")
                
    except Exception as e:
        print(f"  [!] Connection failed. Ensure the server is running.")

def audit_sri():
    print("\n[+] Auditing Subresource Integrity (SRI)...")
    html_files = ["templates/login.html", "templates/vault.html"]
    for file_path in html_files:
        if not os.path.exists(file_path): continue
        
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            if 'integrity="sha384-' in content:
                print(f"  [✓] {file_path}: SRI detected for external scripts.")
            else:
                print(f"  [✗] {file_path}: Potential security risk. SRI missing.")

def audit_argon2_config():
    print("\n[+] Auditing Cryptographic Hardening (Argon2)...")
    js_path = "static/js/vault.js"
    if os.path.exists(js_path):
        with open(js_path, "r", encoding="utf-8") as f:
            content = f.read()
            # Check for high memory usage (64MB)
            if 'mem: 1024 * 64' in content:
                print("  [✓] Argon2 Memory: 64MB (Resistant to GPU/ASIC attacks)")
            else:
                print("  [✗] Argon2 Memory: Low (Possible weak key derivation)")
    else:
        print("  [!] vault.js not found.")

if __name__ == "__main__":
    print("========================================")
    print("🛡️  ZK-Vault Security Strength Auditor")
    print("========================================\n")
    
    # Check local server
    audit_headers("http://127.0.0.1:5000")
    
    # Check local files
    audit_sri()
    audit_argon2_config()
    
    print("\n[!] Recommendation: Ensure production deployment uses SSL/TLS (HTTPS).")
    print("========================================")
