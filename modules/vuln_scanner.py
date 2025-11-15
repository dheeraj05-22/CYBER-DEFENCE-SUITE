# modules/vuln_scanner.py

import nmap
import requests


def scan_vulnerabilities(target):
    print(f"\n🔍 Scanning {target} for vulnerabilities...\n")

    nm = nmap.PortScanner()
    try:
        # Run service detection (-sV)
        nm.scan(target, arguments="-sV")

        if target not in nm.all_hosts():
            print("❌ Target not found or not reachable.")
            return

        for host in nm.all_hosts():
            print(f"\n🖥️ Host: {host}")
            print(f"   🔎 State: {nm[host].state()}")

            for proto in nm[host].all_protocols():
                print(f"\n📡 Protocol: {proto}")
                ports = nm[host][proto].keys()

                for port in ports:
                    service = nm[host][proto][port]
                    state = service["state"]
                    name = service["name"]
                    product = service.get("product", "")
                    version = service.get("version", "")
                    extrainfo = service.get("extrainfo", "")

                    print(f"   ➡️ Port: {port} | State: {state} | "
                          f"Service: {name} | {product} {version} {extrainfo}")

        # If the target looks like a website, run web vulnerability checks
        if target.startswith("http://") or target.startswith("https://") or "." in target:
            check_web_vulnerabilities(target)

    except Exception as e:
        print(f"⚠️ Error scanning target: {e}")


def check_web_vulnerabilities(url):
    print(f"\n🌍 Running basic web vulnerability checks on {url}\n")

    if not url.startswith("http"):
        url = "http://" + url

    try:
        # --- 1. Check HTTP headers for security ---
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers

        print("🛡️ Security Header Checks:")
        required_headers = [
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-XSS-Protection",
            "Strict-Transport-Security"
        ]

        missing_headers = [h for h in required_headers if h not in headers]

        if missing_headers:
            print(f"   ❌ Missing headers: {', '.join(missing_headers)}")
        else:
            print("   ✅ All essential security headers are present.")

        # --- 2. Check HTTPS enforcement ---
        if url.startswith("https://"):
            print("   ✅ Site uses HTTPS.")
        else:
            print("   ❌ Site does not enforce HTTPS.")

        # --- 3. Basic SQL Injection test ---
        test_url = url.rstrip("/") + "/?id=1'"
        vuln_test = requests.get(test_url, timeout=5)

        if any(err in vuln_test.text.lower() for err in ["sql", "syntax", "mysql", "odbc", "error"]):
            print("   ⚠️ Possible SQL Injection vulnerability detected!")
        else:
            print("   ✅ No obvious SQL Injection detected.")

        # --- 4. Check for sensitive files ---
        print("\n📂 Checking for common sensitive files:")
        sensitive_paths = ["robots.txt", ".git/", "config.php", "admin/"]
        for path in sensitive_paths:
            test_path = url.rstrip("/") + "/" + path
            resp = requests.get(test_path, timeout=5)
            if resp.status_code == 200:
                print(f"   ⚠️ Found accessible: {path}")
        print("   ✅ Sensitive file check completed.")

    except Exception as e:
        print(f"⚠️ Web vulnerability check failed: {e}")
