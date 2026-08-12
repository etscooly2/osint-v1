import socket
import json
import requests
from urllib.parse import urlparse
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import whois
import datetime
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

def perform_whois(domain, output_box):
    output_box.insert(tk.END, f"\n[+] Fetching WHOIS Registration Data\n")
    output_box.see(tk.END)
    try:
        w = whois.whois(domain)
        if w.registrar:
            output_box.insert(tk.END, f"    - Registrar       : {w.registrar}\n")
        if w.creation_date:
            c_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            output_box.insert(tk.END, f"    - Creation Date   : {c_date}\n")
        if w.expiration_date:
            e_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            output_box.insert(tk.END, f"    - Expiration Date : {e_date}\n")
        if w.name_servers:
            ns = ", ".join(w.name_servers[:4]) if isinstance(w.name_servers, list) else w.name_servers
            output_box.insert(tk.END, f"    - Name Servers    : {ns}\n")
    except Exception as e:
        output_box.insert(tk.END, f"    - WHOIS lookup failed or restricted: {e}\n")
    output_box.see(tk.END)

def scan_extended_ports(ip_address, output_box):
    output_box.insert(tk.END, f"\n[+] Scanning Extended Network & Web Ports\n")
    output_box.see(tk.END)
    ports_to_check = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
        53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS", 
        445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
    }
    
    for port, service in ports_to_check.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip_address, port))
            if result == 0:
                output_box.insert(tk.END, f"    - Port {port} ({service}) : [OPEN]\n")
            s.close()
        except Exception:
            pass
        output_box.see(tk.END)

def check_ssl_certificate(domain, output_box):
    output_box.insert(tk.END, f"\n[+] Checking SSL/TLS Certificate Info\n")
    output_box.see(tk.END)
    try:
        requests.get(f"https://{domain}", timeout=5, verify=True)
        output_box.insert(tk.END, f"    - SSL Handshake   : Successful (Valid Certificate Chain)\n")
    except requests.exceptions.SSLError:
        output_box.insert(tk.END, f"    - SSL Handshake   : Failed or Invalid/Self-Signed Certificate\n")
    except Exception as e:
        output_box.insert(tk.END, f"    - SSL Check status: Restricted or unreachable ({e.__class__.__name__})\n")
    output_box.see(tk.END)

def enumerate_dns_records(domain, output_box):
    output_box.insert(tk.END, f"\n[+] Extracting Deep DNS Records (MX, TXT, NS)\n")
    output_box.see(tk.END)
    record_types = ['MX', 'TXT', 'NS']
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                output_box.insert(tk.END, f"    - {rtype} Record: {rdata.to_text()}\n")
        except Exception:
            output_box.insert(tk.END, f"    - {rtype} Record: [No records found or query restricted]\n")
    output_box.see(tk.END)

def check_threat_intelligence(ip_address, domain, output_box):
    output_box.insert(tk.END, f"\n[+] Querying Global Threat Intelligence APIs (VirusTotal / Shodan Simulation)\n")
    output_box.see(tk.END)
    
    # Example VirusTotal Domain Report check (Requires public free API key or handles gracefully)
    try:
        vt_headers = {"x-apikey": "YOUR_VIRUSTOTAL_API_KEY_HERE"}
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=vt_headers, timeout=5)
        if vt_res.status_code == 200:
            stats = vt_res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            output_box.insert(tk.END, f"    - VirusTotal Engine Score: Malicious: {stats.get('malicious', 0)} | Harmless: {stats.get('harmless', 0)}\n")
        else:
            output_box.insert(tk.END, f"    - VirusTotal API: Skipped/Requires valid API key in code configuration.\n")
    except Exception:
        output_box.insert(tk.END, f"    - VirusTotal API: Lookup unavailable.\n")
        
    output_box.see(tk.END)

def check_tech_stack(target_url, output_box):
    output_box.insert(tk.END, f"\n[+] Performing Advanced Technology Fingerprinting (Tech Stack)\n")
    output_box.see(tk.END)
    try:
        res = requests.get(target_url, timeout=6)
        html_content = res.text.lower()
        headers = res.headers
        
        detected = []
        if "wp-content" in html_content or "wordpress" in html_content:
            detected.append("WordPress CMS")
        if "shopify" in html_content:
            detected.append("Shopify E-Commerce")
        if "react" in html_content or "__next" in html_content:
            detected.append("React / Next.js Framework")
        if "jquery" in html_content:
            detected.append("jQuery Library")
        if "bootstrap" in html_content:
            detected.append("Bootstrap CSS Framework")
        if "cloudflare" in headers.get("Server", "").lower() or "cf-ray" in headers:
            detected.append("Cloudflare CDN / WAF")
            
        if detected:
            for tech in detected:
                output_box.insert(tk.END, f"    - Identified Technology: {tech}\n")
        else:
            output_box.insert(tk.END, f"    - No major template signatures instantly matched standard library.\n")
    except Exception as e:
        output_box.insert(tk.END, f"    - Technology fingerprinting error: {e}\n")
    output_box.see(tk.END)

def test_subdomain(sub_target, output_box):
    try:
        resolved_ip = socket.gethostbyname(sub_target)
        output_box.insert(tk.END, f"    - Discovered: {sub_target} --> {resolved_ip}\n")
        output_box.see(tk.END)
        return True
    except socket.gaierror:
        return False

def multithreaded_subdomain_brute(domain, output_box):
    output_box.insert(tk.END, f"\n[+] Executing Multithreaded High-Speed Subdomain Enumeration\n")
    output_box.see(tk.END)
    
    subdomains = [
        "www", "mail", "ftp", "admin", "test", "webmail", "api", "shop", 
        "blog", "secure", "vpn", "portal", "dev", "staging", "remote", "cloud", 
        "dns", "status", "dashboard", "jenkins", "git", "metrics", "db", "shop",
        "support", "internal", "api2", "beta", "staging2", "auth", "account"
    ]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(test_subdomain, f"{sub}.{domain}", output_box): sub for sub in subdomains}
        for future in as_completed(futures):
            pass
    output_box.see(tk.END)

def brute_force_directories(target_url, output_box):
    output_box.insert(tk.END, f"\n[+] Executing Lightweight Directory & Endpoint Brute-Forcer\n")
    output_box.see(tk.END)
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url
    
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    directories = [
        "admin", "login", "dashboard", "api", "config", "backup", "test", 
        "wp-admin", "server-status", "robots.txt", "sitemap.xml", "secret", "private"
    ]
    
    found_paths = 0
    for directory in directories:
        test_url = f"{base_url}/{directory}"
        try:
            res = requests.get(test_url, timeout=3, allow_redirects=False)
            if res.status_code in [200, 301, 302, 403]:
                output_box.insert(tk.END, f"    - Discovered Path: /{directory} (Status: {res.status_code})\n")
                found_paths += 1
                output_box.see(tk.END)
        except Exception:
            pass
    if found_paths == 0:
        output_box.insert(tk.END, "    - No common endpoints responded with active status codes.\n")
    output_box.see(tk.END)

def get_dns_and_ip(domain, output_box):
    output_box.insert(tk.END, f"\n[+] Resolving Deep Network Intelligence & Geolocation for: {domain}\n")
    output_box.see(tk.END)
    try:
        ip_address = socket.gethostbyname(domain)
        output_box.insert(tk.END, f"    - Target IP Address : {ip_address}\n")
        
        try:
            host_info = socket.gethostbyaddr(ip_address)
            output_box.insert(tk.END, f"    - Hostname          : {host_info[0]}\n")
        except socket.herror:
            output_box.insert(tk.END, "    - Hostname          : [Reverse DNS lookup failed]\n")
            
        geo_res = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        if geo_res.status_code == 200:
            geo_data = geo_res.json()
            if geo_data.get("status") == "success":
                output_box.insert(tk.END, f"    - Country           : {geo_data.get('country')}\n")
                output_box.insert(tk.END, f"    - Region/City       : {geo_data.get('regionName')}, {geo_data.get('city')}\n")
                output_box.insert(tk.END, f"    - ISP / Organization: {geo_data.get('isp')} / {geo_data.get('org')}\n")
                output_box.insert(tk.END, f"    - Timezone          : {geo_data.get('timezone')}\n")
                output_box.insert(tk.END, f"    - Coordinates       : {geo_data.get('lat')}, {geo_data.get('lon')}\n")
        
        return ip_address
    except socket.gaierror:
        output_box.insert(tk.END, "    - Error: Unable to resolve domain name. Check address validity.\n")
        return None
    except Exception as e:
        output_box.insert(tk.END, f"    - Error during network lookup: {e}\n")
        return None

def inspect_http_headers(target_url, output_box):
    output_box.insert(tk.END, f"\n[+] Inspecting Comprehensive HTTP Headers & Security Posture\n")
    output_box.see(tk.END)
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    try:
        response = requests.get(target_url, timeout=10, allow_redirects=True)
        output_box.insert(tk.END, f"    - Final URL    : {response.url}\n")
        output_box.insert(tk.END, f"    - Status Code  : {response.status_code}\n")
        output_box.insert(tk.END, f"    - Encoding     : {response.encoding}\n")
        
        output_box.insert(tk.END, "\n    [Full Infrastructure & Security Headers Scanned]\n")
        headers_to_check = [
            'Server', 'X-Powered-By', 'Strict-Transport-Security', 
            'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',
            'Access-Control-Allow-Origin', 'X-XSS-Protection', 'Expect-CT', 'Set-Cookie'
        ]
        
        missing_headers = 0
        for header in headers_to_check:
            val = response.headers.get(header)
            if val:
                output_box.insert(tk.END, f"      * {header}: {val}\n")
            else:
                output_box.insert(tk.END, f"      * {header}: [Not Disclosed / Missing]\n")
                missing_headers += 1
                
        output_box.insert(tk.END, f"\n    - Security Posture Analysis: {len(headers_to_check) - missing_headers}/{len(headers_to_check)} standard security headers implemented.\n")
        output_box.see(tk.END)
        return response.url
    except requests.exceptions.RequestException as e:
        output_box.insert(tk.END, f"    - HTTP Request failed: {e}\n")
        output_box.see(tk.END)
        return None

def check_robots(final_url, output_box):
    if not final_url:
        return
    output_box.insert(tk.END, f"\n[+] Enumerating robots.txt & Sensitive Disclosures\n")
    output_box.see(tk.END)
    parsed = urlparse(final_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    
    try:
        res = requests.get(robots_url, timeout=5)
        if res.status_code == 200:
            output_box.insert(tk.END, f"    - Found: {robots_url}\n\n")
            lines = res.text.splitlines()
            for line in lines[:25]:
                output_box.insert(tk.END, f"      {line}\n")
            if len(lines) > 25:
                output_box.insert(tk.END, "      ... [Output truncated]\n")
        else:
            output_box.insert(tk.END, f"    - robots.txt not accessible (Status: {res.status_code})\n")
    except Exception as e:
        output_box.insert(tk.END, f"    - Could not fetch robots.txt: {e}\n")
    output_box.see(tk.END)

def execute_recon_thread(target, output_box):
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"[*] Starting Max-Power Enterprise Intelligence Gathering on: {target}\n" + "="*70 + "\n")
    
    clean_domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    ip_address = get_dns_and_ip(clean_domain, output_box)
    if ip_address:
        scan_extended_ports(ip_address, output_box)
        check_threat_intelligence(ip_address, clean_domain, output_box)
    
    perform_whois(clean_domain, output_box)
    enumerate_dns_records(clean_domain, output_box)
    multithreaded_subdomain_brute(clean_domain, output_box)
    check_ssl_certificate(clean_domain, output_box)
    
    final_url = inspect_http_headers(target, output_box)
    if final_url:
        check_tech_stack(final_url, output_box)
    check_robots(final_url, output_box)
    brute_force_directories(target, output_box)
    
    output_box.insert(tk.END, "\n" + "="*70 + "\n          ENTERPRISE OSINT SCAN COMPLETE & VERIFIED                 \n" + "="*70 + "\n")
    output_box.see(tk.END)

def run_recon(entry_widget, output_box):
    target = entry_widget.get().strip().strip('"\'.,')
    if not target:
        messagebox.showerror("Error", "Target cannot be empty.")
        return
    
    threading.Thread(target=execute_recon_thread, args=(target, output_box), daemon=True).start()

def save_report(output_box):
    report_content = output_box.get(1.0, tk.END).strip()
    if not report_content:
        messagebox.showwarning("Warning", "No scan data available to save.")
        return
    
    file_path = filedialog.asksaveasfilename(
        defaultextension=".html",
        filetypes=[("HTML Report Files", "*.html"), ("Text Files", "*.txt"), ("All Files", "*.*")],
        initialfile=f"enterprise_osint_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )
    if file_path:
        try:
            # Generate a structured professional HTML report format automatically
            html_template = f"""<!DOCTYPE html>
<html>
<head>
    <title>Enterprise OSINT Intelligence Report</title>
    <style>
        body {{ background-color: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; }}
        h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
        pre {{ background-color: #161b22; color: #51f851; padding: 15px; border-radius: 6px; border: 1px solid #30363d; font-family: 'Courier New', Courier, monospace; overflow-x: auto; }}
        .meta {{ color: #8b949e; font-size: 0.9em; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>Enterprise OSINT Intelligence Report</h1>
    <div class="meta">Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    <pre>{report_content}</pre>
</body>
</html>"""
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_template if file_path.endswith('.html') else report_content)
            messagebox.showinfo("Success", f"Professional report successfully saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

def change_theme(choice, root, output_box):
    if choice == "Hacker Green":
        root.configure(bg="#1e1e1e")
        output_box.configure(bg="#000000", fg="#00ff00", insertbackground="white")
    elif choice == "Matrix Amber":
        root.configure(bg="#1a1100")
        output_box.configure(bg="#0d0800", fg="#ffb000", insertbackground="white")
    elif choice == "Cyber Blue":
        root.configure(bg="#0f172a")
        output_box.configure(bg="#020617", fg="#38bdf8", insertbackground="white")

def main():
    root = tk.Tk()
    root.title("Max-Power Python OSINT Suite [Enterprise Edition]")
    root.geometry("1050x800")
    root.configure(bg="#1e1e1e")

    title_label = tk.Label(root, text="Enterprise-Grade OSINT & Threat Intelligence Suite", fg="#00ff00", bg="#1e1e1e", font=("Arial", 14, "bold"))
    title_label.pack(pady=10)

    frame = tk.Frame(root, bg="#1e1e1e")
    frame.pack(pady=5)

    label = tk.Label(frame, text="Target URL/Domain:", fg="white", bg="#1e1e1e", font=("Arial", 10))
    label.pack(side=tk.LEFT, padx=5)

    entry = tk.Entry(frame, width=25, font=("Arial", 10))
    entry.pack(side=tk.LEFT, padx=5)
    entry.insert(0, "example.com")

    scan_btn = tk.Button(frame, text="Run Enterprise Scan", bg="#007acc", fg="white", font=("Arial", 10, "bold"), command=lambda: run_recon(entry, output_box))
    scan_btn.pack(side=tk.LEFT, padx=5)

    save_btn = tk.Button(frame, text="Export HTML Report", bg="#28a745", fg="white", font=("Arial", 10, "bold"), command=lambda: save_report(output_box))
    save_btn.pack(side=tk.LEFT, padx=5)

    theme_var = tk.StringVar(value="Hacker Green")
    theme_menu = tk.OptionMenu(frame, theme_var, "Hacker Green", "Matrix Amber", "Cyber Blue", command=lambda val: change_theme(val, root, output_box))
    theme_menu.config(bg="#333333", fg="white", font=("Arial", 9))
    theme_menu.pack(side=tk.LEFT, padx=5)

    output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, bg="#000000", fg="#00ff00", insertbackground="white", font=("Consolas", 10))
    output_box.pack(padx=15, pady=15, fill=tk.BOTH, expand=True)

    root.mainloop()

if __name__ == "__main__":
    main()
