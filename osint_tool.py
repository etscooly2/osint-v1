import socket
import json
import requests
from urllib.parse import urlparse
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import whois

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
            s.settimeout(0.8)
            result = s.connect_ex((ip_address, port))
            if result == 0:
                output_box.insert(tk.END, f"    - Port {port} ({service}) : OPEN\n")
            s.close()
        except Exception:
            pass
        output_box.see(tk.END)

def check_ssl_certificate(domain, output_box):
    output_box.insert(tk.END, f"\n[+] Checking SSL/TLS Certificate Info\n")
    output_box.see(tk.END)
    try:
        context = socket.ssl.create_default_context() if hasattr(socket, 'ssl') else None
        # Using a simple requests check to look at certificate verification properties
        res = requests.get(f"https://{domain}", timeout=5, verify=True)
        output_box.insert(tk.END, f"    - SSL Handshake   : Successful (Valid Certificate Chain)\n")
    except requests.exceptions.SSLError:
        output_box.insert(tk.END, f"    - SSL Handshake   : Failed or Invalid/Self-Signed Certificate\n")
    except Exception as e:
        output_box.insert(tk.END, f"    - SSL Check status: Restricted or unreachable ({e.__class__.__name__})\n")
    output_box.see(tk.END)

def enumerate_subdomains(domain, output_box):
    output_box.insert(tk.END, f"\n[+] Enumerating Expanded Subdomains\n")
    output_box.see(tk.END)
    subdomains = [
        "www", "mail", "ftp", "admin", "test", "webmail", "api", "shop", 
        "blog", "secure", "vpn", "portal", "dev", "staging", "remote", "cloud", "dns"
    ]
    
    found_any = False
    for sub in subdomains:
        sub_target = f"{sub}.{domain}"
        try:
            resolved_ip = socket.gethostbyname(sub_target)
            output_box.insert(tk.END, f"    - Discovered: {sub_target} --> {resolved_ip}\n")
            found_any = True
            output_box.see(tk.END)
        except socket.gaierror:
            pass
    if not found_any:
        output_box.insert(tk.END, "    - No expanded subdomains resolved publicly.\n")
    output_box.see(tk.END)

def get_dns_and_ip(domain, output_box):
    output_box.insert(tk.END, f"\n[+] Resolving Deep Network Intelligence for: {domain}\n")
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
        
        for header in headers_to_check:
            val = response.headers.get(header)
            if val:
                output_box.insert(tk.END, f"      * {header}: {val}\n")
            else:
                output_box.insert(tk.END, f"      * {header}: [Not Disclosed]\n")
        output_box.see(tk.END)
        return response.url
    except requests.exceptions.RequestException as e:
        output_box.insert(tk.END, f"    - HTTP Request failed: {e}\n")
        output_box.see(tk.END)
        return None

def check_robots(final_url, output_box):
    if not final_url:
        return
    output_box.insert(tk.END, f"\n[+] Enumerating robots.txt & Sitemap Paths\n")
    output_box.see(tk.END)
    parsed = urlparse(final_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    
    try:
        res = requests.get(robots_url, timeout=5)
        if res.status_code == 200:
            output_box.insert(tk.END, f"    - Found: {robots_url}\n\n")
            lines = res.text.splitlines()
            for line in lines[:20]:
                output_box.insert(tk.END, f"      {line}\n")
            if len(lines) > 20:
                output_box.insert(tk.END, "      ... [Output truncated]\n")
        else:
            output_box.insert(tk.END, f"    - robots.txt not accessible (Status: {res.status_code})\n")
    except Exception as e:
        output_box.insert(tk.END, f"    - Could not fetch robots.txt: {e}\n")
    output_box.see(tk.END)

def execute_recon_thread(target, output_box):
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"[*] Starting Max-Power Intelligence Gathering on: {target}\n" + "="*60 + "\n")
    
    clean_domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    ip_address = get_dns_and_ip(clean_domain, output_box)
    if ip_address:
        scan_extended_ports(ip_address, output_box)
    
    perform_whois(clean_domain, output_box)
    enumerate_subdomains(clean_domain, output_box)
    check_ssl_certificate(clean_domain, output_box)
    
    final_url = inspect_http_headers(target, output_box)
    check_robots(final_url, output_box)
    
    output_box.insert(tk.END, "\n" + "="*60 + "\n          MAX-POWER OSINT SCAN COMPLETE               \n" + "="*60 + "\n")
    output_box.see(tk.END)

def run_recon(entry_widget, output_box):
    target = entry_widget.get().strip().strip('"\'.,')
    if not target:
        messagebox.showerror("Error", "Target cannot be empty.")
        return
    
    threading.Thread(target=execute_recon_thread, args=(target, output_box), daemon=True).start()

def main():
    root = tk.Tk()
    root.title("Max-Power Python OSINT Suite")
    root.geometry("900x700")
    root.configure(bg="#1e1e1e")

    title_label = tk.Label(root, text="Ultimate OSINT Intelligence Suite", fg="#00ff00", bg="#1e1e1e", font=("Arial", 14, "bold"))
    title_label.pack(pady=10)

    frame = tk.Frame(root, bg="#1e1e1e")
    frame.pack(pady=5)

    label = tk.Label(frame, text="Target URL/Domain:", fg="white", bg="#1e1e1e", font=("Arial", 10))
    label.pack(side=tk.LEFT, padx=5)

    entry = tk.Entry(frame, width=40, font=("Arial", 10))
    entry.pack(side=tk.LEFT, padx=5)
    entry.insert(0, "example.com")

    scan_btn = tk.Button(frame, text="Run Ultimate Scan", bg="#007acc", fg="white", font=("Arial", 10, "bold"), command=lambda: run_recon(entry, output_box))
    scan_btn.pack(side=tk.LEFT, padx=5)

    output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, bg="#000000", fg="#00ff00", insertbackground="white", font=("Consolas", 10))
    output_box.pack(padx=15, pady=15, fill=tk.BOTH, expand=True)

    root.mainloop()

if __name__ == "__main__":
    main()
