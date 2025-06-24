#!/usr/bin/env python3
# LunisecX - OpenBash Pentesting Tool (Tek Dosya CLI Sürüm)

import argparse
import socket
import scapy.all as scapy
import requests
import ipaddress
import threading
import json
import csv
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scapy.all import sniff, wrpcap
from colorama import Fore, Style, init

init(autoreset=True)

scan_results = {
    "open_ports": [],
    "discovered_urls": [],
    "sensitive_files": [],
    "xss_vulns": [],
    "lfi_vulns": [],
    "critical_leaks": []
}

port_services = {
    80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 25: "SMTP", 3306: "MySQL"
}

sensitive_paths = [
    "/.env", "/.git/config", "/config.php", "/robots.txt", "/backup.zip", "/phpinfo.php"
]

def validate_url(url):
    return url if url.startswith("http") else "http://" + url

def parse_port_range(port_range):
    if not port_range:
        return [21, 22, 80, 443]
    try:
        if "-" in port_range:
            start, end = map(int, port_range.split("-"))
            return list(range(start, end + 1))
        else:
            return [int(port_range)]
    except:
        print("[!] Geçersiz port aralığı")
        return [80]

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        data = s.recv(1024)
        s.close()
        return data.decode(errors="ignore").strip()
    except:
        return "Banner alınamadı"

def is_host_up(ip):
    try:
        arp = scapy.ARP(pdst=ip)
        eth = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        pkt = eth/arp
        ans = scapy.srp(pkt, timeout=1, verbose=False)[0]
        return len(ans) > 0
    except:
        return False

def scan_tcp_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            banner = grab_banner(ip, port)
            print(f"{Fore.GREEN}[TCP] {ip}:{port} açık - {banner}")
            scan_results["open_ports"].append({
                "ip": ip,
                "port": port,
                "banner": banner
            })
            return True
    except:
        pass
    return False

def scan_udp_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"", (ip, port))
        s.recvfrom(1024)
        return True
    except socket.timeout:
        return True
    except:
        return False

def scan_ports(ip, ports, use_udp=False):
    open_ports = []
    for port in ports:
        if use_udp:
            if scan_udp_port(ip, port):
                open_ports.append(port)
        else:
            if scan_tcp_port(ip, port):
                open_ports.append(port)
    return open_ports

def scan_network(target, port_range=None, use_udp=False):
    ports = parse_port_range(port_range)
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        print("[X] Geçersiz IP veya CIDR")
        return

    for ip in net.hosts():
        ip_str = str(ip)
        if is_host_up(ip_str):
            print(f"{Fore.CYAN}[✓] {ip_str} aktif")
            scan_ports(ip_str, ports, use_udp)
        else:
            print(f"{Fore.YELLOW}[X] {ip_str} yanıt vermiyor")

def discover_urls(base_url, wordlist_path=None):
    if wordlist_path:
        try:
            with open(wordlist_path, "r") as f:
                paths = [line.strip() for line in f]
        except:
            print(f"[!] Wordlist okunamadı: {wordlist_path}")
            return
    else:
        paths = ["/admin", "/login", "/dashboard", "/config", "/robots.txt"]

    def worker(path):
        try:
            url = f"{base_url.rstrip('/')}{path}"
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                print(f"{Fore.GREEN}[+] Keşfedilen URL: {url}")
                scan_results["discovered_urls"].append(url)
        except:
            pass

    threads = [threading.Thread(target=worker, args=(p,)) for p in paths]
    for t in threads: t.start()
    for t in threads: t.join()

def check_sensitive_files(base):
    for path in sensitive_paths:
        try:
            url = f"{base.rstrip('/')}{path}"
            r = requests.get(url, timeout=3)
            if r.status_code == 200 and len(r.text.strip()) > 0:
                print(f"{Fore.RED}[!] Duyarlı dosya bulundu: {url}")
                preview = r.text.strip().splitlines()[0][:100]
                scan_results["sensitive_files"].append({
                    "url": url,
                    "preview": preview
                })
                if "APP_KEY" in r.text or "DB_PASSWORD" in r.text:
                    scan_results["critical_leaks"].append({
                        "url": url,
                        "keywords": ["APP_KEY", "DB_PASSWORD"]
                    })
        except:
            pass

def test_reflected_xss(url):
    payload = "<script>alert(1)</script>"
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in qs:
        qs[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        try:
            res = requests.get(test_url, timeout=5)
            if payload in res.text:
                print(f"{Fore.RED}[XSS] Reflected XSS bulundu: {test_url}")
                scan_results["xss_vulns"].append(test_url)
        except:
            continue

def test_lfi(url):
    payload = "../../../../etc/passwd"
    if "?" not in url:
        return
    try:
        test_url = url + payload
        res = requests.get(test_url, timeout=5)
        if "root:x:" in res.text:
            print(f"{Fore.RED}[LFI] Yerel dosya içerme açığı bulundu: {test_url}")
            scan_results["lfi_vulns"].append(test_url)
    except:
        pass

def analyze_traffic(port=None, custom_filter=None, pcap_output=None):
    if custom_filter:
        bpf_filter = custom_filter
    elif port:
        bpf_filter = f"tcp port {port}"
    else:
        bpf_filter = "ip"

    print(f"{Fore.CYAN}[i] Trafik dinleniyor. Filtre: {bpf_filter}")
    packets = []

    def packet_callback(pkt):
        print(f"{Fore.MAGENTA}[PACKET] {pkt.summary()}")
        packets.append(pkt)

    try:
        sniff(filter=bpf_filter, prn=packet_callback, store=True)
    except KeyboardInterrupt:
        print("\n[i] Trafik dinleme sonlandırıldı.")
        if pcap_output:
            wrpcap(pcap_output, packets)
            print(f"{Fore.GREEN}[✓] Trafik kaydedildi: {pcap_output}")

def export_results(filename):
    try:
        if filename.endswith(".json"):
            with open(filename, "w") as f:
                json.dump(scan_results, f, indent=2)
        elif filename.endswith(".txt"):
            with open(filename, "w") as f:
                for key, items in scan_results.items():
                    f.write(f"{key.upper()}:\n")
                    for item in items:
                        f.write(f"- {item}\n")
        print(f"{Fore.GREEN}[✓] Sonuçlar kaydedildi: {filename}")
    except Exception as e:
        print(f"[X] Rapor kaydedilemedi: {e}")

def scan_web(target, wordlist=None):
    url = validate_url(target)
    try:
        r = requests.get(url, timeout=5)
        print(f"[i] {url} erişildi. HTTP {r.status_code}")
    except:
        print(f"[X] {url} erişilemiyor")
        return

    discover_urls(url, wordlist)
    check_sensitive_files(url)

    for u in scan_results["discovered_urls"]:
        test_reflected_xss(u)
        test_lfi(u)

def main():
    parser = argparse.ArgumentParser(description="LunisecX - OpenBash Pentesting Tool")
    parser.add_argument("-n", "--network", help="Ağ taraması yap (IP/CIDR)")
    parser.add_argument("-w", "--web", help="Web uygulaması taraması")
    parser.add_argument("--wordlist", help="URL keşfi için wordlist")
    parser.add_argument("--ports", help="Port aralığı (örn: 1-1000)")
    parser.add_argument("--udp", action="store_true", help="UDP port taraması yap")
    parser.add_argument("-t", "--traffic", type=int, help="Trafik analizi için port")
    parser.add_argument("--filter", help="BPF filtresi (örn: 'tcp port 80')")
    parser.add_argument("--pcap", help="PCAP dosyası adı")
    parser.add_argument("--output", help="Sonuçları kaydet (.json/.txt)")
    parser.add_argument("--version", action="version", version="LunisecX v1.0")

    args = parser.parse_args()

    if args.network:
        scan_network(args.network, args.ports, args.udp)
    if args.web:
        scan_web(args.web, args.wordlist)
    if args.traffic:
        analyze_traffic(args.traffic, args.filter, args.pcap)
    if args.output:
        export_results(args.output)

if __name__ == "__main__":
    main()
