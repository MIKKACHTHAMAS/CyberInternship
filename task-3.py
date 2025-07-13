import argparse
import socket
import threading
import queue
import time
import requests
from bs4 import BeautifulSoup
import itertools
import sys
from urllib.parse import urljoin

class PortScanner:
    def __init__(self, target, ports, max_threads=100):
        self.target = target
        self.ports = ports
        self.max_threads = max_threads
        self.open_ports = []
        self.queue = queue.Queue()
        self.lock = threading.Lock()

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    with self.lock:
                        self.open_ports.append(port)
        except Exception as e:
            pass

    def worker(self):
        while True:
            port = self.queue.get()
            self.scan_port(port)
            self.queue.task_done()

    def run_scan(self):
        print(f"[*] Scanning {self.target}...")
        start_time = time.time()

        # Create and start worker threads
        for _ in range(self.max_threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()

        # Add ports to queue
        for port in self.ports:
            self.queue.put(port)

        # Wait for all ports to be scanned
        self.queue.join()

        # Print results
        print("\n[+] Scan completed in {:.2f} seconds".format(time.time() - start_time))
        if self.open_ports:
            print("[+] Open ports:")
            for port in sorted(self.open_ports):
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                print(f"  - {port}/tcp ({service})")
        else:
            print("[-] No open ports found")

class BruteForcer:
    def __init__(self, target, username=None, max_threads=10):
        self.target = target
        self.username = username
        self.max_threads = max_threads
        self.queue = queue.Queue()
        self.found = False
        self.lock = threading.Lock()

    def worker(self):
        while not self.queue.empty() and not self.found:
            password = self.queue.get()
            try:
                if self.try_login(password):
                    with self.lock:
                        self.found = True
                        print(f"\n[+] Found credentials: {self.username}:{password}")
            except Exception as e:
                pass
            finally:
                self.queue.task_done()

    def try_login(self, password):
        # This is a template method - should be overridden for specific services
        return False

    def run_bruteforce(self, passwords):
        print(f"[*] Starting brute force attack on {self.target}")
        start_time = time.time()

        # Add passwords to queue
        for password in passwords:
            self.queue.put(password)

        # Create and start worker threads
        for _ in range(self.min(self.max_threads, len(passwords))):
            t = threading.Thread(target=self.worker)
            t.start()

        # Wait for all passwords to be tried
        self.queue.join()

        if not self.found:
            print("\n[-] No valid credentials found")
        print("[*] Attack completed in {:.2f} seconds".format(time.time() - start_time))

class HTTPBruteForcer(BruteForcer):
    def __init__(self, target, login_url, username_field, password_field, username=None, max_threads=10):
        super().__init__(target, username, max_threads)
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PentestToolkit/1.0'
        })

    def try_login(self, password):
        data = {
            self.username_field: self.username,
            self.password_field: password
        }
        response = self.session.post(self.login_url, data=data, timeout=5)
        return "invalid" not in response.text.lower() and "login failed" not in response.text.lower()

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PentestToolkit/1.0'
        })
        self.vulnerabilities = []

    def scan_xss(self):
        test_urls = [
            f"{self.target}/search?q=<script>alert(1)</script>",
            f"{self.target}/contact?email=\"onmouseover=\"alert(1)"
        ]
        for url in test_urls:
            try:
                response = self.session.get(url, timeout=5)
                if "<script>alert(1)</script>" in response.text or '"onmouseover="alert(1)' in response.text:
                    self.vulnerabilities.append({
                        'type': 'XSS',
                        'url': url,
                        'severity': 'High'
                    })
            except:
                continue

    def scan_sqli(self):
        test_urls = [
            f"{self.target}/product?id=1'",
            f"{self.target}/user?name=admin'--"
        ]
        for url in test_urls:
            try:
                response = self.session.get(url, timeout=5)
                if "sql" in response.text.lower() and "error" in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': url,
                        'severity': 'Critical'
                    })
            except:
                continue

    def scan(self):
        print(f"[*] Scanning {self.target} for vulnerabilities")
        self.scan_xss()
        self.scan_sqli()
        
        if self.vulnerabilities:
            print("\n[+] Found vulnerabilities:")
            for vuln in self.vulnerabilities:
                print(f"  - {vuln['type']} ({vuln['severity']}) at {vuln['url']}")
        else:
            print("\n[-] No common vulnerabilities found")

class PentestToolkit:
    def __init__(self):
        self.modules = {
            'portscan': self.run_portscan,
            'bruteforce': self.run_bruteforce,
            'vulnscan': self.run_vulnscan
        }

    def run_portscan(self, args):
        target = args.target
        if args.ports == 'common':
            ports = range(1, 1025)
        elif args.ports == 'all':
            ports = range(1, 65536)
        else:
            ports = [int(p) for p in args.ports.split(',')]
        
        scanner = PortScanner(target, ports, max_threads=args.threads)
        scanner.run_scan()

    def run_bruteforce(self, args):
        target = args.target
        login_url = args.login_url
        username_field = args.username_field
        password_field = args.password_field
        username = args.username
        wordlist = args.wordlist
        
        try:
            with open(wordlist, 'r') as f:
                passwords = [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            print(f"[-] Error: Wordlist file {wordlist} not found")
            return
        
        bruteforcer = HTTPBruteForcer(
            target=target,
            login_url=login_url,
            username_field=username_field,
            password_field=password_field,
            username=username,
            max_threads=args.threads
        )
        
        bruteforcer.run_bruteforce(passwords)

    def run_vulnscan(self, args):
        target = args.target
        scanner = VulnerabilityScanner(target)
        scanner.scan()

    def main(self):
        parser = argparse.ArgumentParser(description="Penetration Testing Toolkit")
        subparsers = parser.add_subparsers(dest='command', required=True)
        
        # Port scanner command
        portscan_parser = subparsers.add_parser('portscan', help='Port scanning module')
        portscan_parser.add_argument('target', help='Target IP or hostname')
        portscan_parser.add_argument('-p', '--ports', default='common',
                                   help='Ports to scan (common:1-1024, all:1-65535, or comma-separated list)')
        portscan_parser.add_argument('-t', '--threads', type=int, default=100,
                                   help='Number of threads to use')
        
        # Brute force command
        bruteforce_parser = subparsers.add_parser('bruteforce', help='Password brute force module')
        bruteforce_parser.add_argument('target', help='Target website URL')
        bruteforce_parser.add_argument('login_url', help='Login page URL')
        bruteforce_parser.add_argument('username_field', help='Username form field name')
        bruteforce_parser.add_argument('password_field', help='Password form field name')
        bruteforce_parser.add_argument('wordlist', help='Path to password wordlist')
        bruteforce_parser.add_argument('-u', '--username', required=True, help='Username to test')
        bruteforce_parser.add_argument('-t', '--threads', type=int, default=10,
                                     help='Number of threads to use')
        
        # Vulnerability scanner command
        vulnscan_parser = subparsers.add_parser('vulnscan', help='Vulnerability scanning module')
        vulnscan_parser.add_argument('target', help='Target website URL')
        
        args = parser.parse_args()
        
        if args.command in self.modules:
            self.modules[args.command](args)
        else:
            print(f"[-] Unknown command: {args.command}")

if __name__ == "__main__":
    toolkit = PentestToolkit()
    toolkit.main()