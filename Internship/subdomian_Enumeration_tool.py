import requests
import threading
import argparse

# Argument parser
parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
parser.add_argument("-d", "--domain", required=True, help="Target domain (example.com)")
parser.add_argument("-w", "--wordlist", required=True, help="Path to subdomain wordlist")
parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default=20)")

args = parser.parse_args()

domain = args.domain
wordlist = args.wordlist
thread_count = args.threads

discovered_subdomains = []
lock = threading.Lock()

def check_subdomain(subdomain):
    url_http = f"http://{subdomain}.{domain}"
    url_https = f"https://{subdomain}.{domain}"

    for url in [url_https, url_http]:
        try:
            response = requests.get(url, timeout=3)
            if response.status_code < 500:
                print(f"[+] Found: {url} | Status: {response.status_code}")
                with lock:
                    discovered_subdomains.append(url)
                break
        except requests.RequestException:
            pass

def main():
    with open(wordlist) as f:
        subdomains = f.read().splitlines()

    threads = []

    for sub in subdomains:
        t = threading.Thread(target=check_subdomain, args=(sub,))
        t.start()
        threads.append(t)

        if len(threads) >= thread_count:
            for thread in threads:
                thread.join()
            threads = []

    for thread in threads:
        thread.join()

    with open("discovered_subdomains.txt", "w") as f:
        for sub in discovered_subdomains:
            f.write(sub + "\n")

    print("\nEnumeration complete. Results saved to discovered_subdomains.txt")

if __name__ == "__main__":
    main()
