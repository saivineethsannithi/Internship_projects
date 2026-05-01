"""
Port Scanner Using Python
By: Inlighn Tech - Student Implementation
Scans open ports on a target machine using multithreading.
USAGE: python port_scanner.py
"""

import socket
import concurrent.futures
import sys
from datetime import datetime


# ─────────────────────────────────────────────
# Common services mapped to port numbers
# ─────────────────────────────────────────────
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def get_banner(sock: socket.socket) -> str:
    """Try to grab a service banner from an open socket."""
    try:
        sock.settimeout(2)
        # Send a generic probe and read response
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        # Return only the first line of the banner
        return banner.splitlines()[0] if banner else "N/A"
    except Exception:
        return "N/A"


def scan_port(host: str, port: int) -> dict | None:
    """
    Attempt a TCP connection to host:port.
    Returns a result dict if open, None if closed/filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = COMMON_SERVICES.get(port, "Unknown")
                # Try to resolve service name from system DB
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    pass
                banner = get_banner(sock)
                return {"port": port, "service": service, "banner": banner}
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def resolve_host(host: str) -> str | None:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def print_banner():
    print("=" * 65)
    print("         PORT SCANNER  —  Inlighn Tech")
    print("=" * 65)


def print_results(results: list[dict], host: str, ip: str,
                  start_port: int, end_port: int, elapsed: float):
    """Print scan results in a structured table."""
    print(f"\n{'─'*65}")
    print(f"  Target  : {host}  ({ip})")
    print(f"  Range   : {start_port} – {end_port}")
    print(f"  Scanned : {end_port - start_port + 1} ports in {elapsed:.2f}s")
    print(f"  Open    : {len(results)} port(s) found")
    print(f"{'─'*65}")

    if not results:
        print("  No open ports found in the specified range.")
    else:
        print(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER'}")
        print(f"  {'─'*6}  {'─'*13}  {'─'*35}")
        for r in sorted(results, key=lambda x: x["port"]):
            banner = r["banner"][:40] + "…" if len(r["banner"]) > 40 else r["banner"]
            print(f"  {r['port']:<8} {r['service']:<15} {banner}")

    print(f"{'─'*65}\n")


def run_scanner(host: str, start_port: int, end_port: int,
                max_threads: int = 200):
    """Main scanning function using ThreadPoolExecutor."""
    ip = resolve_host(host)
    if not ip:
        print(f"[ERROR] Cannot resolve host: {host}")
        sys.exit(1)

    print(f"\n[*] Starting scan on {host} ({ip}) at {datetime.now().strftime('%H:%M:%S')}")
    print(f"[*] Port range: {start_port} – {end_port}  |  Threads: {max_threads}\n")

    open_ports = []
    total = end_port - start_port + 1
    scanned = 0

    start_time = datetime.now()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port): port
            for port in range(start_port, end_port + 1)
        }

        for future in concurrent.futures.as_completed(futures):
            scanned += 1
            # Live progress every 100 ports
            if scanned % 100 == 0 or scanned == total:
                pct = (scanned / total) * 100
                print(f"\r  Progress: {scanned}/{total} ({pct:.1f}%)", end="", flush=True)

            result = future.result()
            if result:
                open_ports.append(result)
                print(f"\n  [OPEN] Port {result['port']} — {result['service']}")

    elapsed = (datetime.now() - start_time).total_seconds()
    print_results(open_ports, host, ip, start_port, end_port, elapsed)
    return open_ports


def get_user_input() -> tuple[str, int, int]:
    """Collect scan parameters from the user."""
    print_banner()
    print()

    host = input("  Enter target IP or hostname: ").strip()
    if not host:
        print("[ERROR] Host cannot be empty.")
        sys.exit(1)

    print()
    print("  Port range options:")
    print("  [1] Common ports only  (1–1024)")
    print("  [2] Extended range     (1–5000)")
    print("  [3] Full range         (1–65535)")
    print("  [4] Custom range")
    choice = input("\n  Choose option [1-4]: ").strip()

    if choice == "1":
        return host, 1, 1024
    elif choice == "2":
        return host, 1, 5000
    elif choice == "3":
        print("  [!] Full scan may take several minutes.")
        return host, 1, 65535
    elif choice == "4":
        try:
            start = int(input("  Start port: ").strip())
            end   = int(input("  End port  : ").strip())
            if not (1 <= start <= end <= 65535):
                raise ValueError
            return host, start, end
        except ValueError:
            print("[ERROR] Invalid port range.")
            sys.exit(1)
    else:
        print("[ERROR] Invalid choice.")
        sys.exit(1)


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        host, start_port, end_port = get_user_input()
        results = run_scanner(host, start_port, end_port)

        # Save results to file
        save = input("  Save results to file? [y/N]: ").strip().lower()
        if save == "y":
            filename = f"scan_{host.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, "w") as f:
                f.write(f"Port Scan Results\n")
                f.write(f"Host   : {host}\n")
                f.write(f"Time   : {datetime.now()}\n")
                f.write(f"{'─'*40}\n")
                for r in sorted(results, key=lambda x: x["port"]):
                    f.write(f"Port {r['port']:5} | {r['service']:15} | {r['banner']}\n")
            print(f"  [✓] Results saved to {filename}")

        print("\n  Scan complete. Goodbye!\n")

    except KeyboardInterrupt:
        print("\n\n  [!] Scan interrupted by user.")
        sys.exit(0)
