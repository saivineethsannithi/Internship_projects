"""
Password Cracker Using Python

Cracks hashed passwords using dictionary or brute-force attacks.
Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.

USAGE:
  python password_cracker.py
  
  Or with arguments:
  python password_cracker.py --hash <hash> --type sha256 --wordlist wordlist.txt
  python password_cracker.py --hash <hash> --type md5 --brute --min 1 --max 4
"""

import hashlib
import itertools
import string
import argparse
import threading
import queue
import sys
import time
from datetime import datetime


# ─────────────────────────────────────────────
# Supported hash algorithms
# ─────────────────────────────────────────────
SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]


def hash_password(password: str, algorithm: str) -> str:
    """Hash a plain-text password with the given algorithm."""
    h = hashlib.new(algorithm)
    h.update(password.encode("utf-8"))
    return h.hexdigest()


def verify_hash_format(hash_str: str, algorithm: str) -> bool:
    """Check if a hash string matches the expected length for an algorithm."""
    expected_lengths = {
        "md5": 32, "sha1": 40, "sha224": 56,
        "sha256": 64, "sha384": 96, "sha512": 128,
    }
    return len(hash_str) == expected_lengths.get(algorithm, 0)


# ─────────────────────────────────────────────
# Dictionary Attack
# ─────────────────────────────────────────────
def dictionary_attack(target_hash: str, algorithm: str,
                      wordlist_path: str, num_threads: int = 4) -> str | None:
    """
    Attempt to crack a hash using a wordlist file.
    Uses multithreading for speed.
    """
    # Load wordlist
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Wordlist file not found: {wordlist_path}")
        return None

    total = len(words)
    print(f"\n[*] Dictionary attack | {total:,} words | {num_threads} threads")
    print(f"[*] Algorithm: {algorithm.upper()} | Target: {target_hash[:20]}...")

    found = threading.Event()
    result_container = [None]
    attempts_counter = [0]
    lock = threading.Lock()

    password_queue = queue.Queue()
    for word in words:
        password_queue.put(word)

    start_time = time.time()

    def worker():
        while not found.is_set():
            try:
                word = password_queue.get(timeout=0.1)
            except queue.Empty:
                break
            with lock:
                attempts_counter[0] += 1
            if hash_password(word, algorithm) == target_hash:
                result_container[0] = word
                found.set()
            password_queue.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(num_threads)]
    for t in threads:
        t.start()

    # Progress display
    while not found.is_set() and any(t.is_alive() for t in threads):
        elapsed = time.time() - start_time
        with lock:
            done = attempts_counter[0]
        rate = done / elapsed if elapsed > 0 else 0
        pct = (done / total) * 100 if total > 0 else 0
        print(f"\r  Tried: {done:>7,}/{total:,} ({pct:5.1f}%)  Speed: {rate:,.0f}/s", end="", flush=True)
        time.sleep(0.2)

    for t in threads:
        t.join()

    elapsed = time.time() - start_time
    print(f"\r  Tried: {attempts_counter[0]:>7,}/{total:,} (100.0%)  Time: {elapsed:.2f}s        ")

    return result_container[0]


# ─────────────────────────────────────────────
# Brute-force Attack
# ─────────────────────────────────────────────
def generate_passwords(charset: str, min_len: int, max_len: int):
    """Generator that yields all character combinations within a length range."""
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


def brute_force_attack(target_hash: str, algorithm: str,
                       charset: str, min_len: int, max_len: int,
                       num_threads: int = 4) -> str | None:
    """
    Attempt to crack a hash via brute-force generation.
    """
    # Estimate total combinations for display
    total_estimate = sum(len(charset) ** l for l in range(min_len, max_len + 1))
    print(f"\n[*] Brute-force attack | Charset: {len(charset)} chars | "
          f"Length: {min_len}–{max_len} | ~{total_estimate:,} combinations")
    print(f"[*] Algorithm: {algorithm.upper()} | Target: {target_hash[:20]}...")

    if total_estimate > 10_000_000:
        confirm = input(f"  [!] This will try ~{total_estimate:,} combinations. Continue? [y/N]: ").strip().lower()
        if confirm != "y":
            print("  Brute-force cancelled.")
            return None

    found = threading.Event()
    result_container = [None]
    attempts_counter = [0]
    lock = threading.Lock()

    pw_queue = queue.Queue(maxsize=10000)
    start_time = time.time()

    def producer():
        """Fill the queue with generated passwords."""
        for pw in generate_passwords(charset, min_len, max_len):
            if found.is_set():
                break
            pw_queue.put(pw)
        # Signal workers to stop
        for _ in range(num_threads):
            pw_queue.put(None)

    def worker():
        while not found.is_set():
            pw = pw_queue.get()
            if pw is None:
                break
            with lock:
                attempts_counter[0] += 1
            if hash_password(pw, algorithm) == target_hash:
                result_container[0] = pw
                found.set()

    prod_thread = threading.Thread(target=producer, daemon=True)
    prod_thread.start()

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(num_threads)]
    for w in workers:
        w.start()

    # Progress display
    while not found.is_set() and (prod_thread.is_alive() or any(w.is_alive() for w in workers)):
        elapsed = time.time() - start_time
        with lock:
            done = attempts_counter[0]
        rate = done / elapsed if elapsed > 0 else 0
        print(f"\r  Tried: {done:>10,}  Speed: {rate:>10,.0f}/s  Elapsed: {elapsed:.1f}s", end="", flush=True)
        time.sleep(0.3)

    prod_thread.join()
    for w in workers:
        w.join()

    elapsed = time.time() - start_time
    print(f"\r  Tried: {attempts_counter[0]:>10,}  Time: {elapsed:.2f}s                              ")

    return result_container[0]


# ─────────────────────────────────────────────
# Helper: Hash a password (utility)
# ─────────────────────────────────────────────
def hash_utility():
    """Interactive helper to generate a hash from a plain-text password."""
    print("\n  ── Hash Generator ──")
    pw = input("  Enter password to hash: ").strip()
    algo = input(f"  Algorithm [{'/'.join(SUPPORTED_ALGORITHMS)}]: ").strip().lower()
    if algo not in SUPPORTED_ALGORITHMS:
        print("  [ERROR] Unsupported algorithm.")
        return
    hashed = hash_password(pw, algo)
    print(f"\n  Password : {pw}")
    print(f"  Algorithm: {algo.upper()}")
    print(f"  Hash     : {hashed}\n")


# ─────────────────────────────────────────────
# Interactive menu
# ─────────────────────────────────────────────
def interactive_menu():
    """Run the tool in interactive (menu-driven) mode."""
    print("=" * 60)
    print("       PASSWORD CRACKER  —  Inlighn Tech")
    print("=" * 60)
    print()
    print("  [1] Dictionary Attack  (use a wordlist)")
    print("  [2] Brute-Force Attack (generate combinations)")
    print("  [3] Hash Generator     (hash a known password)")
    print("  [0] Exit")
    print()
    choice = input("  Select option: ").strip()

    if choice == "0":
        print("  Goodbye!")
        sys.exit(0)

    if choice == "3":
        hash_utility()
        return

    # Collect common inputs
    target_hash = input("\n  Enter target hash: ").strip().lower()
    print(f"  Algorithms: {', '.join(SUPPORTED_ALGORITHMS)}")
    algorithm = input("  Hash algorithm: ").strip().lower()

    if algorithm not in SUPPORTED_ALGORITHMS:
        print("  [ERROR] Unsupported algorithm.")
        return

    if not verify_hash_format(target_hash, algorithm):
        print(f"  [WARNING] Hash length doesn't match {algorithm.upper()}. Proceeding anyway.")

    threads = input("  Number of threads [default 4]: ").strip()
    num_threads = int(threads) if threads.isdigit() else 4

    result = None

    # ── Dictionary Attack ──
    if choice == "1":
        wordlist = input("  Path to wordlist file: ").strip()
        result = dictionary_attack(target_hash, algorithm, wordlist, num_threads)

    # ── Brute-Force Attack ──
    elif choice == "2":
        print("\n  Charset options:")
        print("  [1] Lowercase letters only  (a-z)")
        print("  [2] Letters + digits        (a-z, 0-9)")
        print("  [3] Letters + digits + symbols")
        print("  [4] Digits only             (0-9)")
        print("  [5] Custom charset")
        cs_choice = input("  Choose charset: ").strip()

        charsets = {
            "1": string.ascii_lowercase,
            "2": string.ascii_lowercase + string.digits,
            "3": string.ascii_lowercase + string.digits + string.punctuation,
            "4": string.digits,
        }

        if cs_choice in charsets:
            charset = charsets[cs_choice]
        elif cs_choice == "5":
            charset = input("  Enter custom charset (e.g. abc123): ").strip()
        else:
            print("  [ERROR] Invalid choice.")
            return

        try:
            min_len = int(input("  Minimum password length: ").strip())
            max_len = int(input("  Maximum password length: ").strip())
            if min_len < 1 or max_len < min_len:
                raise ValueError
        except ValueError:
            print("  [ERROR] Invalid length range.")
            return

        result = brute_force_attack(target_hash, algorithm, charset,
                                    min_len, max_len, num_threads)
    else:
        print("  [ERROR] Invalid option.")
        return

    # ── Show result ──
    print()
    if result:
        print(f"  ✅ PASSWORD FOUND: {result}")
        print(f"  Hash     : {target_hash}")
        print(f"  Algorithm: {algorithm.upper()}")
    else:
        print("  ❌ Password NOT found with the given settings.")
    print()


# ─────────────────────────────────────────────
# CLI argument mode
# ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(description="Password Cracker — Inlighn Tech")
    parser.add_argument("--hash",      help="Target hash to crack")
    parser.add_argument("--type",      help="Hash algorithm", choices=SUPPORTED_ALGORITHMS)
    parser.add_argument("--wordlist",  help="Path to wordlist file (dictionary attack)")
    parser.add_argument("--brute",     action="store_true", help="Use brute-force attack")
    parser.add_argument("--min",       type=int, default=1,  help="Min password length (brute)")
    parser.add_argument("--max",       type=int, default=4,  help="Max password length (brute)")
    parser.add_argument("--charset",   default="lower",
                        choices=["lower", "digits", "alnum", "all"],
                        help="Charset for brute-force")
    parser.add_argument("--threads",   type=int, default=4,  help="Number of threads")
    return parser.parse_args()


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    args = parse_args()

    # If CLI arguments provided, run directly
    if args.hash and args.type:
        target = args.hash.lower()
        algo   = args.type

        if args.wordlist:
            result = dictionary_attack(target, algo, args.wordlist, args.threads)
        elif args.brute:
            cs_map = {
                "lower":  string.ascii_lowercase,
                "digits": string.digits,
                "alnum":  string.ascii_lowercase + string.digits,
                "all":    string.ascii_lowercase + string.digits + string.punctuation,
            }
            charset = cs_map[args.charset]
            result = brute_force_attack(target, algo, charset,
                                        args.min, args.max, args.threads)
        else:
            print("[ERROR] Specify --wordlist or --brute")
            sys.exit(1)

        if result:
            print(f"\n✅ PASSWORD FOUND: {result}")
        else:
            print("\n❌ Password not found.")
    else:
        # Interactive menu mode
        try:
            while True:
                interactive_menu()
                again = input("  Run again? [y/N]: ").strip().lower()
                if again != "y":
                    break
            print("  Goodbye!\n")
        except KeyboardInterrupt:
            print("\n\n  Interrupted. Goodbye!\n")
            sys.exit(0)
