# 🛡️ Python Cybersecurity Projects — Inlighn Tech Internship

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red?style=for-the-badge&logo=hackthebox&logoColor=white)
![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-blue?style=for-the-badge)

**A comprehensive portfolio of 9 cybersecurity projects spanning offensive and defensive security disciplines**

[Projects](#-projects-overview) • [Tools](#-tools--technologies) • [Repositories](#-github-repositories) • [Contact](#-author)

</div>

---

## 📋 About This Repository

This repository documents the complete set of cybersecurity projects developed during my internship at **Inlighn Tech** (May 2025). Each project explores a distinct area of ethical hacking, network security, or defensive operations, built primarily in Python or with industry-standard security tools.

> ⚠️ **Ethical Use Notice:** All tools were designed and tested exclusively on systems I own or have explicit permission to access. These tools are intended for authorized security testing and educational purposes only.

---

## 📊 Internship at a Glance

| Metric | Value |
|--------|-------|
| 🎯 **Total Projects** | 9 (7 Python tools + 2 defensive labs) |
| 💻 **Lines of Code** | ~1,800 |
| 📚 **Key Libraries** | `socket`, `hashlib`, `itertools`, `pikepdf`, `pypdf`, `scapy`, `requests`, `threading` |
| 📦 **GitHub Repositories** | 3 (SOC Lab, Phishing Reports, Wireshark Analysis) |
| ⚔️ **Attack Techniques** | Dictionary, Brute-force, ARP/ICMP scanning, Subdomain enumeration |
| 🛡️ **Defensive Tools** | PDF Protector, Network Scanner, Port Scanner, SOC Home Lab |

---

## 🚀 Projects Overview

<table>
  <tr>
    <th>#</th>
    <th>Project</th>
    <th>Category</th>
    <th>Difficulty</th>
  </tr>
  <tr><td>1</td><td><a href="#1️⃣-port-scanner">Port Scanner</a></td><td>Network Reconnaissance</td><td>Intermediate</td></tr>
  <tr><td>2</td><td><a href="#2️⃣-password-cracker">Password Cracker</a></td><td>Cryptography</td><td>Intermediate</td></tr>
  <tr><td>3</td><td><a href="#3️⃣-pdf-protection-tool">PDF Protection Tool</a></td><td>Document Security</td><td>Beginner</td></tr>
  <tr><td>4</td><td><a href="#4️⃣-pdf-password-cracker">PDF Password Cracker</a></td><td>PDF Security</td><td>Intermediate</td></tr>
  <tr><td>5</td><td><a href="#5️⃣-network-scanner">Network Scanner</a></td><td>Network Reconnaissance</td><td>Advanced</td></tr>
  <tr><td>6</td><td><a href="#6️⃣-subdomain-enumeration-tool">Subdomain Enumeration</a></td><td>Web Recon / OSINT</td><td>Intermediate</td></tr>
  <tr><td>7</td><td><a href="#7️⃣-home-soc-lab">Home SOC Lab</a></td><td>Blue Team / SIEM</td><td>Advanced</td></tr>
  <tr><td>8</td><td><a href="#8️⃣-phishing-email-investigation">Phishing Investigation</a></td><td>Email Forensics</td><td>Intermediate</td></tr>
  <tr><td>9</td><td><a href="#9️⃣-wireshark-network-analysis">Wireshark Analysis</a></td><td>Network Forensics</td><td>Intermediate</td></tr>
</table>

---

## 1️⃣ Port Scanner

> **Multi-threaded TCP port scanner with banner grabbing**

**File:** `port_scanner.py` | **Libraries:** `socket`, `concurrent.futures`, `sys`, `datetime`

### 🎯 Objective
Build a multi-threaded TCP port scanner that identifies open ports on any target machine, retrieves the service name associated with each port, and attempts to capture banner information to identify software versions.

### ⚙️ How It Works
- Accepts target IP/hostname and port range (common 1–1024, extended 1–5000, full 1–65535, or custom)
- Resolves hostname via `socket.gethostbyname()`
- Spawns up to **200 worker threads** via `ThreadPoolExecutor` for concurrent scanning
- Uses `socket.connect_ex()` for non-blocking connection attempts
- Performs banner grabbing on open ports via HTTP HEAD requests
- Outputs results to a formatted table and timestamped text file

### 💡 Code Snippet
```python
def scan_port(host: str, port: int) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = COMMON_SERVICES.get(port, 'Unknown')
                try:
                    service = socket.getservbyport(port, 'tcp')
                except OSError:
                    pass
                banner = get_banner(sock)
                return {'port': port, 'service': service, 'banner': banner}
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None
```

### 🔑 Key Concepts
- TCP socket programming with `connect_ex()`
- Service identification via `socket.getservbyport()`
- Banner grabbing via raw HTTP HEAD probes
- Concurrent execution with `ThreadPoolExecutor`

---

## 2️⃣ Password Cracker

> **Multi-threaded hash cracker with dictionary and brute-force modes**

**File:** `password_cracker.py` | **Libraries:** `hashlib`, `itertools`, `string`, `threading`, `queue`, `argparse`

### 🎯 Objective
Crack hashed passwords using two methods: a **dictionary attack** (testing words from a wordlist) and a **brute-force attack** (generating all character combinations up to a specified length).

### 🔐 Supported Algorithms
`MD5` • `SHA-1` • `SHA-224` • `SHA-256` • `SHA-384` • `SHA-512`

### 💡 Code Snippets

**Multi-threaded dictionary worker:**
```python
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
            found.set()  # signal all threads to stop
        password_queue.task_done()
```

**Brute-force generator:**
```python
def generate_passwords(charset: str, min_len: int, max_len: int):
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield ''.join(combo)
```

### 🎯 Attack Modes
| Mode | Description | Speed |
|------|-------------|-------|
| **Dictionary** | Tests words from a wordlist file | Fast |
| **Brute-Force** | Generates all character combinations | Slower |
| **Hash Generator** | Hashes a known plaintext for testing | Instant |

---

## 3️⃣ PDF Protection Tool

> **Add AES-based password encryption to PDF files**

**File:** `pdf_protect.py` | **Install:** `pip install pypdf`

### 🎯 Objective
A command-line tool that adds AES-based password encryption to any PDF file, supporting separate **user passwords** (for opening) and **owner passwords** (for editing permissions).

### 💡 Code Snippet
```python
def protect_pdf(input_path, output_path, user_password, owner_password=None):
    in_path = validate_input_file(input_path)
    out_path = validate_output_path(output_path)
    validate_password(user_password)

    if not owner_password:
        owner_password = user_password

    reader = PdfReader(str(in_path))
    if reader.is_encrypted:
        raise ValueError('PDF is already encrypted')

    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    if reader.metadata:
        writer.add_metadata(reader.metadata)

    writer.encrypt(user_password=user_password,
                   owner_password=owner_password)

    with open(str(out_path), 'wb') as f:
        writer.write(f)
```

### ✅ Validation Features
- Verifies file exists and is a valid PDF
- Checks PDF is not already encrypted
- Confirms output directory is writable
- Enforces minimum password length (4 characters)
- Preserves original document metadata
- Reports input/output file sizes

---

## 4️⃣ PDF Password Cracker

> **Multithreaded PDF password recovery with progress tracking**

**File:** `pdf_cracker.py` | **Install:** `pip install pikepdf tqdm`

### 🎯 Objective
A multithreaded PDF password recovery tool supporting both **wordlist-based** and **brute-force** attacks, using `pikepdf` for efficient testing and `tqdm` for real-time progress visualization.

### 💡 Code Snippets

**Password testing function:**
```python
def try_password(pdf_file: str, password: str) -> str | None:
    try:
        with pikepdf.open(pdf_file, password=password):
            return password  # success — password is correct
    except pikepdf._core.PasswordError:
        return None  # wrong password
    except Exception as e:
        print(f'[WARNING] Unexpected error: {e}')
        return None
```

**Parallel cracking engine:**
```python
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    progress = tqdm(total=total, desc='Cracking', unit='pwd')
    futures = {}
    for pwd in passwords:
        if stop_event.is_set(): break
        future = executor.submit(worker, pwd)
        futures[future] = pwd

    for future in as_completed(futures):
        progress.update(1)
        result = future.result()
        if result is not None:
            found_password = result
            stop_event.set()  # cancel remaining threads
            break
```

### 📋 Usage Examples
```bash
# Wordlist attack
python pdf_cracker.py protected.pdf --wordlist wordlist.txt

# Brute-force digits
python pdf_cracker.py protected.pdf --generate --chars 0123456789 --max-length 4

# Increase thread count
python pdf_cracker.py protected.pdf --generate --max-length 3 --threads 16
```

---

## 5️⃣ Network Scanner

> **ARP + ICMP-based local network device discovery**

**File:** `network_scanner_fixed.py` | **Install:** `pip install scapy` *(requires Administrator/sudo)*

### 🎯 Objective
Discover all active devices on a subnet by combining **ICMP ping sweeps** and **ARP requests**. Retrieves IP address, MAC address, and hostname for each device.

### 💡 Code Snippets

**ICMP ping check (cross-platform):**
```python
def is_host_alive(ip: str) -> bool:
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-w', '1000', ip]
    result = subprocess.run(
        command, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=3
    )
    return result.returncode == 0
```

**ARP MAC resolution:**
```python
def get_mac_address(ip: str) -> str:
    try:
        mac = getmacbyip(ip)  # scapy fast lookup
        if mac and mac != 'ff:ff:ff:ff:ff:ff':
            return mac
    except Exception:
        pass

    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    answered, _ = scapy.srp(broadcast/arp, timeout=1, verbose=False)
    for sent, received in answered:
        return received.hwsrc
    return 'Unknown'
```

### 🔑 Key Features
- 🌐 Accepts CIDR notation (e.g., `192.168.1.0/24`)
- 🧵 Spawns one daemon thread per host for parallel scanning
- 📡 Combines ICMP ping with ARP requests
- 🔍 Performs reverse DNS lookup for hostname resolution
- 🪟 Cross-platform (Windows/Linux/macOS)

---

## 6️⃣ Subdomain Enumeration Tool

> **Multithreaded subdomain discovery via wordlist brute-forcing**

**File:** `subdomain_Enumeration_tool.py` | **Install:** `pip install requests`

### 🎯 Objective
Discover valid subdomains of a target domain by testing names from a wordlist. Tests both **HTTPS and HTTP**, recording any returning a non-5xx status code.

### 💡 Code Snippet
```python
def check_subdomain(subdomain):
    url_http = f'http://{subdomain}.{domain}'
    url_https = f'https://{subdomain}.{domain}'

    for url in [url_https, url_http]:  # try HTTPS first
        try:
            response = requests.get(url, timeout=3)
            if response.status_code < 500:
                print(f'[+] Found: {url} | Status: {response.status_code}')
                with lock:
                    discovered_subdomains.append(url)
                break
        except requests.RequestException:
            pass  # subdomain not reachable
```

### ⚡ Features
- Reads candidates from a wordlist file
- Batched threading for controlled concurrency
- Thread-safe result collection via `threading.Lock`
- Prioritizes HTTPS over HTTP
- Saves results to `discovered_subdomains.txt`

---

## 7️⃣ Home SOC Lab

> **A virtualized Security Operations Center for threat detection practice**

**🔗 Repository:** [github.com/saivineethsannithi/home-soc-lab](https://github.com/saivineethsannithi/home-soc-lab)

**Tools:** Wazuh • Sysmon • Kali Linux • Metasploit • Atomic Red Team • VirtualBox

### 🎯 Overview
A complete SOC environment built from scratch using industry-standard open-source tools, replicating the architecture of a real SOC for practicing threat detection, log analysis, and incident response workflows.

### 🏗️ Lab Architecture
- 🖥️ **VirtualBox VM Environment** — Attacker (Kali Linux) and target (Windows 10/Server) on isolated network
- 📊 **Wazuh SIEM/XDR** — Centralized log ingestion, correlation rules, and alerting on Ubuntu Server
- 🔍 **Sysmon** — Custom configuration for deep endpoint visibility (process creation, network connections, file ops)
- 🏢 **Active Directory** — Domain controller for realistic enterprise simulation
- ⚔️ **Attack Simulations** — Metasploit and Atomic Red Team for generating detection events
- 📈 **Tuned Dashboards** — Alert rules optimized to reduce false positives

---

## 8️⃣ Phishing Email Investigation

> **Real-world phishing forensics with structured incident reports**

**🔗 Repository:** [github.com/saivineethsannithi/Phishing-Email-Investigation-Reports](https://github.com/saivineethsannithi/Phishing-Email-Investigation-Reports)

**Tools:** VirusTotal • AbuseIPDB • MXToolbox • Manual Header Analysis

### 🎯 Overview
A collection of structured investigation reports analyzing real-world phishing samples, following professional incident-response methodology.

### 🔬 Investigation Workflow
1. **Header Forensics** — Tracing delivery paths, identifying forged sender fields, extracting originating IPs
2. **IOC Extraction** — Capturing malicious URLs, attachment hashes, sender domains
3. **Reputation Lookups** — VirusTotal, AbuseIPDB, MXToolbox for severity assessment
4. **Structured Reporting** — Aligned with SOC analyst escalation procedures
5. **Remediation Guidance** — Blocking rules, user communication, containment steps

---

## 9️⃣ Wireshark Network Analysis

> **Packet-level forensics and protocol investigation**

**🔗 Repository:** [github.com/saivineethsannithi/wireshark-network-analysis](https://github.com/saivineethsannithi/wireshark-network-analysis)

**Tools:** Wireshark • tcpdump • PCAP files

### 🎯 Overview
Packet capture analysis exercises using Wireshark to study network protocols and identify anomalous traffic patterns. Annotated PCAP analyses cover both common attack signatures and baseline traffic.

### 📡 Protocols Studied
`TCP/IP` • `HTTP` • `DNS` • `ARP` • `SMB` • `TLS`

### 🔍 Key Techniques Demonstrated
- Protocol-level analysis of network traffic
- Detection of **SYN flood** patterns, **ARP spoofing**, and **port scan** signatures
- Extraction of credentials transmitted in plaintext
- Identification of **C2 (command-and-control)** beaconing patterns
- Structured findings reports with timestamps and hardening recommendations

---

## 🛠️ Tools & Technologies

### 📦 Python Libraries

| Library | Type | Used In |
|---------|------|---------|
| `socket` | stdlib | Port Scanner, Network Scanner |
| `concurrent.futures` | stdlib | Port Scanner |
| `hashlib` | stdlib | Password Cracker |
| `itertools` | stdlib | Password Cracker, PDF Cracker |
| `threading` + `queue` | stdlib | Multiple projects |
| `argparse` | stdlib | CLI tools |
| `scapy` | `pip install scapy` | Network Scanner |
| `pikepdf` | `pip install pikepdf` | PDF Cracker |
| `tqdm` | `pip install tqdm` | PDF Cracker |
| `pypdf` | `pip install pypdf` | PDF Protection |
| `requests` | `pip install requests` | Subdomain Enumeration |

### 🔧 Security Tools

| Tool | Purpose |
|------|---------|
| **Wazuh** | Open-source SIEM/XDR platform |
| **Sysmon** | Windows endpoint visibility (Sysinternals) |
| **Wireshark** | Network protocol analyzer |
| **Metasploit** | Penetration testing framework |
| **Kali Linux** | Offensive security distribution |
| **VirtualBox** | Virtualization platform |

---

## 📦 GitHub Repositories

<table>
  <tr>
    <th>Repository</th>
    <th>Skills Demonstrated</th>
    <th>Tools</th>
  </tr>
  <tr>
    <td><a href="https://github.com/saivineethsannithi/home-soc-lab"><b>home-soc-lab</b></a></td>
    <td>SIEM deployment, threat detection, AD simulation, attack simulation</td>
    <td>Wazuh, Sysmon, Kali, VirtualBox, Metasploit</td>
  </tr>
  <tr>
    <td><a href="https://github.com/saivineethsannithi/Phishing-Email-Investigation-Reports"><b>Phishing-Email-Investigation-Reports</b></a></td>
    <td>Email forensics, IOC extraction, threat reporting, SOC workflows</td>
    <td>VirusTotal, AbuseIPDB, MXToolbox</td>
  </tr>
  <tr>
    <td><a href="https://github.com/saivineethsannithi/wireshark-network-analysis"><b>wireshark-network-analysis</b></a></td>
    <td>Packet analysis, protocol inspection, attack detection, PCAP review</td>
    <td>Wireshark, PCAP files, network protocols</td>
  </tr>
</table>

---

## 🎓 Key Takeaways

- 🐍 Python's standard library alone (`socket`, `hashlib`, `threading`, `itertools`) is sufficient to build powerful security tools
- 🧵 Multithreading with `ThreadPoolExecutor` and `threading.Event` enables highly efficient, stoppable parallel workloads
- 🛡️ Defensive tools are equally important as offensive tools in a security professional's portfolio
- 📋 Real-world SOC workflows require both technical skill and structured methodology
- ⚖️ All security testing must be conducted only on authorized systems — ethical practice is non-negotiable

---

## ⚠️ Legal & Ethical Disclaimer

All tools and techniques in this repository are intended for **educational purposes** and **authorized security testing** only. Users are responsible for ensuring they have explicit permission before using any of these tools against systems, networks, or applications. The author assumes no liability for misuse or damage caused by these tools.

---

## 👤 Author

**Sai Vineeth Sannithi**

🎓 *Cybersecurity Intern @ Inlighn Tech (May 2025)*

[![GitHub](https://img.shields.io/badge/GitHub-saivineethsannithi-181717?style=for-the-badge&logo=github)](https://github.com/saivineethsannithi)

---

<div align="center">

**⭐ If you find this portfolio useful, consider starring the repositories!**

*Built with 🐍 Python, ☕ caffeine, and a passion for cybersecurity*

</div>
