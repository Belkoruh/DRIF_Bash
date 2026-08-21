# ⚡ DFIR Bash - Linux Digital Forensics & Incident Response Suite

```text
  _____  ______ _____ _____    ____             _     
 |  __ \|  ____|_   _|  __ \  |  _ \           | |    
 | |  | | |__    | | | |__) | | |_) | __ _ ___| |__  
 | |  | |  __|   | | |  _  /  |  _ < / _` / __| '_ \ 
 | |__| | |     _| |_| | \ \  | |_) | (_| \__ \ | | |
 |_____/|_|    |_____|_|  \_\ |____/ \__,_|___/_| |_|
```

> **Author**: [Bellk0ruh](https://github.com/Bellk0ruh)  
> **License**: [BSD 3-Clause License](file:///d:/scripts/bash/DFIR_bash/LICENSE)  
> **Target OS**: Linux (Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Fedora, Arch, SUSE, Alpine)  
> **Architecture**: Inspired by `DRIF_Powershell` and engineered strictly following **RFC 3227**, **ISO/IEC 27037**, and the **MITRE ATT&CK® for Linux** framework.

---

## 📋 Table of Contents

- [Overview & Philosophy](#-overview--philosophy)
- [Key Forensic Principles](#-key-forensic-principles)
- [Project Architecture](#-project-architecture)
- [Quick Start Guide](#-quick-start-guide)
- [Command Line Options](#-command-line-options)
- [Module Directory Reference](#-module-directory-reference)
  - [1. Master Orchestrator (`DFIR-Script.sh`)](#1-master-orchestrator-dfir-scriptsh)
  - [2. Acquisition Modules (`Acquisition/`)](#2-acquisition-modules-acquisition)
  - [3. Analysis & Threat Hunting Modules (`Analysis/`)](#3-analysis--threat-hunting-modules-analysis)
  - [4. Emergency Containment & Live Auditing (`Containment/`)](#4-emergency-containment--live-auditing-containment)
- [Interactive Standalone HTML Forensic Dashboard](#-interactive-standalone-html-forensic-dashboard)
- [SIEM-Ready Normalized CSV Schemas](#-siem-ready-normalized-csv-schemas)
- [Threat Intelligence & STIX 2.1 / MISP Export](#-threat-intelligence--stix-21--misp-export)
- [MITRE ATT&CK® Matrix for Linux](#-mitre-attck-matrix-for-linux)
- [Chain of Custody & Best Practices](#-chain-of-custody--best-practices)
- [License & Disclaimer](#-license--disclaimer)

---

## 🔍 Overview & Philosophy

**DFIR Bash** is a modular, high-performance digital forensics, incident response triage, and threat hunting suite tailored for modern Linux endpoints, cloud workloads, and enterprise servers. 

It automates end-to-end evidence acquisition, memory extraction, stealth rootkit detection, and forensic analysis while strictly guaranteeing **100% Read-Only / Non-Destructive** execution on the target host.

---

## 🛡️ Key Forensic Principles

1. **RFC 3227 Order of Volatility**:
   - Captures evidence strictly by volatility rank: Registers/RAM & active sockets $\rightarrow$ Processes & `/proc` state $\rightarrow$ Kernel filters/eBPF $\rightarrow$ Routing/ARP cache $\rightarrow$ Ephemeral staging $\rightarrow$ Persistent disk logs and filesystem metadata.
2. **Forensic Soundness & Zero-Footprint**:
   - **Strict Read-Only Guarantee**: Acquisition and analysis modules never modify, truncate, or touch target files or system services.
   - **MACB Timestamp Preservation**: Uses `cp -p` and `tar --atime-preserve` so that reading files during evidence collection does not modify last access times (*atime*).
   - **Volatile Deleted Binary Recovery**: Automatically detects and extracts memory-mapped executables unlinked from disk via `/proc/[pid]/exe` without terminating the process.
3. **Chain of Custody & Cryptographic Verification**:
   - Calculates **SHA-256 hashes** for every single acquired file into `checksums.sha256`.
   - Generates a machine-readable `manifest.json` documenting host identity, kernel build, UTC timestamps, user context, and collection checksums.
   - Compresses evidence into a sealed `.tar.gz` archive with a detached `.sha256` digital seal.
4. **Hermetic Separation with Containment**:
   - The master orchestrator only runs read-only acquisition and analysis modules. Active containment tools (firewall isolation, user suspension, process termination) are isolated in `Containment/` and must be explicitly invoked by an analyst.

---

## 🏛 Project Architecture

```text
d:\scripts\bash\DFIR_bash/
├── DFIR-Script.sh                              # Master Orchestrator & Automated Triage Engine
├── LICENSE                                     # BSD 3-Clause License
├── README.md                                   # Master Documentation & MITRE ATT&CK Mapping
│
├── Acquisition/                                # 18 Modular Forensic Collectors (Read-Only)
│   ├── CollectNetworkTriage.sh                 # Sockets (TCP/UDP/RAW), Routes, ARP, DNS, iptables/nftables
│   ├── CollectExecutionArtifacts.sh           # Process tree, /proc/[pid]/*, environ, maps, memfd, deleted binaries
│   ├── CollectPersistence.sh                  # Systemd services/timers, Cron, At, ld.so.preload, shell hooks, PAM
│   ├── CollectUserActivity.sh                 # /etc/passwd, /etc/shadow audit, sudoers, wtmp/btmp, command histories
│   ├── CollectSSHArtifacts.sh                 # authorized_keys, known_hosts, OpenSSH configs, key inventories
│   ├── CollectBrowserArtifacts.sh             # SQLite history, downloads, cookies for Chrome, Firefox, Brave, Edge, Tor
│   ├── CollectAIArtifacts.sh                  # Local LLMs (Ollama), Claude, Cursor, Copilot, API token presence
│   ├── CollectSystemLogs.sh                   # journalctl with time-window, auth.log, auditd, dmesg, applications
│   ├── CollectSecuritySubsystems.sh           # AppArmor profiles & denials, SELinux AVCs, kernel mitigations (ASLR, Yama)
│   ├── CollectHardwareAndContainers.sh        # USB devices (lsusb), PCI (lspci), mounts (fstab), Docker, Podman, K8s
│   ├── CollectVPNAndTunnelingArtifacts.sh     # WireGuard, OpenVPN, Tailscale, ZeroTier, Cloudflared, Ngrok, Chisel
│   ├── CollectCloudMetadata.sh                # AWS EC2 (IMDSv2), Azure VM IMDS, GCP metadata, Cloud-Init logs
│   ├── CollectWebserverAndDatabaseArtifacts.sh# Nginx, Apache, SSL certs, Redis unauth audit, MySQL, PostgreSQL
│   ├── CollectEBPFArtifacts.sh                # Loaded eBPF programs, maps, attached links, XDP, /sys/fs/bpf objects
│   ├── CollectDeveloperEcosystem.sh           # NPM (.npmrc tokens), Python (.pypirc, .pth injection), Cargo, Git hooks
│   ├── CollectMailArtifacts.sh                # Postfix, Exim, Sendmail, active mail queues (mailq), /etc/aliases
│   ├── CollectDesktopArtifacts.sh             # recently-used.xbel, Linux Trash (~/.local/share/Trash), thumbnails
│   ├── DumpProcessMemory.sh                   # Surgical virtual memory dumping for specific suspect PIDs
│   ├── CollectFileSystemArtifacts.sh          # SUID/SGID (GTFOBins), getcap, /tmp staging, immutable flags (+i)
│   ├── CollectRootkitIndicators.sh            # LKM modules, kernel taint decode, /proc vs ps hidden processes
│   ├── GenerateEvidenceManifest.sh            # SHA-256 evidence hashing, manifest.json & checksums.sha256
│   └── ArchiveFolder.sh                       # Secure .tar.gz archive with strict timestamp preservation
│
├── Analysis/                                   # 11 Analysis, Threat Hunting & Reporting Scripts
│   ├── Generate-DFIRHtmlReport.sh             # Standalone dark-mode HTML dashboard with metric cards & search
│   ├── Generate-MACTimeline.sh                # Forensic MACB Timeline (Modified/Accessed/Changed/Birth) & Bodyfile
│   ├── Generate-STIXReport.sh                 # Standard STIX 2.1 Threat Intel JSON Bundle & MISP/OpenCTI CSV
│   ├── DetectCryptominers.sh                  # Stratum protocol, fake kworker CPU hogs, mining configs & pools
│   ├── DetectLogTampering.sh                  # Anti-forensics, unlinked deleted logs in RAM, zeroed wtmp/btmp
│   ├── DumpPrivilegedUsers.sh                 # Rapid audit of UID 0 accounts, sudo/wheel groups, NOPASSWD rules
│   ├── ListCronAndTimers.sh                   # Consolidated tabular overview of all scheduled tasks (Cron & Timers)
│   ├── ListNetworkListeners.sh                # Triage of listening ports with binary paths & exposure levels
│   ├── ListPackageIntegrity.sh                # Core system binary checksum audit (dpkg -V / rpm -Va / pacman -Qk)
│   ├── ListKernelModules.sh                   # Audit loaded modules for out-of-tree (O) or unsigned (E) LKMs
│   └── ScanSuspiciousStaging.sh               # Rapid webshell, reverse shell, and ELF binary scan in /tmp
│
└── Containment/                                # 6 Emergency Incident Response & Active Containment Scripts
    ├── Isolate-Host.sh                        # Emergency firewall isolation (DROP all) with SOC whitelist & release
    ├── Kill-C2Threat.sh                       # Surgical neutralization of PIDs, remote C2 IPs, and malware binaries
    ├── QuarantineArtifact.sh                  # Zero-permission artifact quarantine with chattr +i immutable lock
    ├── EnableForensicAuditing.sh              # Live response high-resolution Auditd rule injection in RAM
    ├── LocalUserResponse.sh                   # Compromised user neutralization (lock, expire, kill processes)
    ├── RevokeSessions.sh                      # Forceful disconnect of remote sessions & Kerberos ticket purge
    └── README.md                              # Standard Operating Procedures for Incident Responders
```

---

## 🚀 Quick Start Guide

### 1. Full Automated Triage
Execute the master orchestrator to perform an end-to-end collection, analysis, HTML dashboard generation, and sealed archive packaging:

```bash
# Recommended execution with elevated ROOT privileges
sudo ./DFIR-Script.sh

# Target an external mount directly (Zero-Footprint best practice)
sudo ./DFIR-Script.sh -o /mnt/external_usb/incident_case_001 -c

# Adjust log and event search window (e.g., last 7 days)
sudo ./DFIR-Script.sh -w 7 -c
```

### 2. Targeted Module Execution
Run specific modular collectors based on the incident scope:

```bash
# Collect only Cloud, eBPF, Network, and Process artifacts
sudo ./DFIR-Script.sh -m cloud,ebpf,network,process,security

# Quick triage mode (skips heavy browser history databases and thumbnail caches)
sudo ./DFIR-Script.sh -q
```

---

## ⚙️ Command Line Options

| Option | Long Flag | Description | Default |
|---|---|---|---|
| `-w <days>` | `--window <days>` | Log and file modification search window in days | `2` |
| `-o <dir>` | `--output <dir>` | Destination directory for evidence storage | `./DFIR-<host>-<date>` |
| `-c` | `--compress` | Automatically packages evidence into sealed `.tar.gz` | `true` |
| `--no-compress` | | Skips `.tar.gz` archive creation | |
| `-a` | `--analyze` | Generates HTML dashboard & STIX 2.1 Threat Intel | `true` |
| `--no-analyze` | | Skips HTML dashboard generation | |
| `-q` | `--quick` | Quick triage mode (skips heavy browser/GUI caches) | `false` |
| `-m <list>` | `--modules <list>` | Runs only specified comma-separated modules | All |
| `-h` | `--help` | Displays help message and banner | |

---

## 🛠 Module Directory Reference

### 1. Master Orchestrator (`DFIR-Script.sh`)
Coordinates the end-to-end forensic acquisition workflow:
- Initializes the standardized evidence folder `DFIR-<hostname>-<YYYY-MM-DD_HHMMSS>`.
- Sequences all 18 acquisition modules respecting RFC 3227.
- Generates `checksums.sha256` and `manifest.json`.
- Compiles the standalone interactive dark-mode HTML report and STIX 2.1 Threat Intel bundle.
- Packages and digitally seals the final `.tar.gz` archive.

---

### 2. Acquisition Modules (`Acquisition/`)

| Module | Forensic Scope & Targeted Artifacts |
|---|---|
| [CollectNetworkTriage.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectNetworkTriage.sh) | Sockets (`ss`, `netstat`, `lsof`), active TCP/UDP connections, routing tables, ARP cache, DNS resolvers, `/proc/net/*` kernel tables, firewall rules, and active eBPF network filters. |
| [CollectExecutionArtifacts.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectExecutionArtifacts.sh) | Process tree (`ps auxww`, `pstree`), `/proc/[pid]/cmdline`, `/proc/[pid]/environ`, open file descriptors (`fd/`), memory maps (`maps`), `memfd_create` detection, and **automatic quarantine of deleted running ELF binaries**. |
| [CollectPersistence.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectPersistence.sh) | Systemd services/timers, System & User Crontabs (`/var/spool/cron`), At jobs, dynamic library hijacking (`/etc/ld.so.preload`), shell startup hooks (`/etc/profile.d`, `.bashrc`), PAM hooks, Udev rules, and Autostart entries. |
| [CollectUserActivity.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectUserActivity.sh) | Account audit (`/etc/passwd`, `/etc/shadow` hash algorithms), sudoers configurations (`NOPASSWD` rules), active sessions (`utmp`), login histories (`wtmp`, `btmp`, `last`, `lastb`), and shell command histories (`.bash_history`, `.zsh_history`). |
| [CollectSSHArtifacts.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectSSHArtifacts.sh) | Authorized SSH keys (`authorized_keys`), known hosts (`known_hosts`), OpenSSH daemon/client configs, private/public key inventory, and active SSH sessions. |
| [CollectBrowserArtifacts.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectBrowserArtifacts.sh) | SQLite history databases, downloads, extensions, and preferences for Chrome, Chromium, Firefox, Brave, Edge, Opera, and Tor Browser across all users. |
| [CollectAIArtifacts.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectAIArtifacts.sh) | Local LLM runtimes (Ollama models, LM Studio), AI coding assistants (Claude Desktop/Code, Cursor IDE, Windsurf, Copilot, Aider), and API token presence (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`). |
| [CollectSystemLogs.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectSystemLogs.sh) | Systemd journal (`journalctl`) with time filtering, authentication logs (`auth.log`/`secure`), Auditd logs (`/var/log/audit`), kernel ring buffer (`dmesg`), syslog, and web server logs. |
| [CollectSecuritySubsystems.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectSecuritySubsystems.sh) | **AppArmor** profiles and denial events (`apparmor="DENIED"`), **SELinux** status, booleans, modules and AVC denials (`type=AVC`), and kernel mitigations (ASLR, Yama ptrace, Seccomp). |
| [CollectHardwareAndContainers.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectHardwareAndContainers.sh) | Connected USB devices (`lsusb`), PCI devices (`lspci`), block mounts (`/etc/fstab`, `findmnt`), Container engines (Docker, Podman, Kubernetes kubeconfig/pods, LXC), and core crash dumps (`coredumpctl`). |
| [CollectVPNAndTunnelingArtifacts.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectVPNAndTunnelingArtifacts.sh) | Encrypted tunnels and reverse proxies: WireGuard (`wg show`), OpenVPN, Tailscale, ZeroTier, Cloudflare Tunnel (`cloudflared`), Ngrok, Chisel, FRP, Ligolo-ng, and IPsec policies (`ip xfrm`). |
| [CollectCloudMetadata.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectCloudMetadata.sh) | Cloud instance identity & IAM credential extraction: **AWS EC2 (IMDSv2)**, **Azure VM IMDS**, **GCP Compute Engine metadata**, and Cloud-Init provisioning logs (`/var/log/cloud-init.log`). |
| [CollectWebserverAndDatabaseArtifacts.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectWebserverAndDatabaseArtifacts.sh) | Configurations, vhosts, SSL/TLS certificates, malicious `.htaccess` injections for Nginx, Apache, Caddy, Lighttpd, **Redis unauthenticated public exposure audit**, MySQL, and PostgreSQL `pg_hba.conf`. |
| [CollectEBPFArtifacts.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectEBPFArtifacts.sh) | Loaded eBPF programs, maps, attached links, XDP programs, kprobes, tracepoints, and `/sys/fs/bpf` pinned objects to detect modern stealth rootkits (Symbiote, BPFDoor, TripleCross). |
| [CollectDeveloperEcosystem.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectDeveloperEcosystem.sh) | Developer supply chain artifacts: NPM (`.npmrc` auth tokens), Python (`.pypirc`, `.pth` persistence injection files), Cargo credentials, Go binaries, Git global hooks (`core.hooksPath`), and plaintext credentials. |
| [CollectMailArtifacts.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectMailArtifacts.sh) | Mail transport agents (Postfix, Exim, Sendmail), active outbound/inbound mail queues (`mailq`), local mailboxes (`/var/mail/`), and mail aliases pipe command hijacking (`/etc/aliases`). |
| [CollectDesktopArtifacts.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectDesktopArtifacts.sh) | Workstation artifacts: recently opened files (`recently-used.xbel`), Linux Trash can deleted items and metadata (`~/.local/share/Trash`), thumbnail cache (`~/.cache/thumbnails`), and X11 keyloggers (`xinput`). |
| [DumpProcessMemory.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/DumpProcessMemory.sh) | Surgical memory dumper for suspect PIDs via `/proc/[pid]/mem` and `/proc/[pid]/maps` or `gcore` to extract decrypted C2 configs, private keys, and injected shellcodes. |
| [CollectFileSystemArtifacts.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectFileSystemArtifacts.sh) | SUID/SGID binaries cross-referenced with **GTFOBins**, POSIX file capabilities (`getcap`), world-writable staging files (`/tmp`, `/dev/shm`), hidden filenames, recently modified binaries in `$PATH`, and immutable attributes (`chattr +i`). |
| [CollectRootkitIndicators.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/CollectRootkitIndicators.sh) | Kernel module audit (out-of-tree `O` / unsigned `E` LKMs), kernel taint bitmask decoding (`/proc/sys/kernel/tainted`), hidden process detection (`/proc` vs `ps`), and known rootkit file signatures (Diamorphine, Reptile, Azazel). |
| [GenerateEvidenceManifest.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/GenerateEvidenceManifest.sh) | Cryptographic chain of custody generator: computes SHA-256 hashes for all collected evidence files, generating `manifest.json` and `checksums.sha256`. |
| [ArchiveFolder.sh](file:///d:/scripts/bash/DFIR_bash/Acquisition/ArchiveFolder.sh) | Forensic compression into `.tar.gz` preserving all file permissions, ownerships, and MACB timestamps (`--atime-preserve`), generating a detached `.sha256` seal. |

---

### 3. Analysis & Threat Hunting Modules (`Analysis/`)

| Script | Purpose & Description |
|---|---|
| [Generate-DFIRHtmlReport.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/Generate-DFIRHtmlReport.sh) | Compiles a standalone, single-file interactive dark-mode HTML forensic dashboard with metric cards, live multi-table filtering, and threat highlighting. |
| [Generate-MACTimeline.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/Generate-MACTimeline.sh) | Generates a standard SleuthKit Bodyfile and CSV supertimeline capturing Modified (M), Accessed (A), Changed Inode (C), and Birth/Creation (B) timestamps. |
| [Generate-STIXReport.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/Generate-STIXReport.sh) | Extracts discovered IOCs (malware hashes, C2 remote IPs, commands, compromised accounts) into a **STIX 2.1 JSON Bundle** and MISP/OpenCTI flat CSV feed. |
| [DetectCryptominers.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/DetectCryptominers.sh) | Threat hunter for cryptominers: detects Stratum protocols (ports 3333, 4444, 5555, 7777), fake kernel threads (`[kworker]`) hiding high CPU usage, miner configs, and GPU utilization. |
| [DetectLogTampering.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/DetectLogTampering.sh) | Anti-forensics hunter: identifies unlinked deleted logs held open in RAM (`/proc/*/fd`), truncated/zeroed `wtmp`/`btmp` records, `HISTFILE=/dev/null` evasions, and wiping tools. |
| [DumpPrivilegedUsers.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/DumpPrivilegedUsers.sh) | Audits UID 0 accounts, administrative group members (sudo, wheel, shadow), `NOPASSWD` rules in `/etc/sudoers.d/`, and passwordless shadow accounts. |
| [ListCronAndTimers.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/ListCronAndTimers.sh) | Consolidated tabular overview of all scheduled tasks: Systemd timers, `/etc/crontab`, `/etc/cron.*`, user crontabs, and deferred `atq` jobs. |
| [ListNetworkListeners.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/ListNetworkListeners.sh) | Instant terminal triage of listening ports, associated process names, PID, executable paths, and highlights public exposures (`0.0.0.0` / `*`). |
| [ListPackageIntegrity.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/ListPackageIntegrity.sh) | Verifies cryptographic package checksums of key system binaries (`ls`, `ps`, `ss`, `sudo`, `sshd`, `login`) using `dpkg -V`, `rpm -Va`, or `pacman -Qk`. |
| [ListKernelModules.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/ListKernelModules.sh) | Audits loaded kernel modules from `/proc/modules` and flags out-of-tree (`O`), unsigned (`E`), or proprietary (`P`) LKMs. |
| [ScanSuspiciousStaging.sh](file:///d:/scripts/bash/DFIR_bash/Analysis/ScanSuspiciousStaging.sh) | Rapid scanner for world-writable staging directories (`/tmp`, `/dev/shm`, `/var/tmp`) to detect ELF binaries, hidden scripts, webshells, and reverse shells. |

---

### 4. Emergency Containment & Live Auditing (`Containment/`)

| Script | Operational Response Capability |
|---|---|
| [Isolate-Host.sh](file:///d:/scripts/bash/DFIR_bash/Containment/Isolate-Host.sh) | Emergency firewall containment (`DROP all`) while preserving bidirectional communication with SOC/SIEM analyst IPs. Includes clean `--release` rollback. |
| [Kill-C2Threat.sh](file:///d:/scripts/bash/DFIR_bash/Containment/Kill-C2Threat.sh) | Surgically terminates suspect PIDs, blocks malicious remote C2 IP addresses in `iptables`, and quarantines malware binaries. |
| [QuarantineArtifact.sh](file:///d:/scripts/bash/DFIR_bash/Containment/QuarantineArtifact.sh) | Moves suspicious files to `/var/dfir_quarantine`, strips all permissions (`chmod 000`), sets the immutable inode attribute (`chattr +i`), and calculates SHA-256 seal. |
| [EnableForensicAuditing.sh](file:///d:/scripts/bash/DFIR_bash/Containment/EnableForensicAuditing.sh) | Live incident high-resolution Auditd rule injection in kernel memory (tracing all `execve` executions, `/etc` modifications, kernel module loads, `ptrace` injections). |
| [LocalUserResponse.sh](file:///d:/scripts/bash/DFIR_bash/Containment/LocalUserResponse.sh) | Neutralizes a compromised local account: locks password, expires account, disables shell to `/sbin/nologin`, quarantines SSH keys, and terminates all active processes. |
| [RevokeSessions.sh](file:///d:/scripts/bash/DFIR_bash/Containment/RevokeSessions.sh) | Forcefully disconnects all remote interactive sessions (`pts/*`) and purges Kerberos ticket caches without disconnecting the analyst. |

---

## 📊 Interactive Standalone HTML Forensic Dashboard

The `Generate-DFIRHtmlReport.sh` script produces an interactive, single-file HTML report:
- **Executive Dashboard** with metric cards and alert counters.
- **Categorized Tabs**:
  1. ⚡ **Detections & MITRE**: Threat indicators, deleted running binaries in RAM, `memfd_create` executions, suspicious commands.
  2. 🔬 **eBPF & Stealth**: Loaded eBPF socket filters, tracepoints, and kprobes.
  3. 🛡️ **AppArmor & SELinux**: MAC statuses, AppArmor profile violations, and SELinux AVC denials.
  4. 🖥️ **Processes**: Complete process tree, cmdline arguments, CWD, and user contexts.
  5. 🌐 **Network**: Sockets, listening ports, interfaces, and ARP tables.
  6. 🔗 **VPN & C2 Tunnels**: WireGuard, Tailscale, Ngrok, Chisel, and reverse proxies.
  7. ☁️ **Cloud & Web/DB**: AWS IMDSv2, Azure, GCP metadata, Nginx, Apache, and Redis audits.
  8. 📦 **Dev & Supply Chain**: NPM tokens, Python `.pth` hooks, Cargo, and Git hooks.
  9. 💻 **Desktop & Trash**: Deleted files in Trash, `recently-used.xbel`, and thumbnail caches.
  10. 🔄 **Persistence**: Systemd timers, Cron, At, and shell startup hooks.
  11. 🔌 **Devices & Containers**: Connected USB/PCI devices, block mounts, Docker/Podman containers, coredumps.
  12. 👤 **Users**: Local accounts, shadow audits, active sessions, SSH keys, and sudoers rules.
  13. 📁 **SUID & Staging**: SUID binaries (GTFOBins audit), capabilities, and staging files.
  14. 🤖 **AI Artifacts**: Detected LLM servers, AI IDE configs, and API token presence.
  15. 📜 **Security Events**: Extracted authentication successes, failures, and sudo executions.
- **Global Search & Live Filtering** across all tables.
- **Visual Alert Badging** (Red/Yellow risk indicators for high-risk findings).

---

## 📁 SIEM-Ready Normalized CSV Schemas

All modules automatically export standardized CSV files into `CSV_Results/` for seamless ingestion into **Splunk**, **Elasticsearch**, **Microsoft Sentinel**, or **Wazuh**:

| Output CSV | Description & Key Columns |
|---|---|
| `Processes.csv` | Process inventory (`PID,PPID,User,UID,ProcessName,ExePath,IsDeleted,HasMemfd,CWD,CommandLine`). |
| `DeletedRunningBinaries.csv` | Unlinked running executables in RAM (`PID,User,DeletedExePath,QuarantinePath,SHA256`). |
| `MemfdExecutions.csv` | Anonymous fileless in-memory executions (`PID,User,Comm,MemfdMapping`). |
| `OpenSockets.csv` | Network sockets (`Protocol,State,Local_Address,Local_Port,Remote_Address,Remote_Port,Process_Name,PID,User`). |
| `NetworkInterfaces.csv` | Network interface metadata, IP addresses, MAC addresses, and operational statuses. |
| `RouteTable.csv` | Kernel routing tables and gateway configurations. |
| `ARPTable.csv` | ARP neighbor cache entries. |
| `TunnelingArtifacts.csv` | VPN and encrypted C2 tunnels (`TunnelType,Interface,RemotePeer,ConfigFile,Status`). |
| `CloudMetadata.csv` | Cloud instance identity & IAM credentials (`Provider,MetadataKey,Value,SourceURL`). |
| `WebAndDatabaseServers.csv` | Web servers, SSL certs, and DB security alerts (`Category,ServiceName,ConfigPath,PortBinding,SecurityAlert`). |
| `EBPFPrograms.csv` | Loaded eBPF programs and probes (`ProgID,Type,Name,Tag,LoadedByUID,MapCount,AttachedLinks,AnomalyFlag`). |
| `DeveloperEcosystem.csv` | Supply chain secrets and hooks (`Ecosystem,ArtifactType,Path,HasCredentials,RiskAlert`). |
| `TrashArtifacts.csv` | Linux Trash deleted files (`User,OriginalPath,DeletionDateUTC,TrashFilePath,FileSize`). |
| `RecentFiles.csv` | Recently opened files from `.xbel` (`User,FilePath,MIMEType,Application,LastVisitedUTC`). |
| `MailArtifacts.csv` | Mail transport configurations and queues (`MTA,QueueSize,ConfigPath,SecurityAlert`). |
| `PersistenceSummary.csv` | Consolidated persistence mechanisms (`Type,Name,Location,Details,Owner,Permissions`). |
| `ScheduledTasks.csv` | Systemd timers, crontabs, and at jobs. |
| `ShellHooks.csv` | Shell startup scripts (`/etc/profile.d`, `.bashrc`, `.bash_profile`). |
| `LocalUsers.csv` | User accounts, UIDs, GIDs, home directories, and login shells. |
| `ActiveSessions.csv` | Active interactive sessions from `utmp` and `w`. |
| `LoginHistory.csv` | Historical successful logins from `wtmp`. |
| `FailedLogins.csv` | Historical failed authentication attempts from `btmp`. |
| `CommandHistory.csv` | User shell command histories with suspicious pattern detection flags. |
| `SSHAuthorizedKeys.csv` | Authorized SSH public keys, options, algorithms, and comments. |
| `SSHKnownHosts.csv` | SSH known host entries. |
| `BrowserHistory.csv` | Web browser navigation history entries (`Browser,User,URL,Title,VisitCount,LastVisitTimeUTC`). |
| `BrowserDownloads.csv` | Web browser downloaded files (`Browser,User,TargetPath,CurrentPath,ReceivedBytes,TotalBytes,StartTimeUTC`). |
| `BrowserExtensions.csv` | Installed web browser extensions and add-ons. |
| `AIToolsDetected.csv` | Detected AI runtimes and LLM tooling (`ToolType,Name,Path,DetectedArtifacts`). |
| `AITokenPresence.csv` | Detected AI API keys and environment tokens (`TokenName,Location,User,MaskedPreview`). |
| `SecurityEvents.csv` | Normalized authentication, sudo, and SSH events (`Timestamp,Host,Service,EventType,User,SourceIP,Message`). |
| `MACSubsystems.csv` | AppArmor and SELinux operational statuses (`Subsystem,Status,EnforcingMode,ProfilesCount,Details`). |
| `AppArmorDenials.csv` | AppArmor violation records (`Timestamp,Profile,Operation,DeniedMask,RequestedMask,Name,PID,Comm,SourceFile`). |
| `SELinuxDenials.csv` | SELinux AVC denial records (`Timestamp,SContext,TContext,TClass,Permissions,DeniedExe,PID,Comm,SourceFile`). |
| `ConnectedDevices.csv` | Connected hardware peripherals (`DeviceType,DeviceID,Vendor,Model,SerialNumber,BusInfo`). |
| `MountPoints.csv` | Storage mounts and filesystem options (`Device,MountPoint,FSType,Options,Dump,Pass`). |
| `Containers.csv` | Docker and Podman container instances (`Runtime,ContainerID,Name,Image,Status,Created,Ports`). |
| `SystemCoredumps.csv` | System core crash dumps (`PID,UID,GID,Executable,Timestamp,Signal,CoreFileSize`). |
| `SUIDBinaries.csv` | SUID/SGID executables with GTFOBins flags (`Path,Permissions,Owner,Group,Size,SHA256,IsGTFOBin`). |
| `FileCapabilities.csv` | Extended POSIX file capabilities (`Path,Capabilities`). |
| `StagingFiles.csv` | Temporary staging files (`Path,Size,Permissions,Owner,FileType,SHA256,IsExecutable`). |
| `RootkitIndicators.csv` | Kernel module anomalies, taints, and rootkit indicators (`Category,IndicatorName,Status,RiskLevel,Description`). |

---

## 🌐 Threat Intelligence & STIX 2.1 / MISP Export

The `Generate-STIXReport.sh` script automatically converts findings into standardized cyber threat intelligence feeds:
- Generates a valid **STIX 2.1 JSON Bundle** containing `indicator` and `observed-data` SDOs.
- Generates a flat CSV feed ready for import into **MISP**, **OpenCTI**, or **TheHive**.

```bash
# Generate STIX 2.1 Threat Intel Bundle from an evidence folder
sudo ./Analysis/Generate-STIXReport.sh ./DFIR-evidence-folder/
```

---

## 🛡 MITRE ATT&CK® Matrix for Linux

| MITRE ATT&CK Tactic | Covered Techniques | Associated Modules |
|---|---|---|
| **Initial Access (TA0001)** | T1078 (Valid Accounts), T1133 (External Remote Services), T1190 (Exploit Public App), T1195 (Supply Chain) | `CollectSSHArtifacts.sh`, `CollectUserActivity.sh`, `CollectWebserverAndDatabaseArtifacts.sh`, `CollectDeveloperEcosystem.sh` |
| **Execution (TA0002)** | T1059 (Command & Scripting Interpreter), T1053 (Scheduled Task/Job), T1610 (Deploy Container) | `CollectExecutionArtifacts.sh`, `CollectPersistence.sh`, `CollectHardwareAndContainers.sh` |
| **Persistence (TA0003)** | T1543.002 (Systemd Service), T1053.003 (Cron), T1546.004 (.bashrc), T1574.006 (LD_PRELOAD), T1546.014 (eBPF) | `CollectPersistence.sh`, `CollectRootkitIndicators.sh`, `CollectEBPFArtifacts.sh` |
| **Privilege Escalation (TA0004)** | T1548.001 (Setuid/Setgid), T1548.003 (Sudoers), T1068 (Priv Esc Exploitation), T1611 (Escape to Host) | `CollectFileSystemArtifacts.sh`, `DumpPrivilegedUsers.sh`, `CollectHardwareAndContainers.sh` |
| **Defense Evasion (TA0005)** | T1070 (Indicator Removal), T1014 (Rootkit), T1620 (memfd_create), T1562.001 (Disable Tools), T1574.007 (eBPF rootkit) | `CollectRootkitIndicators.sh`, `CollectExecutionArtifacts.sh`, `CollectSecuritySubsystems.sh`, `DetectLogTampering.sh`, `CollectEBPFArtifacts.sh` |
| **Credential Access (TA0006)** | T1003.008 (/etc/passwd and /etc/shadow), T1552.004 (Private Keys), T1552.005 (Cloud IMDS), T1555 (Credentials in Files) | `CollectUserActivity.sh`, `CollectSSHArtifacts.sh`, `CollectCloudMetadata.sh`, `CollectDeveloperEcosystem.sh`, `CollectAIArtifacts.sh` |
| **Discovery (TA0007)** | T1082 (System Info), T1049 (Network Connections), T1057 (Process Discovery), T1613 (Container Discovery) | `CollectNetworkTriage.sh`, `CollectExecutionArtifacts.sh`, `CollectHardwareAndContainers.sh` |
| **Command and Control (TA0011)** | T1071 (Application Layer Protocol), T1571 (Non-Standard Port), T1572 (Protocol Tunneling), T1090 (Proxy) | `CollectNetworkTriage.sh`, `CollectVPNAndTunnelingArtifacts.sh`, `ListNetworkListeners.sh` |
| **Impact (TA0040)** | T1496 (Resource Hijacking / Cryptomining) | `DetectCryptominers.sh` |

---

## 🔒 Chain of Custody & Best Practices

1. **Execute from External Storage**: Always point output to an external mount (`-o /mnt/external_drive`) to prevent altering unallocated space on the target machine.
2. **Never Reboot**: Do not restart the compromised system before capturing volatile memory artifacts (`/proc`, open sockets, eBPF maps, memory dumps).
3. **Preserve Checksums & Digital Seals**: Retain the `checksums.sha256` and `.tar.gz.sha256` files for legal admissibility.
4. **Use Strict Containment with Caution**: Emergency containment scripts (`Isolate-Host.sh`, `Kill-C2Threat.sh`, `LocalUserResponse.sh`) alter system state; ensure initial volatile memory collection is completed prior to triggering active containment.

---

## 📄 License & Disclaimer

This project is licensed under the **BSD 3-Clause License** - see the [LICENSE](file:///d:/scripts/bash/DFIR_bash/LICENSE) file for details.  
Copyright (c) 2026, **Bellk0ruh**. All rights reserved.

> *Disclaimer: DFIR Bash is designed for authorized digital forensics, security auditing, and incident response operations. Always ensure you have appropriate legal authorization before executing forensic collection on any host.*
