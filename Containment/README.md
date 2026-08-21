# 🛡️ DFIR Bash - Linux Emergency Containment & Incident Response Playbook

This directory contains operational scripts designed to immediately contain and neutralize active security threats on Linux endpoints and servers while preserving secure response channels for the SOC / CERT / DFIR team.

---

## Available Containment Scripts

### 1. `Isolate-Host.sh`
Isolates the host using kernel packet filtering (`iptables`/`nftables`) with a default `DROP` policy on all inbound and outbound traffic, while maintaining an explicit whitelist for the SOC / Incident Response analyst IPs.

```bash
# Isolate host allowing only SOC / SIEM analyst IPs
sudo ./Isolate-Host.sh --isolate --allowed-ips "10.0.0.50,192.168.1.100"

# Isolate host with outbound DNS resolution permitted
sudo ./Isolate-Host.sh --isolate --allowed-ips "10.0.0.50" --allow-dns

# Check isolation status
./Isolate-Host.sh --status

# Release network isolation (restore previous state)
sudo ./Isolate-Host.sh --release
```

---

### 2. `Kill-C2Threat.sh`
Surgically eliminates an active threat by terminating specific PIDs, blocking malicious remote IP addresses in the firewall, and quarantining associated malware binaries.

```bash
# Terminate PID 4589 and quarantine its executable binary
sudo ./Kill-C2Threat.sh --pid 4589

# Block malicious C2 remote IP address immediately
sudo ./Kill-C2Threat.sh --ip 198.51.100.24

# Terminate all processes running a malware binary and quarantine it
sudo ./Kill-C2Threat.sh --binary /tmp/evil_payload

# Combine PID, IP, and port
sudo ./Kill-C2Threat.sh --pid 4589 --ip 198.51.100.24 --port 4444
```

---

### 3. `QuarantineArtifact.sh`
Safely isolates suspicious files or malware samples into `/var/dfir_quarantine`, strips all permissions (`chmod 000`), sets the immutable inode attribute (`chattr +i`), and computes the SHA-256 digital seal.

```bash
# Quarantine a suspicious script
sudo ./QuarantineArtifact.sh /tmp/.hidden_script.sh

# Quarantine into a custom case folder
sudo ./QuarantineArtifact.sh /tmp/miner /mnt/evidence/quarantine
```

---

### 4. `EnableForensicAuditing.sh`
Temporarily deploys high-resolution kernel **Auditd** monitoring rules during live response (tracing all `execve` executions, `/etc` modifications, kernel module loads, `ptrace` injections, and outbound connections) without rebooting.

```bash
# Activate live response high-resolution audit rules
sudo ./EnableForensicAuditing.sh --enable

# Check auditing status
sudo ./EnableForensicAuditing.sh --status

# Disable and restore previous audit rules
sudo ./EnableForensicAuditing.sh --disable
```

---

### 5. `LocalUserResponse.sh`
Immediately neutralizes a compromised local user account:
- Locks account password (`passwd -l` / `usermod -L`).
- Sets expiration date to 0 / past (`chage -E 0`).
- Changes login shell to `/sbin/nologin`.
- Quarantines `~/.ssh/authorized_keys`.
- Kills all running processes of the user (`pkill -9 -u <user>`).
- Terminates user `loginctl` sessions.

```bash
# Neutralize user 'compromised_user'
sudo ./LocalUserResponse.sh compromised_user
```

---

### 6. `RevokeSessions.sh`
Forcefully closes all active remote interactive sessions (`pts/*`) and purges Kerberos ticket caches without disconnecting the current analyst session.

```bash
# Revoke all remote SSH / interactive sessions
sudo ./RevokeSessions.sh
```
