#!/usr/bin/env bash
# ==============================================================================
# Script: CollectSystemLogs.sh
# Description: Linux event journals, auditd, and security logs forensic acquisition
# Documentation: Collects Systemd journals (journalctl) with time-window filtering,
#                authentication logs (auth.log/secure), Auditd subsystem records,
#                kernel ring buffer (dmesg), and web/package manager logs.
# Author: Bellk0ruh
# License: BSD 3-Clause
# ==============================================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TARGET_DIR="${1:-.}"
WINDOW_DAYS="${2:-2}"
OUTPUT_DIR="${TARGET_DIR}/SystemLogs"
CSV_DIR="${TARGET_DIR}/CSV_Results"

mkdir -p "${OUTPUT_DIR}" "${CSV_DIR}"

log_info() {
    echo -e "${CYAN}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

echo -e "${CYAN}${BOLD}=== System & Security Logs Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR} (Window: last ${WINDOW_DAYS} day(s))${NC}\n"

echo "Timestamp,Host,Service,EventType,User,SourceIP,Message" > "${CSV_DIR}/SecurityEvents.csv"

# ------------------------------------------------------------------------------
# 1. Systemd Journals (Journalctl)
# ------------------------------------------------------------------------------
log_info "Collecting Systemd journals (journalctl)..."
mkdir -p "${OUTPUT_DIR}/Journal"

if command -v journalctl >/dev/null 2>&1; then
    # Logs within time search window
    journalctl --since "${WINDOW_DAYS} days ago" --no-pager > "${OUTPUT_DIR}/Journal/journal_since_${WINDOW_DAYS}d.txt" 2>&1 || true
    
    # Current boot logs
    journalctl -b --no-pager > "${OUTPUT_DIR}/Journal/journal_current_boot.txt" 2>&1 || true
    
    # Errors and critical alerts (Priority 0 to 3: emerg, alert, crit, err)
    journalctl -p 0..3 -xb --no-pager > "${OUTPUT_DIR}/Journal/journal_errors_and_critical.txt" 2>&1 || true
    
    # Failed units
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --failed --no-pager > "${OUTPUT_DIR}/Journal/systemd_failed_units.txt" 2>&1 || true
    fi
fi

# Copy raw persistent journal files
if [ -d /var/log/journal ]; then
    mkdir -p "${OUTPUT_DIR}/Journal/raw_journal_files"
    cp -rp /var/log/journal/* "${OUTPUT_DIR}/Journal/raw_journal_files/" 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# 2. Authentication Logs (auth.log, secure)
# ------------------------------------------------------------------------------
log_info "Collecting and parsing authentication logs (SSH, Sudo, Su, PAM)..."
mkdir -p "${OUTPUT_DIR}/AuthLogs"

for auth_f in /var/log/auth.log* /var/log/secure*; do
    [ -f "$auth_f" ] || continue
    cp -p "$auth_f" "${OUTPUT_DIR}/AuthLogs/" 2>/dev/null
    
    # Extract security events into CSV
    zgrep -Ei '(Accepted|Failed|Invalid user|session opened|session closed|COMMAND=|sudo:)' "$auth_f" 2>/dev/null | tail -n 1000 | while read -r line; do
        [ -n "$line" ] || continue
        ts=$(echo "$line" | awk '{print $1,$2,$3}')
        host=$(echo "$line" | awk '{print $4}')
        svc=$(echo "$line" | awk '{print $5}' | tr -d ':')
        
        etype="OTHER"
        user=""
        src_ip=""
        
        if [[ "$line" =~ Accepted\ (password|publickey)\ for\ ([^ ]+)\ from\ ([^ ]+) ]]; then
            etype="AUTH_SUCCESS"
            user="${BASH_REMATCH[2]}"
            src_ip="${BASH_REMATCH[3]}"
        elif [[ "$line" =~ Failed\ (password|publickey)\ for\ (invalid\ user\ )?([^ ]+)\ from\ ([^ ]+) ]]; then
            etype="AUTH_FAILURE"
            user="${BASH_REMATCH[3]}"
            src_ip="${BASH_REMATCH[4]}"
        elif [[ "$line" =~ sudo:.*COMMAND=(.*) ]]; then
            etype="SUDO_EXEC"
            user=$(echo "$line" | grep -oP 'sudo:\s+\K\w+' || echo "")
        fi
        
        clean_msg=$(echo "$line" | sed 's/"/\\"/g')
        echo "\"${ts}\",\"${host}\",\"${svc}\",\"${etype}\",\"${user}\",\"${src_ip}\",\"${clean_msg}\"" >> "${CSV_DIR}/SecurityEvents.csv"
    done
done

# ------------------------------------------------------------------------------
# 3. Linux Audit Subsystem (Auditd)
# ------------------------------------------------------------------------------
log_info "Collecting Linux Auditd subsystem logs (/var/log/audit)..."
mkdir -p "${OUTPUT_DIR}/Auditd"

if [ -d /var/log/audit ]; then
    cp -rp /var/log/audit/audit.log* "${OUTPUT_DIR}/Auditd/" 2>/dev/null || true
fi
[ -f /etc/audit/auditd.conf ] && cp -p /etc/audit/auditd.conf "${OUTPUT_DIR}/Auditd/" 2>/dev/null
[ -d /etc/audit/rules.d ] && cp -rp /etc/audit/rules.d "${OUTPUT_DIR}/Auditd/" 2>/dev/null

if command -v auditctl >/dev/null 2>&1; then
    auditctl -l > "${OUTPUT_DIR}/Auditd/active_audit_rules.txt" 2>&1 || true
    auditctl -s > "${OUTPUT_DIR}/Auditd/audit_status.txt" 2>&1 || true
fi

# ------------------------------------------------------------------------------
# 4. Kernel Ring Buffer & Kernel Logs (dmesg)
# ------------------------------------------------------------------------------
log_info "Collecting kernel ring buffer messages (dmesg)..."
mkdir -p "${OUTPUT_DIR}/Kernel"

if command -v dmesg >/dev/null 2>&1; then
    dmesg -T > "${OUTPUT_DIR}/Kernel/dmesg_human.txt" 2>&1 || dmesg > "${OUTPUT_DIR}/Kernel/dmesg_raw.txt" 2>&1
fi
for klog in /var/log/kern.log* /var/log/dmesg*; do
    [ -f "$klog" ] && cp -p "$klog" "${OUTPUT_DIR}/Kernel/" 2>/dev/null || true
done

# ------------------------------------------------------------------------------
# 5. General System & Application Logs
# ------------------------------------------------------------------------------
log_info "Collecting general system and application logs..."
mkdir -p "${OUTPUT_DIR}/Applications"

# Syslog & Messages
for slog in /var/log/syslog* /var/log/messages* /var/log/daemon.log*; do
    [ -f "$slog" ] && cp -p "$slog" "${OUTPUT_DIR}/Applications/" 2>/dev/null || true
done

# Package manager logs (Dpkg, APT, YUM, DNF, Pacman)
for pkg_log in /var/log/dpkg.log* /var/log/apt/history.log* /var/log/apt/term.log* /var/log/yum.log* /var/log/dnf.log* /var/log/pacman.log*; do
    [ -f "$pkg_log" ] && cp -p "$pkg_log" "${OUTPUT_DIR}/Applications/" 2>/dev/null || true
done

# Web Servers & Security (Nginx, Apache, Fail2ban, UFW)
for srv_log in /var/log/nginx /var/log/apache2 /var/log/httpd /var/log/fail2ban.log* /var/log/ufw.log*; do
    if [ -d "$srv_log" ]; then
        cp -rp "$srv_log" "${OUTPUT_DIR}/Applications/" 2>/dev/null || true
    elif [ -f "$srv_log" ]; then
        cp -p "$srv_log" "${OUTPUT_DIR}/Applications/" 2>/dev/null || true
    fi
done

log_success "System and security logs triage completed successfully."
