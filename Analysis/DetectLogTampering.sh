#!/usr/bin/env bash
# ==============================================================================
# Script: DetectLogTampering.sh
# Description: Anti-forensics, log wiping, truncation, and unlinked log detection
# Documentation: Audits open file descriptors for unlinked deleted logs (/proc/*/fd),
#                checks for zeroed/truncated authentication logs (wtmp, btmp, lastlog),
#                detects shell history evasion (HISTFILE=/dev/null), and wiper utility traces.
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

echo -e "${CYAN}${BOLD}=== Anti-Forensics & Log Tampering Threat Hunter ===${NC}\n"

tampering_alerts=0

# ------------------------------------------------------------------------------
# 1. Unlinked Deleted Log Files Held Open in Memory (/proc/*/fd)
# ------------------------------------------------------------------------------
echo -e "${BLUE}[1] Auditing Open File Descriptors for Unlinked / Deleted Log Files:${NC}"
for p_dir in /proc/[0-9]*; do
    [ -d "$p_dir" ] || continue
    pid="${p_dir##*/}"
    
    if [ -d "${p_dir}/fd" ]; then
        ls -l "${p_dir}/fd" 2>/dev/null | grep -E '/var/log/.*\(deleted\)' | while read -r fd_line; do
            ((tampering_alerts++))
            pname=$(cat "${p_dir}/comm" 2>/dev/null || echo "unknown")
            echo -e " - ${RED}[UNLINKED DELETED LOG IN RAM]${NC} PID ${pid} (${pname}) holds open: ${fd_line}"
        done
    fi
done
echo ""

# ------------------------------------------------------------------------------
# 2. Check for Zeroed / Truncated Critical Authentication Logs
# ------------------------------------------------------------------------------
echo -e "${BLUE}[2] Checking File Sizes of Critical Authentication Records:${NC}"
for log_file in /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/auth.log /var/log/secure; do
    if [ -f "$log_file" ]; then
        fsize=$(stat -c "%s" "$log_file" 2>/dev/null || echo "0")
        if [ "$fsize" -eq 0 ]; then
            ((tampering_alerts++))
            echo -e " - ${RED}[POSSIBLE LOG TRUNCATION / WIPE]${NC} ${log_file} has 0 bytes!"
        else
            echo -e " - ${GREEN}[OK]${NC} ${log_file} size: ${fsize} bytes"
        fi
    elif [ ! -e "$log_file" ] && [[ "$log_file" =~ (wtmp|lastlog) ]]; then
        echo -e " - ${YELLOW}[WARNING]${NC} ${log_file} does not exist on host."
    fi
done
echo ""

# ------------------------------------------------------------------------------
# 3. Audit Shell Profiles for History Suppression Evasions
# ------------------------------------------------------------------------------
echo -e "${BLUE}[3] Auditing User Shell Profiles for History Suppression (HISTFILE=/dev/null):${NC}"
for prof in /etc/profile /etc/bash.bashrc /etc/environment /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /home/*/.zshrc; do
    [ -f "$prof" ] || continue
    if grep -Eiq '(HISTFILE=/dev/null|HISTSIZE=0|HISTFILESIZE=0|unset HISTFILE|HISTCONTROL=ignorespace)' "$prof" 2>/dev/null; then
        ((tampering_alerts++))
        matched=$(grep -Ei '(HISTFILE=/dev/null|HISTSIZE=0|HISTFILESIZE=0|unset HISTFILE|HISTCONTROL=ignorespace)' "$prof")
        echo -e " - ${RED}[HISTORY EVASION FOUND]${NC} ${prof}: ${YELLOW}${matched}${NC}"
    fi
done
echo ""

# ------------------------------------------------------------------------------
# 4. Check for Wiping & Shredding Utilities on Disk
# ------------------------------------------------------------------------------
echo -e "${BLUE}[4] Checking for Secure Wiping and Anti-Forensics Tooling:${NC}"
for wiper in shred srm wipe logcleaner vanish bcwipe; do
    if command -v "$wiper" >/dev/null 2>&1; then
        wpath=$(command -v "$wiper")
        echo -e " - ${YELLOW}[WIPER UTILITY PRESENT]${NC} ${wiper} at ${wpath}"
    fi
done

echo ""
if [ "$tampering_alerts" -eq 0 ]; then
    echo -e "${GREEN}[+] No obvious anti-forensics or log deletion tampering detected.${NC}"
else
    echo -e "${RED}[!] WARNING: ${tampering_alerts} potential anti-forensics indicator(s) found!${NC}"
fi
