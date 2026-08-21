#!/usr/bin/env bash
# ==============================================================================
# Script: CollectSecuritySubsystems.sh
# Description: Linux Mandatory Access Control (MAC) & Security Subsystems Forensics
# Documentation: Collects AppArmor status, profiles and denial logs, SELinux status,
#                AVC denials, policy booleans, loaded modules, Seccomp statuses,
#                and kernel security mitigations (ASLR, KASLR, Yama ptrace, etc.).
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
OUTPUT_DIR="${TARGET_DIR}/SecuritySubsystems"
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

echo -e "${CYAN}${BOLD}=== Security Subsystems (AppArmor / SELinux / Kernel Mitigations) ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "Subsystem,Status,EnforcingMode,ProfilesCount,Details" > "${CSV_DIR}/MACSubsystems.csv"
echo "Timestamp,Profile,Operation,DeniedMask,RequestedMask,Name,PID,Comm,SourceFile" > "${CSV_DIR}/AppArmorDenials.csv"
echo "Timestamp,SContext,TContext,TClass,Permissions,DeniedExe,PID,Comm,SourceFile" > "${CSV_DIR}/SELinuxDenials.csv"

# ------------------------------------------------------------------------------
# 1. AppArmor Forensics
# ------------------------------------------------------------------------------
log_info "Auditing AppArmor status, active profiles, and denial logs..."
mkdir -p "${OUTPUT_DIR}/AppArmor"

apparmor_active="False"
aa_mode="Disabled"
aa_profiles="0"

if command -v aa-status >/dev/null 2>&1 || command -v apparmor_status >/dev/null 2>&1; then
    aa_cmd="aa-status"
    command -v apparmor_status >/dev/null 2>&1 && aa_cmd="apparmor_status"
    
    $aa_cmd > "${OUTPUT_DIR}/AppArmor/apparmor_status.txt" 2>&1 || true
    
    if grep -q "apparmor module is loaded." "${OUTPUT_DIR}/AppArmor/apparmor_status.txt" 2>/dev/null; then
        apparmor_active="True"
        aa_mode="Enforcing"
        aa_profiles=$(grep -oP '\d+(?= profiles are loaded)' "${OUTPUT_DIR}/AppArmor/apparmor_status.txt" 2>/dev/null || echo "0")
        log_success "AppArmor is active (${aa_profiles} profile(s) loaded)."
    fi
fi

# Copy AppArmor profile definitions
if [ -d /etc/apparmor.d ]; then
    mkdir -p "${OUTPUT_DIR}/AppArmor/profiles"
    cp -rp /etc/apparmor.d/* "${OUTPUT_DIR}/AppArmor/profiles/" 2>/dev/null || true
fi

# Extract AppArmor Denial Events from audit.log, syslog, messages, dmesg
log_info "Extracting AppArmor denial and violation events..."
for log_candidate in /var/log/audit/audit.log* /var/log/syslog* /var/log/messages* /var/log/kern.log*; do
    [ -f "$log_candidate" ] || continue
    zgrep -Ei 'apparmor="DENIED"|apparmor="AUDIT"' "$log_candidate" 2>/dev/null | tail -n 500 | while read -r aaline; do
        [ -n "$aaline" ] || continue
        
        ts=$(echo "$aaline" | awk '{print $1,$2,$3}')
        prof=$(echo "$aaline" | grep -oP 'profile="\K[^"]+' || echo "UNKNOWN")
        op=$(echo "$aaline" | grep -oP 'operation="\K[^"]+' || echo "UNKNOWN")
        denied_mask=$(echo "$aaline" | grep -oP 'denied_mask="\K[^"]+' || echo "")
        req_mask=$(echo "$aaline" | grep -oP 'requested_mask="\K[^"]+' || echo "")
        target_name=$(echo "$aaline" | grep -oP 'name="\K[^"]+' || echo "")
        pid=$(echo "$aaline" | grep -oP 'pid=\K\d+' || echo "")
        comm=$(echo "$aaline" | grep -oP 'comm="\K[^"]+' || echo "")
        
        echo "\"${ts}\",\"${prof}\",\"${op}\",\"${denied_mask}\",\"${req_mask}\",\"${target_name}\",\"${pid}\",\"${comm}\",\"${log_candidate}\"" >> "${CSV_DIR}/AppArmorDenials.csv"
    done
done

echo "\"AppArmor\",\"${apparmor_active}\",\"${aa_mode}\",\"${aa_profiles}\",\"Profiles in /etc/apparmor.d/\"" >> "${CSV_DIR}/MACSubsystems.csv"

# ------------------------------------------------------------------------------
# 2. SELinux Forensics
# ------------------------------------------------------------------------------
log_info "Auditing SELinux status, policy booleans, and AVC denial logs..."
mkdir -p "${OUTPUT_DIR}/SELinux"

selinux_active="False"
se_mode="Disabled"

if command -v sestatus >/dev/null 2>&1; then
    sestatus -v > "${OUTPUT_DIR}/SELinux/sestatus.txt" 2>&1 || true
    if grep -q "SELinux status:\s*enabled" "${OUTPUT_DIR}/SELinux/sestatus.txt" 2>/dev/null; then
        selinux_active="True"
        se_mode=$(grep -oP 'Current mode:\s*\K\w+' "${OUTPUT_DIR}/SELinux/sestatus.txt" 2>/dev/null || echo "enforcing")
        log_success "SELinux is active (Mode: ${se_mode})."
    fi
elif [ -f /etc/selinux/config ]; then
    cp -p /etc/selinux/config "${OUTPUT_DIR}/SELinux/config" 2>/dev/null
fi

if [ "$selinux_active" = "True" ]; then
    # Policy Booleans
    if command -v getsebool >/dev/null 2>&1; then
        getsebool -a > "${OUTPUT_DIR}/SELinux/selinux_booleans.txt" 2>&1 || true
    fi
    # Loaded Modules
    if command -v semodule >/dev/null 2>&1; then
        semodule -l > "${OUTPUT_DIR}/SELinux/selinux_modules.txt" 2>&1 || true
    fi
fi

# Extract SELinux AVC Denials (type=AVC)
log_info "Extracting SELinux AVC denial records..."
for log_candidate in /var/log/audit/audit.log* /var/log/messages* /var/log/syslog*; do
    [ -f "$log_candidate" ] || continue
    zgrep -Ei 'type=AVC' "$log_candidate" 2>/dev/null | tail -n 500 | while read -r avcline; do
        [ -n "$avcline" ] || continue
        
        ts=$(echo "$avcline" | awk '{print $1,$2,$3}')
        scontext=$(echo "$avcline" | grep -oP 'scontext=\K\S+' || echo "")
        tcontext=$(echo "$avcline" | grep -oP 'tcontext=\K\S+' || echo "")
        tclass=$(echo "$avcline" | grep -oP 'tclass=\K\S+' || echo "")
        perms=$(echo "$avcline" | grep -oP '\{[^}]+\}' || echo "")
        exe=$(echo "$avcline" | grep -oP 'exe="\K[^"]+' || echo "")
        pid=$(echo "$avcline" | grep -oP 'pid=\K\d+' || echo "")
        comm=$(echo "$avcline" | grep -oP 'comm="\K[^"]+' || echo "")
        
        echo "\"${ts}\",\"${scontext}\",\"${tcontext}\",\"${tclass}\",\"${perms}\",\"${exe}\",\"${pid}\",\"${comm}\",\"${log_candidate}\"" >> "${CSV_DIR}/SELinuxDenials.csv"
    done
done

echo "\"SELinux\",\"${selinux_active}\",\"${se_mode}\",\"N/A\",\"Policy configs in /etc/selinux/\"" >> "${CSV_DIR}/MACSubsystems.csv"

# ------------------------------------------------------------------------------
# 3. Kernel Security Parameters & Mitigations
# ------------------------------------------------------------------------------
log_info "Collecting kernel security parameters & mitigation flags..."
mkdir -p "${OUTPUT_DIR}/KernelMitigations"

# Sysctl kernel security parameters
if command -v sysctl >/dev/null 2>&1; then
    sysctl kernel.randomize_va_space \
           kernel.kptr_restrict \
           kernel.dmesg_restrict \
           kernel.yama.ptrace_scope \
           kernel.modules_disabled \
           kernel.unprivileged_bpf_disabled \
           kernel.perf_event_paranoid \
           fs.protected_symlinks \
           fs.protected_hardlinks \
           fs.protected_fifos \
           fs.protected_regular \
           fs.suid_dumpable > "${OUTPUT_DIR}/KernelMitigations/security_sysctl.txt" 2>&1 || true
fi

# ASLR status
[ -f /proc/sys/kernel/randomize_va_space ] && cp -p /proc/sys/kernel/randomize_va_space "${OUTPUT_DIR}/KernelMitigations/aslr_status.txt" 2>/dev/null

# Seccomp status check on kernel
if [ -f /proc/sys/kernel/seccomp/actions_avail ]; then
    cp -p /proc/sys/kernel/seccomp/actions_avail "${OUTPUT_DIR}/KernelMitigations/seccomp_actions.txt" 2>/dev/null
fi

log_success "Security subsystems triage completed successfully."
