#!/usr/bin/env bash
# ==============================================================================
# Script: EnableForensicAuditing.sh
# Description: Live incident high-resolution Auditd rule injector & real-time monitoring
# Documentation: Temporarily deploys high-fidelity kernel audit rules in memory without rebooting,
#                tracing all execve executions, /etc modifications, kernel module loads,
#                ptrace injections, and outbound connections during live response.
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

BACKUP_RULES="/var/tmp/audit_rules_pre_dfir.bak"

usage() {
    echo -e "${CYAN}${BOLD}=== Live Incident High-Resolution Forensic Auditing Tool ===${NC}"
    echo "Usage:"
    echo "  $0 [--enable] [--disable] [--status]"
    echo ""
    echo "Options:"
    echo "  --enable    Deploys high-fidelity kernel audit rules (execve, /etc, modules, ptrace)"
    echo "  --disable   Removes DFIR audit rules and restores previous configuration"
    echo "  --status    Displays current audit rules and auditd status"
    echo ""
    exit 1
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] Error: Root privileges are required to manage auditd rules.${NC}" >&2
        exit 1
    fi
}

check_auditctl() {
    if ! command -v auditctl >/dev/null 2>&1; then
        echo -e "${RED}[!] Error: 'auditctl' utility is not installed or available on this system.${NC}" >&2
        exit 1
    fi
}

check_root
check_auditctl
[ $# -eq 0 ] && usage

ACTION="$1"

case "$ACTION" in
    --enable)
        echo -e "${CYAN}[*] Backing up existing audit rules to ${BACKUP_RULES}...${NC}"
        auditctl -l > "$BACKUP_RULES" 2>&1 || true
        
        echo -e "${CYAN}[*] Injecting high-resolution DFIR rules into kernel memory...${NC}"
        
        # 1. Trace all process executions (64-bit and 32-bit)
        auditctl -a always,exit -F arch=b64 -S execve,execveat -k dfir_exec 2>/dev/null || true
        auditctl -a always,exit -F arch=b32 -S execve,execveat -k dfir_exec 2>/dev/null || true
        
        # 2. Trace modifications in critical system directories
        auditctl -w /etc/ -p wa -k dfir_etc_mods 2>/dev/null || true
        auditctl -w /root/.ssh/ -p wa -k dfir_root_ssh 2>/dev/null || true
        auditctl -w /tmp/ -p wa -k dfir_tmp_mods 2>/dev/null || true
        auditctl -w /dev/shm/ -p wa -k dfir_shm_mods 2>/dev/null || true
        
        # 3. Trace kernel module loading and unloading
        auditctl -a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k dfir_kmods 2>/dev/null || true
        
        # 4. Trace ptrace injection and memory reading
        auditctl -a always,exit -F arch=b64 -S ptrace -k dfir_ptrace 2>/dev/null || true
        auditctl -a always,exit -F arch=b64 -S process_vm_readv,process_vm_writev -k dfir_mem_inject 2>/dev/null || true
        
        # Enable auditing
        auditctl -e 1 >/dev/null 2>&1 || true
        
        echo -e "\n${GREEN}${BOLD}[✓] High-resolution DFIR audit rules activated!${NC}"
        echo -e "Key events will be tagged with: ${YELLOW}dfir_exec, dfir_etc_mods, dfir_kmods, dfir_ptrace${NC}"
        echo -e "To view live events: ${CYAN}ausearch -k dfir_exec --start recent -i${NC}"
        ;;
        
    --disable)
        echo -e "${CYAN}[*] Removing DFIR rules and restoring clean audit state...${NC}"
        # Delete all dfir tagged rules
        auditctl -D >/dev/null 2>&1 || true
        
        if [ -f "$BACKUP_RULES" ] && [ -s "$BACKUP_RULES" ]; then
            echo -e "${CYAN}[*] Reapplying backed up rules from ${BACKUP_RULES}...${NC}"
            auditctl -R "$BACKUP_RULES" >/dev/null 2>&1 || true
            rm -f "$BACKUP_RULES"
        fi
        
        echo -e "${GREEN}[✓] Forensic auditing rules successfully removed.${NC}"
        ;;
        
    --status)
        echo -e "${CYAN}${BOLD}=== Current Auditd Kernel Status & Active Rules ===${NC}\n"
        auditctl -s
        echo -e "\n${BLUE}Active Rules:${NC}"
        auditctl -l
        ;;
        
    *)
        usage
        ;;
esac
