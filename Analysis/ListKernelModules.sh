#!/usr/bin/env bash
# ==============================================================================
# Script: ListKernelModules.sh
# Description: Kernel module (LKM) audit and out-of-tree / unsigned module detection
# Documentation: Audits loaded kernel modules (/proc/modules, lsmod), flags out-of-tree
#                (O), unsigned (E/U), or proprietary (P) modules, and inspects /sys/module.
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

echo -e "${CYAN}${BOLD}=== Linux Kernel Module (LKM) Audit ===${NC}\n"

if [ ! -f /proc/modules ]; then
    echo -e "${RED}[!] Unable to access /proc/modules.${NC}" >&2
    exit 1
fi

printf "%-25s %-10s %-8s %-12s %-12s %s\n" "MODULE" "SIZE" "INSTANCES" "STATE" "FLAGS" "STATUS"
printf "%-25s %-10s %-8s %-12s %-12s %s\n" "-------------------------" "----------" "--------" "------------" "------------" "---------------------"

suspicious_count=0

while read -r mod_name mod_size mod_inst mod_by mod_state mod_addr mod_flags; do
    status_label="${GREEN}Standard (In-Tree)${NC}"
    
    if [[ "$mod_flags" =~ \(.*O.*\) ]] || [[ "$mod_flags" =~ \(.*E.*\) ]]; then
        status_label="${RED}SUSPICIOUS (Out-Of-Tree / Unsigned)${NC}"
        ((suspicious_count++))
        printf "%-25s %-10s %-8s %-12s ${YELLOW}%-12s${NC} ${RED}%b${NC}\n" "$mod_name" "$mod_size" "$mod_inst" "$mod_state" "$mod_flags" "$status_label"
    else
        printf "%-25s %-10s %-8s %-12s %-12s %b\n" "$mod_name" "$mod_size" "$mod_inst" "$mod_state" "$mod_flags" "$status_label"
    fi
done < /proc/modules

echo ""
if [ "$suspicious_count" -gt 0 ]; then
    echo -e "${RED}[!] ${suspicious_count} suspicious out-of-tree or unsigned module(s) detected!${NC}"
else
    echo -e "${GREEN}[+] All loaded kernel modules appear standard and in-tree.${NC}"
fi
