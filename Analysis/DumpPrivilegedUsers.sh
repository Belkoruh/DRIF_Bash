#!/usr/bin/env bash
# ==============================================================================
# Script: DumpPrivilegedUsers.sh
# Description: Rapid audit of high-privilege accounts and sudoers rules on Linux
# Documentation: Identifies all accounts with UID 0, members of sudo/wheel/admin groups,
#                permissive sudoers rules (NOPASSWD), and accounts with empty passwords.
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

echo -e "${CYAN}${BOLD}=== Privileged User Accounts & Sudoers Audit (Linux) ===${NC}\n"

# 1. Accounts with UID 0
echo -e "${BLUE}${BOLD}[1] Accounts with UID 0 (Root Equivalent):${NC}"
awk -F: '($3 == 0) { print " - User: " $1 " (UID: 0, Shell: " $7 ", Home: " $6 ")" }' /etc/passwd
uid0_nonroot=$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd)
if [ -n "$uid0_nonroot" ]; then
    echo -e "${RED}[!] CRITICAL ALERT: Non-root account with UID 0 detected: ${uid0_nonroot}${NC}"
fi
echo ""

# 2. Administrative Group Members (sudo, wheel, admin, root)
echo -e "${BLUE}${BOLD}[2] Administrative Group Memberships:${NC}"
for grp in root sudo wheel admin adm shadow; do
    if grep -E "^${grp}:" /etc/group >/dev/null 2>&1; then
        members=$(grep -E "^${grp}:" /etc/group | cut -d: -f4)
        echo -e " - Group ${CYAN}${grp}${NC}: ${members:-<no secondary members>}"
    fi
done
echo ""

# 3. Permissive Sudoers Rules (NOPASSWD and ALL)
echo -e "${BLUE}${BOLD}[3] Passwordless Sudo Rules (NOPASSWD) and ALL Permissions:${NC}"
find /etc/sudoers /etc/sudoers.d/ -type f 2>/dev/null | while read -r sf; do
    grep -v '^[#[:space:]]*$' "$sf" 2>/dev/null | grep -E '(NOPASSWD|ALL=\(ALL\)|ALL=\(ALL:ALL\))' | while read -r rule; do
        if [[ "$rule" =~ NOPASSWD ]]; then
            echo -e " - ${sf} : ${RED}${rule}${NC} [NOPASSWD]"
        else
            echo -e " - ${sf} : ${YELLOW}${rule}${NC}"
        fi
    done
done
echo ""

# 4. Shadow Password Audit
if [ -r /etc/shadow ]; then
    echo -e "${BLUE}${BOLD}[4] Password Hash Audit (/etc/shadow):${NC}"
    while IFS=: read -r user pass lastchg min max warn inact expire flag; do
        if [ -z "$pass" ]; then
            echo -e " - ${RED}[CRITICAL] User with empty password: ${user}${NC}"
        elif [[ "$pass" =~ ^\! ]] || [[ "$pass" =~ ^\* ]]; then
            : # Locked or disabled
        else
            hash_algo="Unknown"
            [[ "$pass" =~ ^\$1\$ ]] && hash_algo="MD5 (Weak)"
            [[ "$pass" =~ ^\$5\$ ]] && hash_algo="SHA-256"
            [[ "$pass" =~ ^\$6\$ ]] && hash_algo="SHA-512"
            [[ "$pass" =~ ^\$y\$ ]] && hash_algo="Yescrypt"
            [[ "$pass" =~ ^\$2[aby]\$ ]] && hash_algo="Bcrypt"
            echo -e " - Active user: ${GREEN}${user}${NC} (Algorithm: ${hash_algo})"
        fi
    done < /etc/shadow
fi
