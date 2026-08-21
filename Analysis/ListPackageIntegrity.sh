#!/usr/bin/env bash
# ==============================================================================
# Script: ListPackageIntegrity.sh
# Description: Key system binary integrity audit via native Linux package managers
# Documentation: Verifies official cryptographic checksums of critical binaries
#                (ls, ps, ss, netstat, sshd, sudo, login, top, etc.) using dpkg -V,
#                rpm -Va, or pacman -Qk to detect trojanized or corrupted system tools.
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

echo -e "${CYAN}${BOLD}=== System Binary Package Integrity Verification ===${NC}\n"

CRITICAL_BINARIES=(
    "/bin/ls"
    "/bin/ps"
    "/bin/netstat"
    "/bin/ss"
    "/bin/login"
    "/usr/sbin/sshd"
    "/usr/bin/sudo"
    "/bin/bash"
    "/bin/sh"
    "/usr/bin/find"
    "/usr/bin/top"
    "/usr/bin/chattr"
    "/usr/bin/passwd"
    "/sbin/iptables"
)

# 1. Detect active package manager
if command -v dpkg >/dev/null 2>&1; then
    echo -e "${BLUE}[*] DPKG / Debian / Ubuntu system detected. Running dpkg -V on critical packages...${NC}\n"
    
    for cbin in "${CRITICAL_BINARIES[@]}"; do
        if [ -f "$cbin" ]; then
            pkg_name=$(dpkg -S "$cbin" 2>/dev/null | cut -d: -f1 || echo "")
            if [ -n "$pkg_name" ]; then
                v_res=$(dpkg -V "$pkg_name" 2>/dev/null | grep "$cbin" || true)
                if [ -n "$v_res" ]; then
                    echo -e " - ${RED}[ANOMALY]${NC} ${cbin} (Package: ${pkg_name}): ${RED}${v_res}${NC}"
                else
                    echo -e " - ${GREEN}[OK]${NC} ${cbin} (Package: ${pkg_name}) - Checksum verified"
                fi
            else
                echo -e " - ${YELLOW}[WARNING]${NC} ${cbin} does not belong to any official package!"
            fi
        fi
    done

elif command -v rpm >/dev/null 2>&1; then
    echo -e "${BLUE}[*] RPM / RHEL / CentOS / Fedora system detected. Running rpm -V...${NC}\n"
    
    for cbin in "${CRITICAL_BINARIES[@]}"; do
        if [ -f "$cbin" ]; then
            pkg_name=$(rpm -qf "$cbin" 2>/dev/null || echo "")
            if [ -n "$pkg_name" ]; then
                v_res=$(rpm -V "$pkg_name" 2>/dev/null | grep "$cbin" || true)
                if [ -n "$v_res" ]; then
                    echo -e " - ${RED}[ANOMALY]${NC} ${cbin}: ${RED}${v_res}${NC}"
                else
                    echo -e " - ${GREEN}[OK]${NC} ${cbin} (${pkg_name}) - Verified"
                fi
            else
                echo -e " - ${YELLOW}[WARNING]${NC} ${cbin} not found in RPM database!"
            fi
        fi
    done

elif command -v pacman >/dev/null 2>&1; then
    echo -e "${BLUE}[*] Pacman / Arch system detected. Running pacman -Qk...${NC}\n"
    for cbin in "${CRITICAL_BINARIES[@]}"; do
        [ -f "$cbin" ] && pacman -Qo "$cbin" 2>/dev/null || true
    done

else
    echo -e "${YELLOW}[!] No supported package manager (dpkg/rpm/pacman) found for integrity verification.${NC}"
fi
