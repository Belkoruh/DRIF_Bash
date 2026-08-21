#!/usr/bin/env bash
# ==============================================================================
# Script: ScanSuspiciousStaging.sh
# Description: Rapid detection of webshells, payloads, and ELF binaries in staging dirs
# Documentation: Scans world-writable directories (/tmp, /dev/shm, /var/tmp, /run/user),
#                identifies executable ELF binaries, script shebangs, hidden files,
#                and common reverse shell / webshell code patterns.
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

echo -e "${CYAN}${BOLD}=== Staging Directories Forensic Scan (/tmp, /dev/shm, /var/tmp) ===${NC}\n"

STAGING_DIRS=("/tmp" "/dev/shm" "/var/tmp" "/run/user" "/dev/mqueue")
SUSP_KEYWORDS='(bash -i|/dev/tcp/|nc -e|ncat -e|curl.*\|.*sh|wget.*\|.*sh|base64 -d|eval\(gzinflate|eval\(base64_decode|system\(\$_GET|passthru\(\$_POST|shell_exec\()'

found_anomalies=0

for sdir in "${STAGING_DIRS[@]}"; do
    [ -d "$sdir" ] || continue
    echo -e "${BLUE}[*] Scanning staging directory: ${CYAN}${sdir}${NC}..."
    
    find "$sdir" -maxdepth 4 -type f 2>/dev/null | while read -r sfile; do
        [ -f "$sfile" ] || continue
        
        is_susp="False"
        reasons=""
        
        # 1. Check if ELF executable binary
        if head -c 4 "$sfile" 2>/dev/null | grep -q $'\x7fELF'; then
            is_susp="True"
            reasons="[Executable ELF Binary]"
        fi
        
        # 2. Check executable permission
        if [ -x "$sfile" ] && [ "$is_susp" = "False" ]; then
            is_susp="True"
            reasons="[Executable File (+x)]"
        fi
        
        # 3. Check hidden filename
        fname=$(basename "$sfile")
        if [[ "$fname" =~ ^\.[^.] ]]; then
            reasons="${reasons} [Hidden Filename]"
        fi
        
        # 4. Search for suspicious payload patterns and reverse shell strings
        if grep -Eiq "$SUSP_KEYWORDS" "$sfile" 2>/dev/null; then
            is_susp="True"
            reasons="${reasons} [Payload/Reverse Shell Detected]"
        fi
        
        if [ "$is_susp" = "True" ]; then
            ((found_anomalies++))
            perms=$(stat -c "%a" "$sfile" 2>/dev/null || echo "")
            owner=$(stat -c "%U" "$sfile" 2>/dev/null || echo "")
            size=$(stat -c "%s" "$sfile" 2>/dev/null || echo "0")
            sha=$(sha256sum "$sfile" 2>/dev/null | awk '{print $1}')
            
            echo -e " - ${RED}[SUSPICIOUS]${NC} ${sfile}"
            echo -e "   - Reasons    : ${YELLOW}${reasons}${NC}"
            echo -e "   - Metadata   : Size ${size} bytes | Owner: ${owner} | Perms: ${perms}"
            echo -e "   - SHA-256    : ${CYAN}${sha}${NC}\n"
        fi
    done
done

if [ "$found_anomalies" -eq 0 ]; then
    echo -e "${GREEN}[+] No overtly malicious ELF binaries or payload scripts found in staging directories.${NC}"
fi
