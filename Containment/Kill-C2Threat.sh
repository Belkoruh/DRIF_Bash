#!/usr/bin/env bash
# ==============================================================================
# Script: Kill-C2Threat.sh
# Description: Surgical C2 threat neutralization, process termination & firewall block
# Documentation: Surgically eliminates active threats by terminating specific PIDs,
#                blocking malicious remote IP addresses in iptables, and quarantining
#                associated malicious executable binaries.
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

QUARANTINE_DIR="/var/dfir_quarantine"

usage() {
    echo -e "${CYAN}${BOLD}=== Surgical Threat Neutralization Tool ===${NC}"
    echo "Usage:"
    echo "  $0 [--pid <PID>] [--ip <Remote_IP>] [--binary <Binary_Path>] [--port <Port>]"
    echo ""
    echo "Options:"
    echo "  --pid <PID>         Kills the specified PID and quarantines its executable"
    echo "  --ip <IP>           Blocks the specified IP address in iptables (INPUT & OUTPUT)"
    echo "  --binary <Path>     Kills all processes using this binary and quarantines it"
    echo "  --port <Port>       Kills all connections on this port and blocks it in iptables"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --pid 4589 --ip 198.51.100.24"
    echo "  sudo $0 --binary /tmp/evil_payload"
    echo "  sudo $0 --ip 203.0.113.50"
    exit 1
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] Error: Root privileges are required for containment actions.${NC}" >&2
        exit 1
    fi
}

quarantine_file() {
    local src_file="$1"
    [ -f "$src_file" ] || return 0
    
    mkdir -p "$QUARANTINE_DIR"
    ts=$(date +"%Y%m%d_%H%M%S")
    fname=$(basename "$src_file")
    dest="${QUARANTINE_DIR}/${fname}_${ts}.quarantine"
    
    f_sha=$(sha256sum "$src_file" 2>/dev/null | awk '{print $1}')
    
    cp -p "$src_file" "$dest" 2>/dev/null || true
    rm -f "$src_file" 2>/dev/null || true
    chmod 000 "$dest" 2>/dev/null || true
    
    if command -v chattr >/dev/null 2>&1; then
        chattr +i "$dest" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+] Binary moved to quarantine: ${dest}${NC}"
    echo -e "    SHA-256: ${CYAN}${f_sha}${NC}"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") | QUARANTINE | ${src_file} | ${dest} | ${f_sha}" >> "${QUARANTINE_DIR}/quarantine_manifest.log"
}

check_root
[ $# -eq 0 ] && usage

TARGET_PID=""
TARGET_IP=""
TARGET_BIN=""
TARGET_PORT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --pid)
            TARGET_PID="$2"
            shift 2
            ;;
        --ip)
            TARGET_IP="$2"
            shift 2
            ;;
        --binary)
            TARGET_BIN="$2"
            shift 2
            ;;
        --port)
            TARGET_PORT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}[!] Unknown option: $1${NC}" >&2
            usage
            ;;
    esac
done

echo -e "${RED}${BOLD}=== Executing Surgical Threat Containment ===${NC}\n"

# 1. Neutralize PID
if [ -n "$TARGET_PID" ]; then
    if [ -d "/proc/${TARGET_PID}" ]; then
        pname=$(cat "/proc/${TARGET_PID}/comm" 2>/dev/null || echo "unknown")
        exe_path=$(readlink "/proc/${TARGET_PID}/exe" 2>/dev/null || echo "")
        
        echo -e "${CYAN}[*] Neutralizing PID ${TARGET_PID} (${pname})...${NC}"
        
        # Quarantine binary before killing process if valid file on disk
        if [ -n "$exe_path" ] && [ -f "$exe_path" ]; then
            quarantine_file "$exe_path"
        fi
        
        kill -9 "$TARGET_PID" 2>/dev/null || true
        echo -e "${GREEN}[✓] Process PID ${TARGET_PID} terminated.${NC}"
    else
        echo -e "${YELLOW}[!] PID ${TARGET_PID} is not running.${NC}"
    fi
fi

# 2. Neutralize Binary
if [ -n "$TARGET_BIN" ]; then
    if [ -f "$TARGET_BIN" ]; then
        echo -e "${CYAN}[*] Terminating processes running binary: ${TARGET_BIN}...${NC}"
        fuser -k -9 "$TARGET_BIN" 2>/dev/null || true
        quarantine_file "$TARGET_BIN"
    else
        echo -e "${YELLOW}[!] Target binary ${TARGET_BIN} not found on disk.${NC}"
    fi
fi

# 3. Block Remote IP
if [ -n "$TARGET_IP" ]; then
    echo -e "${CYAN}[*] Blocking IP address ${TARGET_IP} in iptables firewall...${NC}"
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT 1 -s "$TARGET_IP" -j DROP
        iptables -I OUTPUT 1 -d "$TARGET_IP" -j DROP
        iptables -I FORWARD 1 -s "$TARGET_IP" -j DROP
        iptables -I FORWARD 1 -d "$TARGET_IP" -j DROP
        echo -e "${GREEN}[✓] IP ${TARGET_IP} blocked at top of iptables ruleset.${NC}"
    fi
fi

# 4. Block Port & Kill Connections
if [ -n "$TARGET_PORT" ]; then
    echo -e "${CYAN}[*] Terminating sockets on port ${TARGET_PORT}...${NC}"
    if command -v fuser >/dev/null 2>&1; then
        fuser -k -9 "${TARGET_PORT}/tcp" 2>/dev/null || true
        fuser -k -9 "${TARGET_PORT}/udp" 2>/dev/null || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT 1 -p tcp --dport "$TARGET_PORT" -j DROP
        iptables -I INPUT 1 -p udp --dport "$TARGET_PORT" -j DROP
        iptables -I OUTPUT 1 -p tcp --dport "$TARGET_PORT" -j DROP
        iptables -I OUTPUT 1 -p udp --dport "$TARGET_PORT" -j DROP
        echo -e "${GREEN}[✓] Port ${TARGET_PORT} (TCP/UDP) blocked in firewall.${NC}"
    fi
fi

echo -e "\n${GREEN}${BOLD}[✓] Surgical threat neutralization completed.${NC}"
