#!/usr/bin/env bash
# ==============================================================================
# Script: ListNetworkListeners.sh
# Description: Triage and inspection of open listening network ports on Linux
# Documentation: Identifies all listening TCP/UDP ports, associated binary names,
#                absolute executable paths (/proc/PID/exe), owning users,
#                and whether the socket is exposed publicly (0.0.0.0 / ::) or to localhost.
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

echo -e "${CYAN}${BOLD}=== Listening Network Sockets & Services Triage ===${NC}\n"

printf "%-6s %-22s %-8s %-18s %-25s %s\n" "PROTO" "LOCAL ADDRESS" "PID" "USER" "PROCESS" "EXE PATH"
printf "%-6s %-22s %-8s %-18s %-25s %s\n" "------" "----------------------" "--------" "------------------" "-------------------------" "-------------------"

if command -v ss >/dev/null 2>&1; then
    ss -tulpn -H 2>/dev/null | while read -r proto state recvq sendq local remote users; do
        loc_ip="${local%:*}"
        loc_port="${local##*:}"
        
        pname="-"
        pid="-"
        exe="-"
        puser="-"
        
        if [ -n "$users" ]; then
            pname=$(echo "$users" | grep -oP 'users:\(\("\K[^"]+' || echo "-")
            pid=$(echo "$users" | grep -oP 'pid=\K\d+' || echo "-")
            if [ "$pid" != "-" ] && [ -d "/proc/$pid" ]; then
                exe=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "-")
                puid=$(grep -oP '^Uid:\s*\K\d+' "/proc/$pid/status" 2>/dev/null || echo "")
                [ -n "$puid" ] && puser=$(id -nu "$puid" 2>/dev/null || echo "$puid")
            fi
        fi
        
        # Highlight in red if exposed on all interfaces (0.0.0.0 or *)
        loc_display="${local}"
        if [[ "$local" =~ ^(0\.0\.0\.0|\*|\[::\]): ]]; then
            printf "%-6s ${RED}%-22s${NC} %-8s %-18s %-25s %s\n" "$proto" "$loc_display" "$pid" "$puser" "$pname" "$exe"
        else
            printf "%-6s ${GREEN}%-22s${NC} %-8s %-18s %-25s %s\n" "$proto" "$loc_display" "$pid" "$puser" "$pname" "$exe"
        fi
    done
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulpn 2>/dev/null | grep -E '(LISTEN|udp)' | head -n 50
fi
