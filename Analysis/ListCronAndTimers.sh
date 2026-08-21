#!/usr/bin/env bash
# ==============================================================================
# Script: ListCronAndTimers.sh
# Description: Consolidated overview of scheduled tasks and systemd timers on Linux
# Documentation: Enumerates Systemd timers, system crontabs, cron.d/daily/hourly directories,
#                user crontabs (/var/spool/cron), and deferred atq jobs.
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

echo -e "${CYAN}${BOLD}=== Consolidated Scheduled Tasks & Timers Triage ===${NC}\n"

# 1. Systemd Timers
echo -e "${BLUE}${BOLD}[1] Active Systemd Timers:${NC}"
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-timers --all --no-pager 2>/dev/null | head -n 25
else
    echo "systemctl not available."
fi
echo ""

# 2. System Crontab (/etc/crontab)
echo -e "${BLUE}${BOLD}[2] System Crontab (/etc/crontab):${NC}"
if [ -f /etc/crontab ]; then
    grep -v '^[#[:space:]]*$' /etc/crontab | while read -r line; do
        echo -e " - ${line}"
    done
else
    echo "/etc/crontab file not found."
fi
echo ""

# 3. Cron Directories (/etc/cron.*)
echo -e "${BLUE}${BOLD}[3] Cron Directory Executables (/etc/cron.*):${NC}"
for cdir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$cdir" ]; then
        echo -e " ${CYAN}Directory ${cdir}:${NC}"
        for cf in "$cdir"/*; do
            [ -f "$cf" ] || continue
            echo -e "  - $(basename "$cf") [$(stat -c "%U:%G %a" "$cf" 2>/dev/null || echo "")]"
        done
    fi
done
echo ""

# 4. User Crontabs (/var/spool/cron)
echo -e "${BLUE}${BOLD}[4] User Crontabs (/var/spool/cron):${NC}"
for spool in /var/spool/cron/crontabs /var/spool/cron; do
    if [ -d "$spool" ]; then
        for ufile in "$spool"/*; do
            [ -f "$ufile" ] || continue
            echo -e " ${YELLOW}User $(basename "$ufile"):${NC}"
            grep -v '^[#[:space:]]*$' "$ufile" | while read -r uline; do
                echo -e "  - ${uline}"
            done
        done
    fi
done
echo ""

# 5. At Queue (atq)
echo -e "${BLUE}${BOLD}[5] Deferred Jobs Queue (atq):${NC}"
if command -v atq >/dev/null 2>&1; then
    at_list=$(atq 2>/dev/null || true)
    if [ -n "$at_list" ]; then
        echo "$at_list"
    else
        echo "No 'at' jobs queued."
    fi
else
    echo "Command 'atq' not available."
fi
