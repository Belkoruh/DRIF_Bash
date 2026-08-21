#!/usr/bin/env bash
# ==============================================================================
# Script: RevokeSessions.sh
# Description: Immediate interactive session termination and Kerberos ticket purge
# Documentation: Terminates all active remote interactive SSH/TTY sessions (excluding
#                the current analyst terminal), terminates systemd/loginctl sessions,
#                and purges active Kerberos ticket caches.
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

CURRENT_PTS=$(tty 2>/dev/null | sed 's#/dev/##' || echo "")

echo -e "${CYAN}${BOLD}=== Emergency Interactive Session Revocation ===${NC}\n"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Root privileges recommended to terminate all user sessions.${NC}" >&2
fi

echo -e "${BLUE}[*] Current analyst terminal : ${GREEN}${CURRENT_PTS:-Unknown}${NC}"

# 1. Terminate remote pseudo-terminal sessions (pts/*)
echo -e "${CYAN}[1] Terminating remote pseudo-terminals (pts)...${NC}"
who | while read -r usr line_tty date_val time_val host_from; do
    if [ "$line_tty" != "$CURRENT_PTS" ]; then
        echo -e "${YELLOW}[!] Disconnecting user ${usr} on ${line_tty} (${host_from})...${NC}"
        pkill -9 -t "$line_tty" 2>/dev/null || true
    fi
done

# 2. Terminate systemd loginctl sessions
if command -v loginctl >/dev/null 2>&1; then
    echo -e "${CYAN}[2] Revoking systemd loginctl sessions...${NC}"
    loginctl list-sessions --no-legend 2>/dev/null | while read -r sess_id uid_val user_val seat_val tty_val; do
        if [ "$tty_val" != "$CURRENT_PTS" ] && [ -n "$sess_id" ]; then
            loginctl terminate-session "$sess_id" 2>/dev/null || true
        fi
    done
fi

# 3. Purge Kerberos ticket caches
echo -e "${CYAN}[3] Purging Kerberos ticket caches (/tmp/krb5cc_*)...${NC}"
if command -v kdestroy >/dev/null 2>&1; then
    kdestroy -A 2>/dev/null || true
fi
rm -f /tmp/krb5cc_* 2>/dev/null || true

echo -e "\n${GREEN}${BOLD}[✓] Session revocation completed successfully.${NC}"
