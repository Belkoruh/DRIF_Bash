#!/usr/bin/env bash
# ==============================================================================
# Script: LocalUserResponse.sh
# Description: Immediate neutralization and containment of a compromised local user
# Documentation: Locks user password, forces immediate account expiration, changes
#                login shell to /sbin/nologin, quarantines ~/.ssh/authorized_keys,
#                kills all user processes, and terminates interactive sessions.
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

TARGET_USER="${1:-}"

if [ -z "$TARGET_USER" ]; then
    echo -e "${RED}[!] Error: Please specify the username to neutralize.${NC}" >&2
    echo "Usage: $0 <Username>" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Error: Root privileges are required for this containment action.${NC}" >&2
    exit 1
fi

if ! id "$TARGET_USER" >/dev/null 2>&1; then
    echo -e "${RED}[!] User '${TARGET_USER}' does not exist on this system.${NC}" >&2
    exit 1
fi

if [ "$TARGET_USER" = "root" ]; then
    echo -e "${RED}[!] Safety guard: Cannot neutralize the root account with this script.${NC}" >&2
    exit 1
fi

echo -e "${RED}${BOLD}=== Neutralizing Compromised User Account: ${TARGET_USER} ===${NC}\n"

# 1. Lock password
echo -e "${CYAN}[1] Locking account password...${NC}"
passwd -l "$TARGET_USER" 2>/dev/null || usermod -L "$TARGET_USER" 2>/dev/null || true
echo -e "${GREEN}[+] Password locked.${NC}"

# 2. Force immediate account expiration
echo -e "${CYAN}[2] Setting immediate account expiration...${NC}"
if command -v chage >/dev/null 2>&1; then
    chage -E 0 "$TARGET_USER" 2>/dev/null || true
    echo -e "${GREEN}[+] Expiration date set to 0 (expired).${NC}"
fi

# 3. Change default login shell to nologin
echo -e "${CYAN}[3] Changing login shell to /sbin/nologin...${NC}"
nologin_bin="/sbin/nologin"
[ -f /usr/sbin/nologin ] && nologin_bin="/usr/sbin/nologin"
[ ! -f "$nologin_bin" ] && nologin_bin="/bin/false"
usermod -s "$nologin_bin" "$TARGET_USER" 2>/dev/null || true
echo -e "${GREEN}[+] Shell updated to ${nologin_bin}.${NC}"

# 4. Quarantine SSH authorized_keys
user_home=$(eval echo "~${TARGET_USER}")
if [ -d "${user_home}/.ssh" ]; then
    echo -e "${CYAN}[4] Quarantining SSH authorized_keys...${NC}"
    ts=$(date +"%Y%m%d_%H%M%S")
    for ak in "${user_home}/.ssh/authorized_keys" "${user_home}/.ssh/authorized_keys2"; do
        if [ -f "$ak" ]; then
            mv "$ak" "${ak}.quarantined_${ts}" 2>/dev/null
            chmod 000 "${ak}.quarantined_${ts}" 2>/dev/null
            echo -e "${YELLOW}[!] Key moved to quarantine: ${ak} -> ${ak}.quarantined_${ts}${NC}"
        fi
    done
fi

# 5. Terminate systemd user sessions
echo -e "${CYAN}[5] Terminating active user sessions...${NC}"
if command -v loginctl >/dev/null 2>&1; then
    loginctl terminate-user "$TARGET_USER" 2>/dev/null || true
fi

# 6. Forcefully kill all processes owned by the user
echo -e "${CYAN}[6] Killing all active user processes...${NC}"
pkill -9 -u "$TARGET_USER" 2>/dev/null || true

echo -e "\n${GREEN}${BOLD}[✓] User account ${TARGET_USER} has been fully neutralized.${NC}"
