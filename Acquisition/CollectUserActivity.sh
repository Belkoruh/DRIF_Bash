#!/usr/bin/env bash
# ==============================================================================
# Script: CollectUserActivity.sh
# Description: Forensic triage and acquisition of Linux user accounts and activity
# Documentation: Collects user accounts, groups, sudoers privileges, active sessions (utmp),
#                successful/failed login records (wtmp, btmp, last, lastb),
#                and all shell command histories (.bash_history, .zsh_history, etc.).
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

TARGET_DIR="${1:-.}"
OUTPUT_DIR="${TARGET_DIR}/UserInformation"
CSV_DIR="${TARGET_DIR}/CSV_Results"

mkdir -p "${OUTPUT_DIR}" "${CSV_DIR}"

log_info() {
    echo -e "${CYAN}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

echo -e "${CYAN}${BOLD}=== User Activity Artifacts Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

# ------------------------------------------------------------------------------
# 1. User Accounts & Groups
# ------------------------------------------------------------------------------
log_info "Collecting user accounts, groups, and permissions..."
[ -f /etc/passwd ] && cp -p /etc/passwd "${OUTPUT_DIR}/passwd.txt"
[ -f /etc/group ] && cp -p /etc/group "${OUTPUT_DIR}/group.txt"
[ -f /etc/gshadow ] && cp -p /etc/gshadow "${OUTPUT_DIR}/gshadow.txt" 2>/dev/null
[ -f /etc/login.defs ] && cp -p /etc/login.defs "${OUTPUT_DIR}/login.defs.txt" 2>/dev/null
[ -f /etc/subuid ] && cp -p /etc/subuid "${OUTPUT_DIR}/subuid.txt" 2>/dev/null
[ -f /etc/subgid ] && cp -p /etc/subgid "${OUTPUT_DIR}/subgid.txt" 2>/dev/null

if [ -f /etc/shadow ]; then
    cp -p /etc/shadow "${OUTPUT_DIR}/shadow.txt" 2>/dev/null || true
fi

# Export local users to CSV
echo "Username,UID,GID,HomeDir,Shell,PasswordStatus,IsUIDZero,AccountLocked" > "${CSV_DIR}/LocalUsers.csv"
if [ -f /etc/passwd ]; then
    while IFS=: read -r username password uid gid gecos homedir shell; do
        is_uid_zero="False"
        [ "$uid" = "0" ] && is_uid_zero="True"
        
        pwd_status="NO_PASSWORD_OR_LOCKED"
        is_locked="False"
        
        if [ -f /etc/shadow ] && [ -r /etc/shadow ]; then
            shadow_entry=$(grep -E "^${username}:" /etc/shadow 2>/dev/null || true)
            if [ -n "$shadow_entry" ]; then
                sh_pwd=$(echo "$shadow_entry" | cut -d: -f2)
                if [[ "$sh_pwd" =~ ^! ]] || [[ "$sh_pwd" =~ ^\* ]]; then
                    pwd_status="LOCKED_OR_DISABLED"
                    is_locked="True"
                elif [ -z "$sh_pwd" ]; then
                    pwd_status="EMPTY_PASSWORD_CRITICAL"
                    log_warn "ALERT: User ${username} has an empty password!"
                else
                    pwd_status="PASSWORD_SET"
                fi
            fi
        fi
        
        # Alert if a non-root account has UID 0 (Root backdoor)
        if [ "$uid" = "0" ] && [ "$username" != "root" ]; then
            log_warn "CRITICAL ALERT: Non-root account with UID 0 detected: ${username}!"
        fi
        
        echo "\"${username}\",\"${uid}\",\"${gid}\",\"${homedir}\",\"${shell}\",\"${pwd_status}\",\"${is_uid_zero}\",\"${is_locked}\"" >> "${CSV_DIR}/LocalUsers.csv"
    done < /etc/passwd
fi

# ------------------------------------------------------------------------------
# 2. Sudo Privileges & Sudoers Configurations
# ------------------------------------------------------------------------------
log_info "Collecting and auditing sudoers configuration..."
mkdir -p "${OUTPUT_DIR}/Sudoers"
[ -f /etc/sudoers ] && cp -p /etc/sudoers "${OUTPUT_DIR}/Sudoers/sudoers" 2>/dev/null
[ -d /etc/sudoers.d ] && cp -rp /etc/sudoers.d "${OUTPUT_DIR}/Sudoers/sudoers.d" 2>/dev/null

echo "Source,Rule,HasNOPASSWD,HasALL" > "${CSV_DIR}/SudoPrivileges.csv"
find /etc/sudoers /etc/sudoers.d/ -type f 2>/dev/null | while read -r sfile; do
    grep -v '^[#[:space:]]*$' "$sfile" 2>/dev/null | while read -r srule; do
        has_nopasswd="False"
        has_all="False"
        [[ "$srule" =~ NOPASSWD ]] && has_nopasswd="True"
        [[ "$srule" =~ ALL ]] && has_all="True"
        clean_rule=$(echo "$srule" | sed 's/"/\\"/g')
        echo "\"${sfile}\",\"${clean_rule}\",\"${has_nopasswd}\",\"${has_all}\"" >> "${CSV_DIR}/SudoPrivileges.csv"
    done
done

# ------------------------------------------------------------------------------
# 3. Active Sessions & Login Records (utmp, wtmp, btmp, last, lastb)
# ------------------------------------------------------------------------------
log_info "Collecting active user sessions and login history..."
mkdir -p "${OUTPUT_DIR}/LoginRecords"

# Active sessions (who / w)
w > "${OUTPUT_DIR}/LoginRecords/w_active_sessions.txt" 2>&1
who -a > "${OUTPUT_DIR}/LoginRecords/who_active_sessions.txt" 2>&1

echo "User,TTY,FromIP,LoginTime,Idle,JCPU,PCPU,Command" > "${CSV_DIR}/ActiveSessions.csv"
w -h 2>/dev/null | while read -r user tty from login idle jcpu pcpu what; do
    echo "\"${user}\",\"${tty}\",\"${from}\",\"${login}\",\"${idle}\",\"${jcpu}\",\"${pcpu}\",\"${what}\"" >> "${CSV_DIR}/ActiveSessions.csv"
done

# Login history (last)
if command -v last >/dev/null 2>&1; then
    last -F -a -w > "${OUTPUT_DIR}/LoginRecords/last_logins.txt" 2>&1
    echo "User,TTY,Host,LoginTime,LogoutTime,Duration" > "${CSV_DIR}/LoginHistory.csv"
    last -F -a -w 2>/dev/null | head -n 500 | grep -v 'reboot' | grep -v 'wtmp begins' | while read -r line; do
        usr=$(echo "$line" | awk '{print $1}')
        tty=$(echo "$line" | awk '{print $2}')
        clean_line=$(echo "$line" | sed 's/"/\\"/g')
        echo "\"${usr}\",\"${tty}\",\"N/A\",\"${clean_line}\",\"N/A\",\"N/A\"" >> "${CSV_DIR}/LoginHistory.csv"
    done
fi

# Failed login attempts (lastb - brute-force triage)
if command -v lastb >/dev/null 2>&1; then
    lastb -F -a -w > "${OUTPUT_DIR}/LoginRecords/lastb_failed_logins.txt" 2>&1
    echo "User,TTY,Host,Details" > "${CSV_DIR}/FailedLogins.csv"
    lastb -F -a -w 2>/dev/null | head -n 500 | grep -v 'btmp begins' | while read -r line; do
        usr=$(echo "$line" | awk '{print $1}')
        tty=$(echo "$line" | awk '{print $2}')
        clean_line=$(echo "$line" | sed 's/"/\\"/g')
        echo "\"${usr}\",\"${tty}\",\"N/A\",\"${clean_line}\"" >> "${CSV_DIR}/FailedLogins.csv"
    done
fi

# Lastlog
if command -v lastlog >/dev/null 2>&1; then
    lastlog > "${OUTPUT_DIR}/LoginRecords/lastlog.txt" 2>&1
fi

# Copy raw binary wtmp/btmp/utmp logs
for binlog in /var/run/utmp /run/utmp /var/log/wtmp /var/log/btmp; do
    if [ -f "$binlog" ]; then
        cp -p "$binlog" "${OUTPUT_DIR}/LoginRecords/$(basename "$binlog")" 2>/dev/null
        if command -v utmpdump >/dev/null 2>&1; then
            utmpdump "$binlog" > "${OUTPUT_DIR}/LoginRecords/$(basename "$binlog")_dump.txt" 2>&1 || true
        fi
    fi
done

# ------------------------------------------------------------------------------
# 4. User Shell Command Histories (.bash_history, .zsh_history...)
# ------------------------------------------------------------------------------
log_info "Collecting command histories for all user profiles..."
mkdir -p "${OUTPUT_DIR}/ShellHistories"

echo "User,HistoryFile,LineNumber,Command,IsSuspicious" > "${CSV_DIR}/CommandHistory.csv"

suspicious_pattern='(nc |ncat |netcat |bash -i|/dev/tcp/|curl.*\|.*sh|wget.*\|.*sh|chmod \+s|chmod 4777|chmod 777 /|chattr \+i|useradd|usermod|base64 -d|nmap|hydra|sqlmap|mimikatz|bloodhound|chisel|socat|iptables -F|rm -rf /|/proc/|LD_PRELOAD|eval\()'

for uhome in /root /home/*; do
    [ -d "$uhome" ] || continue
    u_name=$(basename "$uhome")
    mkdir -p "${OUTPUT_DIR}/ShellHistories/${u_name}"
    
    for hfile in .bash_history .zsh_history .sh_history .history .python_history .mysql_history .psql_history .rediscli_history .nano_history .viminfo .lesshst; do
        full_h="${uhome}/${hfile}"
        if [ -f "$full_h" ]; then
            cp -p "$full_h" "${OUTPUT_DIR}/ShellHistories/${u_name}/${hfile}" 2>/dev/null
            
            line_num=0
            while IFS= read -r cmd || [ -n "$cmd" ]; do
                ((line_num++))
                is_susp="False"
                if [[ "$cmd" =~ $suspicious_pattern ]]; then
                    is_susp="True"
                    log_warn "Suspicious command found for user [${u_name}] line ${line_num}: ${cmd}"
                fi
                clean_cmd=$(echo "$cmd" | sed 's/"/\\"/g')
                echo "\"${u_name}\",\"${hfile}\",\"${line_num}\",\"${clean_cmd}\",\"${is_susp}\"" >> "${CSV_DIR}/CommandHistory.csv"
            done < "$full_h"
        fi
    done
done

log_success "User activity triage completed successfully."
