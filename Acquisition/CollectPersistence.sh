#!/usr/bin/env bash
# ==============================================================================
# Script: CollectPersistence.sh
# Description: Forensic triage and acquisition of Linux persistence mechanisms
# Documentation: Collects Systemd services, Timers, Crontabs (system and user),
#                At jobs, shell startup hooks (/etc/profile.d, .bashrc), dynamic library
#                preloading (/etc/ld.so.preload), startup modules, Udev, Polkit, PAM,
#                and Autostart entries.
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
OUTPUT_DIR="${TARGET_DIR}/Persistence"
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

echo -e "${CYAN}${BOLD}=== Linux Persistence Artifacts Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "Category,Mechanism,Location,Details,RiskLevel" > "${CSV_DIR}/PersistenceSummary.csv"

# ------------------------------------------------------------------------------
# 1. Dynamic Preloaded Libraries (/etc/ld.so.preload) - CRITICAL
# ------------------------------------------------------------------------------
log_info "Checking /etc/ld.so.preload (dynamic library hijacking)..."
if [ -f /etc/ld.so.preload ]; then
    log_warn "CRITICAL ALERT: /etc/ld.so.preload exists on system!"
    cp -p /etc/ld.so.preload "${OUTPUT_DIR}/ld.so.preload" 2>/dev/null
    preload_content=$(cat /etc/ld.so.preload 2>/dev/null | tr '\n' ' ' || echo "")
    echo "\"Rootkit/Preload\",\"ld.so.preload\",\"/etc/ld.so.preload\",\"${preload_content}\",\"CRITICAL\"" >> "${CSV_DIR}/PersistenceSummary.csv"
else
    echo "File /etc/ld.so.preload absent (Normal)" > "${OUTPUT_DIR}/ld.so.preload.status.txt"
fi

if [ -d /etc/ld.so.conf.d ]; then
    mkdir -p "${OUTPUT_DIR}/ld.so.conf.d"
    cp -rp /etc/ld.so.conf* "${OUTPUT_DIR}/ld.so.conf.d/" 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# 2. Scheduled Tasks (Cron, Anacron, At)
# ------------------------------------------------------------------------------
log_info "Collecting scheduled tasks (Crontabs, Anacron, At)..."
mkdir -p "${OUTPUT_DIR}/Cron"

echo "Type,User,Schedule,Command,SourceFile" > "${CSV_DIR}/ScheduledTasks.csv"

# System crontab
if [ -f /etc/crontab ]; then
    cp -p /etc/crontab "${OUTPUT_DIR}/Cron/crontab_system" 2>/dev/null
    grep -v '^[#[:space:]]*$' /etc/crontab | while read -r line; do
        sched=$(echo "$line" | awk '{print $1,$2,$3,$4,$5}')
        usr=$(echo "$line" | awk '{print $6}')
        cmd=$(echo "$line" | cut -d' ' -f7- | sed 's/"/\\"/g')
        echo "\"SystemCrontab\",\"${usr}\",\"${sched}\",\"${cmd}\",\"/etc/crontab\"" >> "${CSV_DIR}/ScheduledTasks.csv"
        echo "\"ScheduledTask\",\"SystemCron\",\"/etc/crontab\",\"${cmd}\",\"INFO\"" >> "${CSV_DIR}/PersistenceSummary.csv"
    done
fi

# cron.* directories
for cdir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$cdir" ]; then
        dest_cdir="${OUTPUT_DIR}/Cron/${cdir##*/}"
        mkdir -p "$dest_cdir"
        cp -rp "${cdir}/"* "$dest_cdir/" 2>/dev/null || true
        
        for cfile in "${cdir}/"*; do
            [ -f "$cfile" ] || continue
            echo "\"DirectoryCron\",\"root\",\"N/A\",\"$(basename "$cfile")\",\"${cfile}\"" >> "${CSV_DIR}/ScheduledTasks.csv"
            echo "\"ScheduledTask\",\"CronDir\",\"${cfile}\",\"Executable in ${cdir}\",\"INFO\"" >> "${CSV_DIR}/PersistenceSummary.csv"
        done
    fi
done

# User crontabs
mkdir -p "${OUTPUT_DIR}/Cron/user_crontabs"
for spool in /var/spool/cron/crontabs /var/spool/cron; do
    if [ -d "$spool" ]; then
        for ufile in "${spool}/"*; do
            [ -f "$ufile" ] || continue
            uuser=$(basename "$ufile")
            cp -p "$ufile" "${OUTPUT_DIR}/Cron/user_crontabs/${uuser}_crontab" 2>/dev/null
            grep -v '^[#[:space:]]*$' "$ufile" | while read -r line; do
                sched=$(echo "$line" | awk '{print $1,$2,$3,$4,$5}')
                cmd=$(echo "$line" | cut -d' ' -f6- | sed 's/"/\\"/g')
                echo "\"UserCrontab\",\"${uuser}\",\"${sched}\",\"${cmd}\",\"${ufile}\"" >> "${CSV_DIR}/ScheduledTasks.csv"
                echo "\"ScheduledTask\",\"UserCron\",\"${ufile}\",\"User: ${uuser} - ${cmd}\",\"LOW\"" >> "${CSV_DIR}/PersistenceSummary.csv"
            done
        done
    fi
done

# At jobs
if command -v atq >/dev/null 2>&1; then
    atq > "${OUTPUT_DIR}/Cron/atq_jobs.txt" 2>&1 || true
fi
for atdir in /var/spool/at /var/spool/cron/atjobs; do
    if [ -d "$atdir" ]; then
        mkdir -p "${OUTPUT_DIR}/Cron/at_spool"
        cp -rp "${atdir}/"* "${OUTPUT_DIR}/Cron/at_spool/" 2>/dev/null || true
    fi
done

# ------------------------------------------------------------------------------
# 3. Systemd Services, Timers, Generators and Drop-in Overrides
# ------------------------------------------------------------------------------
log_info "Collecting Systemd services, timers, and drop-in overrides..."
mkdir -p "${OUTPUT_DIR}/Systemd"

echo "UnitName,Type,LoadState,ActiveState,SubState,ExecStart,UnitPath" > "${CSV_DIR}/SystemdServices.csv"

if command -v systemctl >/dev/null 2>&1; then
    systemctl list-unit-files --all --no-pager > "${OUTPUT_DIR}/Systemd/unit_files.txt" 2>&1
    systemctl list-timers --all --no-pager > "${OUTPUT_DIR}/Systemd/timers.txt" 2>&1
    systemctl list-units --type=service --all --no-pager > "${OUTPUT_DIR}/Systemd/services_active.txt" 2>&1
fi

# Copy custom unit configurations (/etc/systemd/system)
if [ -d /etc/systemd/system ]; then
    mkdir -p "${OUTPUT_DIR}/Systemd/etc_systemd_system"
    cp -rp /etc/systemd/system/* "${OUTPUT_DIR}/Systemd/etc_systemd_system/" 2>/dev/null || true
    
    # Audit custom services and overrides
    find /etc/systemd/system -type f \( -name "*.service" -o -name "*.timer" -o -name "*.conf" \) 2>/dev/null | while read -r unit_file; do
        unit_name=$(basename "$unit_file")
        exec_cmd=$(grep -oP '^ExecStart=\K.*' "$unit_file" 2>/dev/null | head -n 1 | sed 's/"/\\"/g' || echo "")
        echo "\"${unit_name}\",\"CustomService\",\"Enabled\",\"N/A\",\"N/A\",\"${exec_cmd}\",\"${unit_file}\"" >> "${CSV_DIR}/SystemdServices.csv"
        echo "\"Systemd\",\"CustomUnit\",\"${unit_file}\",\"ExecStart: ${exec_cmd}\",\"MEDIUM\"" >> "${CSV_DIR}/PersistenceSummary.csv"
    done
fi

# Copy systemd generators (/run/systemd/generator*)
mkdir -p "${OUTPUT_DIR}/Systemd/generators"
cp -rp /run/systemd/generator* "${OUTPUT_DIR}/Systemd/generators/" 2>/dev/null || true

# ------------------------------------------------------------------------------
# 4. Shell Profiles & Environment Hooks (/etc/profile.d, .bashrc...)
# ------------------------------------------------------------------------------
log_info "Collecting system-wide and user shell profile scripts..."
mkdir -p "${OUTPUT_DIR}/ShellProfiles"

echo "Scope,User,FilePath,SuspiciousKeywords" > "${CSV_DIR}/ShellHooks.csv"

# Global system profiles
for sys_prof in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment /etc/zsh/zprofile /etc/zsh/zshrc; do
    if [ -f "$sys_prof" ]; then
        cp -p "$sys_prof" "${OUTPUT_DIR}/ShellProfiles/$(basename "$sys_prof")" 2>/dev/null
        # Check for suspicious keywords
        susp=$(grep -Ei '(curl|wget|base64|nc|bash -i|/dev/tcp|eval|python -c)' "$sys_prof" 2>/dev/null | head -n 1 | sed 's/"/\\"/g' || echo "")
        echo "\"System\",\"root\",\"${sys_prof}\",\"${susp}\"" >> "${CSV_DIR}/ShellHooks.csv"
        [ -n "$susp" ] && echo "\"ShellHook\",\"SystemProfile\",\"${sys_prof}\",\"Keywords: ${susp}\",\"HIGH\"" >> "${CSV_DIR}/PersistenceSummary.csv"
    fi
done

if [ -d /etc/profile.d ]; then
    mkdir -p "${OUTPUT_DIR}/ShellProfiles/profile.d"
    cp -rp /etc/profile.d/* "${OUTPUT_DIR}/ShellProfiles/profile.d/" 2>/dev/null || true
    for pfile in /etc/profile.d/*; do
        [ -f "$pfile" ] || continue
        susp=$(grep -Ei '(curl|wget|base64|nc|bash -i|/dev/tcp|eval|python -c)' "$pfile" 2>/dev/null | head -n 1 | sed 's/"/\\"/g' || echo "")
        echo "\"SystemProfileD\",\"root\",\"${pfile}\",\"${susp}\"" >> "${CSV_DIR}/ShellHooks.csv"
        [ -n "$susp" ] && echo "\"ShellHook\",\"profile.d\",\"${pfile}\",\"Keywords: ${susp}\",\"HIGH\"" >> "${CSV_DIR}/PersistenceSummary.csv"
    done
fi

# User profiles in /home/* and /root
for user_home in /root /home/*; do
    [ -d "$user_home" ] || continue
    uname=$(basename "$user_home")
    mkdir -p "${OUTPUT_DIR}/ShellProfiles/users/${uname}"
    
    for shfile in .bashrc .bash_profile .bash_login .profile .zshrc .zprofile .tcshrc .cshrc .config/fish/config.fish; do
        full_sh="${user_home}/${shfile}"
        if [ -f "$full_sh" ]; then
            cp -p "$full_sh" "${OUTPUT_DIR}/ShellProfiles/users/${uname}/${shfile//\//_}" 2>/dev/null
            susp=$(grep -Ei '(curl|wget|base64|nc|bash -i|/dev/tcp|eval|python -c|LD_PRELOAD|alias sudo)' "$full_sh" 2>/dev/null | head -n 1 | sed 's/"/\\"/g' || echo "")
            echo "\"User\",\"${uname}\",\"${full_sh}\",\"${susp}\"" >> "${CSV_DIR}/ShellHooks.csv"
            [ -n "$susp" ] && echo "\"ShellHook\",\"UserProfile\",\"${full_sh}\",\"Keywords: ${susp}\",\"HIGH\"" >> "${CSV_DIR}/PersistenceSummary.csv"
        fi
    done
done

# ------------------------------------------------------------------------------
# 5. Boot Initialization (rc.local, init.d, persistent kernel modules)
# ------------------------------------------------------------------------------
log_info "Collecting rc.local, init.d, and boot module configuration..."
mkdir -p "${OUTPUT_DIR}/BootInit"

for rclocal in /etc/rc.local /etc/rc.d/rc.local; do
    if [ -f "$rclocal" ]; then
        cp -p "$rclocal" "${OUTPUT_DIR}/BootInit/rc.local" 2>/dev/null
        echo "\"BootScript\",\"rc.local\",\"${rclocal}\",\"Executed on boot\",\"MEDIUM\"" >> "${CSV_DIR}/PersistenceSummary.csv"
    fi
done

if [ -d /etc/init.d ]; then
    mkdir -p "${OUTPUT_DIR}/BootInit/init.d"
    cp -rp /etc/init.d/* "${OUTPUT_DIR}/BootInit/init.d/" 2>/dev/null || true
fi

# Persistent kernel module loading
mkdir -p "${OUTPUT_DIR}/BootInit/modules"
[ -f /etc/modules ] && cp -p /etc/modules "${OUTPUT_DIR}/BootInit/modules/modules.conf" 2>/dev/null
[ -d /etc/modules-load.d ] && cp -rp /etc/modules-load.d "${OUTPUT_DIR}/BootInit/modules/" 2>/dev/null
[ -d /etc/modprobe.d ] && cp -rp /etc/modprobe.d "${OUTPUT_DIR}/BootInit/modules/" 2>/dev/null

# ------------------------------------------------------------------------------
# 6. UDEV Rules, Polkit, PAM, and Package Manager Hooks
# ------------------------------------------------------------------------------
log_info "Collecting Udev rules, Polkit, PAM, and package manager hooks..."
mkdir -p "${OUTPUT_DIR}/SecurityConfigs"

# Udev rules
[ -d /etc/udev/rules.d ] && cp -rp /etc/udev/rules.d "${OUTPUT_DIR}/SecurityConfigs/udev_rules.d" 2>/dev/null

# Polkit
[ -d /etc/polkit-1 ] && cp -rp /etc/polkit-1 "${OUTPUT_DIR}/SecurityConfigs/polkit-1" 2>/dev/null

# PAM
[ -d /etc/pam.d ] && cp -rp /etc/pam.d "${OUTPUT_DIR}/SecurityConfigs/pam.d" 2>/dev/null

# XDG Autostart
mkdir -p "${OUTPUT_DIR}/Autostart"
[ -d /etc/xdg/autostart ] && cp -rp /etc/xdg/autostart "${OUTPUT_DIR}/Autostart/system_xdg" 2>/dev/null
for uhome in /home/* /root; do
    [ -d "${uhome}/.config/autostart" ] && cp -rp "${uhome}/.config/autostart" "${OUTPUT_DIR}/Autostart/$(basename "$uhome")_autostart" 2>/dev/null || true
done

# Package Manager hooks (APT / DNF / YUM)
[ -d /etc/apt/apt.conf.d ] && cp -rp /etc/apt/apt.conf.d "${OUTPUT_DIR}/SecurityConfigs/apt.conf.d" 2>/dev/null
[ -d /etc/yum.repos.d ] && cp -rp /etc/yum.repos.d "${OUTPUT_DIR}/SecurityConfigs/yum.repos.d" 2>/dev/null

log_success "Persistence triage completed successfully."
