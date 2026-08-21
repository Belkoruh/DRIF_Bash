#!/usr/bin/env bash
# ==============================================================================
# Script: CollectRootkitIndicators.sh
# Description: Linux Rootkit indicators and Kernel integrity triage module
# Documentation: Audits Loadable Kernel Modules (LKMs), decodes kernel taint flags
#                (/proc/sys/kernel/tainted), detects hidden processes (/proc vs ps anomalies),
#                dynamic link library hooks (/etc/ld.so.preload), and known rootkit signatures.
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
OUTPUT_DIR="${TARGET_DIR}/RootkitIndicators"
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

echo -e "${CYAN}${BOLD}=== Linux Rootkit Indicators & Kernel Integrity Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "Category,IndicatorName,Status,RiskLevel,Description" > "${CSV_DIR}/RootkitIndicators.csv"
echo "ModuleName,Size,Instances,State,Address,Flags,IsOutOfTree" > "${CSV_DIR}/KernelModulesAudit.csv"
echo "PID,DetectedInProc,DetectedInPS,IsHiddenAnomaly" > "${CSV_DIR}/HiddenProcessAudit.csv"

# ------------------------------------------------------------------------------
# 1. Kernel Modules (LKM) Audit & Out-of-Tree / Unsigned Detection
# ------------------------------------------------------------------------------
log_info "Auditing loaded kernel modules (LKMs)..."
lsmod > "${OUTPUT_DIR}/lsmod.txt" 2>&1
[ -f /proc/modules ] && cp -p /proc/modules "${OUTPUT_DIR}/proc_modules.txt"

if [ -f /proc/modules ]; then
    while read -r mod_name mod_size mod_inst mod_by mod_state mod_addr mod_flags; do
        is_oot="False"
        # Module flags: (O) = Out-of-tree, (E) = Unsigned, (P) = Proprietary, (C) = Staging
        if [[ "$mod_flags" =~ \(.*O.*\) ]] || [[ "$mod_flags" =~ \(.*E.*\) ]]; then
            is_oot="True"
            log_warn "Out-of-tree or unsigned kernel module detected: ${mod_name} (Flags: ${mod_flags})"
            echo "\"KernelLKM\",\"SuspiciousModule\",\"DETECTED\",\"HIGH\",\"Module ${mod_name} loaded with flags ${mod_flags}\"" >> "${CSV_DIR}/RootkitIndicators.csv"
        fi
        echo "\"${mod_name}\",\"${mod_size}\",\"${mod_inst}\",\"${mod_state}\",\"${mod_addr}\",\"${mod_flags}\",\"${is_oot}\"" >> "${CSV_DIR}/KernelModulesAudit.csv"
    done < /proc/modules
fi

# ------------------------------------------------------------------------------
# 2. Kernel Taint Mask Decoding (/proc/sys/kernel/tainted)
# ------------------------------------------------------------------------------
log_info "Analyzing kernel taint status (/proc/sys/kernel/tainted)..."
if [ -f /proc/sys/kernel/tainted ]; then
    taint_val=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "0")
    echo "Kernel Taint Value: $taint_val" > "${OUTPUT_DIR}/kernel_tainted_decoded.txt"
    
    if [ "$taint_val" -ne 0 ]; then
        log_warn "Kernel is tainted (Tainted Value = ${taint_val})!"
        echo "Active kernel taint bits explanation:" >> "${OUTPUT_DIR}/kernel_tainted_decoded.txt"
        
        # Bitmasks per Linux kernel documentation
        [ $((taint_val & 1)) -ne 0 ] && echo " - Bit 0: Proprietary module loaded (P)" >> "${OUTPUT_DIR}/kernel_tainted_decoded.txt"
        [ $((taint_val & 2)) -ne 0 ] && echo " - Bit 1: Module was force loaded (F)" >> "${OUTPUT_DIR}/kernel_tainted_decoded.txt"
        [ $((taint_val & 4096)) -ne 0 ] && echo " - Bit 12: Out-of-tree module loaded (O)" >> "${OUTPUT_DIR}/kernel_tainted_decoded.txt"
        [ $((taint_val & 8192)) -ne 0 ] && echo " - Bit 13: Unsigned module loaded (E)" >> "${OUTPUT_DIR}/kernel_tainted_decoded.txt"
        [ $((taint_val & 512)) -ne 0 ] && echo " - Bit 9: Kernel has been live-patched" >> "${OUTPUT_DIR}/kernel_tainted_decoded.txt"
        
        echo "\"KernelIntegrity\",\"KernelTaint\",\"TAINTED\",\"MEDIUM\",\"Kernel taint value: ${taint_val}\"" >> "${CSV_DIR}/RootkitIndicators.csv"
    else
        echo "Kernel is clean (Taint = 0)" >> "${OUTPUT_DIR}/kernel_tainted_decoded.txt"
        echo "\"KernelIntegrity\",\"KernelTaint\",\"CLEAN\",\"INFO\",\"Untainted standard kernel (0)\"" >> "${CSV_DIR}/RootkitIndicators.csv"
    fi
fi

# ------------------------------------------------------------------------------
# 3. Hidden Process Detection (/proc vs ps) - Process Hiding Rootkits
# ------------------------------------------------------------------------------
log_info "Searching for hidden processes (/proc vs ps anomalies)..."
ps_pids=$(ps -eo pid --no-headers | tr -d ' ' | sort -n)

hidden_anomalies=0
for pdir in /proc/[0-9]*; do
    [ -d "$pdir" ] || continue
    pid="${pdir##*/}"
    
    in_ps="True"
    if ! echo "$ps_pids" | grep -qx "$pid"; then
        in_ps="False"
        # Re-check to avoid ephemeral process race condition
        if [ -d "/proc/$pid" ]; then
            ((hidden_anomalies++))
            pname=$(cat "/proc/$pid/comm" 2>/dev/null || echo "UNKNOWN")
            log_warn "ROOTKIT ANOMALY: PID ${pid} (${pname}) visible in /proc but HIDDEN from ps!"
            echo "\"${pid}\",\"True\",\"False\",\"True\"" >> "${CSV_DIR}/HiddenProcessAudit.csv"
            echo "\"ProcessHiding\",\"HiddenPID_${pid}\",\"DETECTED\",\"CRITICAL\",\"PID ${pid} (${pname}) hidden from user space\"" >> "${CSV_DIR}/RootkitIndicators.csv"
        fi
    fi
done

if [ "$hidden_anomalies" -eq 0 ]; then
    log_info "No hidden process anomalies detected between /proc and ps."
fi

# ------------------------------------------------------------------------------
# 4. Userland Interception Hooks (/etc/ld.so.preload & LD_PRELOAD)
# ------------------------------------------------------------------------------
log_info "Auditing dynamic library preloading hooks (ld.so.preload)..."
if [ -f /etc/ld.so.preload ]; then
    log_warn "ALERT: /etc/ld.so.preload is present on host!"
    preload_content=$(cat /etc/ld.so.preload 2>/dev/null | tr '\n' ' ' || echo "")
    echo "\"UserlandRootkit\",\"ld.so.preload\",\"DETECTED\",\"CRITICAL\",\"Content: ${preload_content}\"" >> "${CSV_DIR}/RootkitIndicators.csv"
fi

# ------------------------------------------------------------------------------
# 5. Known Rootkit Signatures & File Paths
# ------------------------------------------------------------------------------
log_info "Scanning for known Linux rootkit signatures and paths (Diamorphine, Reptile, Azazel, Jynx)..."
known_rk_paths=(
    "/etc/ld.so.preload"
    "/lib/modules/$(uname -r)/kernel/drivers/char/diamorphine.ko"
    "/lib/modules/$(uname -r)/kernel/drivers/char/reptile.ko"
    "/etc/reptile"
    "/etc/sysstat/systat"
    "/var/run/kbeast"
    "/lib/libbeast.so"
    "/etc/vlany"
    "/usr/lib/libprocesshider.so"
)

for rk_path in "${known_rk_paths[@]}"; do
    if [ -e "$rk_path" ]; then
        log_warn "Known rootkit file pattern found: ${rk_path}"
        echo "\"KnownRootkitSignature\",\"$(basename "$rk_path")\",\"DETECTED\",\"CRITICAL\",\"Path: ${rk_path}\"" >> "${CSV_DIR}/RootkitIndicators.csv"
    fi
done

log_success "Rootkit indicators and kernel integrity triage completed."
