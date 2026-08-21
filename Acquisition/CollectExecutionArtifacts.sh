#!/usr/bin/env bash
# ==============================================================================
# Script: CollectExecutionArtifacts.sh
# Description: Linux execution, process, memory and /proc forensic artifact triage
# Documentation: Captures full process trees, cmdlines, environment variables,
#                file descriptors (/proc/PID/fd), memory maps (/proc/PID/maps),
#                detects and quarantines deleted running binaries (deleted)
#                and anonymous in-memory executions (memfd_create).
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
OUTPUT_DIR="${TARGET_DIR}/ProcessInformation"
QUARANTINE_DIR="${OUTPUT_DIR}/Quarantined_Deleted_Binaries"
CSV_DIR="${TARGET_DIR}/CSV_Results"

mkdir -p "${OUTPUT_DIR}" "${QUARANTINE_DIR}" "${CSV_DIR}"

log_info() {
    echo -e "${CYAN}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

echo -e "${CYAN}${BOLD}=== Execution & Process Artifacts Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

# ------------------------------------------------------------------------------
# 1. Global Process Table Capture
# ------------------------------------------------------------------------------
log_info "Capturing global running process snapshot..."
ps auxww > "${OUTPUT_DIR}/ps_auxww.txt" 2>&1
ps -ef --forest > "${OUTPUT_DIR}/ps_forest.txt" 2>&1
ps -eo pid,ppid,user,uid,gid,lstart,etime,comm,args > "${OUTPUT_DIR}/ps_detailed.txt" 2>&1
if command -v pstree >/dev/null 2>&1; then
    pstree -apnh > "${OUTPUT_DIR}/pstree.txt" 2>&1
fi

# ------------------------------------------------------------------------------
# 2. Deep /proc Triage (Cmdline, Environ, Exe, FD, Maps, Memfd)
# ------------------------------------------------------------------------------
log_info "Performing deep /proc inspection for each running PID..."

echo "PID,PPID,User,UID,ProcessName,ExePath,IsDeleted,HasMemfd,CWD,CommandLine" > "${CSV_DIR}/Processes.csv"
echo "PID,User,DeletedExePath,QuarantinedFile,SHA256" > "${CSV_DIR}/DeletedRunningBinaries.csv"
echo "PID,User,ProcessName,MemfdName,MapsEntry" > "${CSV_DIR}/MemfdExecutions.csv"

deleted_count=0
memfd_count=0

for proc_dir in /proc/[0-9]*; do
    [ -d "$proc_dir" ] || continue
    pid="${proc_dir##*/}"
    
    # Read process name
    pname="UNKNOWN"
    [ -f "${proc_dir}/comm" ] && pname=$(cat "${proc_dir}/comm" 2>/dev/null || echo "UNKNOWN")
    
    ppid="0"
    uid="0"
    user="UNKNOWN"
    if [ -f "${proc_dir}/status" ]; then
        ppid=$(grep -oP '^PPid:\s*\K\d+' "${proc_dir}/status" 2>/dev/null || echo "0")
        uid=$(grep -oP '^Uid:\s*\K\d+' "${proc_dir}/status" 2>/dev/null || echo "0")
        user=$(id -nu "$uid" 2>/dev/null || echo "$uid")
    fi
    
    # Full command line
    cmdline=""
    if [ -f "${proc_dir}/cmdline" ]; then
        cmdline=$(tr '\0' ' ' < "${proc_dir}/cmdline" 2>/dev/null | sed 's/"/\\"/g' || echo "")
    fi
    
    # Current working directory
    cwd=""
    if [ -e "${proc_dir}/cwd" ]; then
        cwd=$(readlink -f "${proc_dir}/cwd" 2>/dev/null || echo "")
    fi
    
    # Executable path
    exe_target=""
    is_deleted="False"
    if [ -e "${proc_dir}/exe" ]; then
        exe_target=$(readlink "${proc_dir}/exe" 2>/dev/null || echo "")
        if [[ "$exe_target" =~ \(deleted\) ]]; then
            is_deleted="True"
            ((deleted_count++))
            
            # Extract and quarantine volatile binary for forensics
            quarantine_file="${QUARANTINE_DIR}/pid_${pid}_${pname}.elf"
            if cp -p "${proc_dir}/exe" "$quarantine_file" 2>/dev/null; then
                sha_hash=$(sha256sum "$quarantine_file" 2>/dev/null | awk '{print $1}' || echo "N/A")
                echo "\"${pid}\",\"${user}\",\"${exe_target}\",\"${quarantine_file}\",\"${sha_hash}\"" >> "${CSV_DIR}/DeletedRunningBinaries.csv"
                log_warn "Deleted binary detected in memory: PID ${pid} (${pname}) -> ${exe_target} [Quarantined]"
            fi
        fi
    fi
    
    # Detect memfd executions (anonymous in-memory injections)
    has_memfd="False"
    if [ -f "${proc_dir}/maps" ]; then
        memfd_match=$(grep -i 'memfd:' "${proc_dir}/maps" 2>/dev/null || true)
        if [ -n "$memfd_match" ]; then
            has_memfd="True"
            ((memfd_count++))
            first_entry=$(echo "$memfd_match" | head -n 1 | sed 's/"/\\"/g')
            echo "\"${pid}\",\"${user}\",\"${pname}\",\"memfd\",\"${first_entry}\"" >> "${CSV_DIR}/MemfdExecutions.csv"
            log_warn "Suspicious memfd_create execution detected: PID ${pid} (${pname})"
        fi
    fi
    
    # Export process record to CSV
    echo "\"${pid}\",\"${ppid}\",\"${user}\",\"${uid}\",\"${pname}\",\"${exe_target}\",\"${is_deleted}\",\"${has_memfd}\",\"${cwd}\",\"${cmdline}\"" >> "${CSV_DIR}/Processes.csv"
    
    # Export environment variables (searching for sensitive keys, LD_PRELOAD, etc.)
    if [ -f "${proc_dir}/environ" ]; then
        env_content=$(tr '\0' '\n' < "${proc_dir}/environ" 2>/dev/null || true)
        if [ -n "$env_content" ]; then
            mkdir -p "${OUTPUT_DIR}/Environments"
            echo "$env_content" > "${OUTPUT_DIR}/Environments/pid_${pid}_env.txt" 2>/dev/null
        fi
    fi
    
    # Export open file descriptors
    if [ -d "${proc_dir}/fd" ]; then
        fd_list=$(ls -l "${proc_dir}/fd" 2>/dev/null || true)
        if [ -n "$fd_list" ]; then
            mkdir -p "${OUTPUT_DIR}/FileDescriptors"
            echo "$fd_list" > "${OUTPUT_DIR}/FileDescriptors/pid_${pid}_fd.txt" 2>/dev/null
        fi
    fi
done

log_info "Total processes analyzed. Deleted binaries: ${deleted_count}, memfd executions: ${memfd_count}."

# ------------------------------------------------------------------------------
# 3. Processes Running from Staging Locations (/dev/shm, /tmp, /var/tmp)
# ------------------------------------------------------------------------------
log_info "Auditing processes running from temporary/staging directories (/tmp, /dev/shm)..."
staging_procs="${OUTPUT_DIR}/processes_in_staging.txt"
grep -E '(/tmp|/dev/shm|/var/tmp|/run/user)' "${CSV_DIR}/Processes.csv" > "$staging_procs" 2>/dev/null || true
if [ -s "$staging_procs" ]; then
    log_warn "Processes detected running directly from /tmp, /dev/shm or /var/tmp!"
fi

log_success "Execution and process triage completed successfully."
