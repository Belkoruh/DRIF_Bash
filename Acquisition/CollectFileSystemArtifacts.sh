#!/usr/bin/env bash
# ==============================================================================
# Script: CollectFileSystemArtifacts.sh
# Description: Linux file system artifacts and privilege escalation forensic triage
# Documentation: Collects SUID/SGID executable binaries (with GTFOBins cross-reference),
#                extended POSIX file capabilities (getcap), temporary staging directories
#                (/tmp, /dev/shm, /var/tmp), hidden files/directories, immutable flags,
#                and recently modified binaries in $PATH.
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
WINDOW_DAYS="${2:-2}"
OUTPUT_DIR="${TARGET_DIR}/FileSystem"
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

echo -e "${CYAN}${BOLD}=== File System Artifacts Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

# ------------------------------------------------------------------------------
# 1. SUID / SGID Binaries & GTFOBins Detection
# ------------------------------------------------------------------------------
log_info "Auditing SUID / SGID executable binaries..."
suid_out="${OUTPUT_DIR}/suid_sgid_binaries.txt"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null > "$suid_out" || true

echo "Path,Permissions,Owner,Group,Size,SHA256,IsGTFOBin" > "${CSV_DIR}/SUIDBinaries.csv"

# Known GTFOBins list for privilege escalation triage
gtfobins_pattern='/(bash|sh|zsh|dash|python|python3|perl|ruby|php|node|nmap|vim|vi|nano|less|more|awk|gawk|tar|zip|find|env|cp|mv|chmod|chown|wget|curl|nc|ncat|netcat|socat|pkexec|sudo|su|gdb|systemctl|journalctl|docker|lxc|git|rsync)$'

while read -r sfile; do
    [ -f "$sfile" ] || continue
    perms=$(stat -c "%a" "$sfile" 2>/dev/null || echo "")
    owner=$(stat -c "%U" "$sfile" 2>/dev/null || echo "")
    group=$(stat -c "%G" "$sfile" 2>/dev/null || echo "")
    size=$(stat -c "%s" "$sfile" 2>/dev/null || echo "0")
    sha=$(sha256sum "$sfile" 2>/dev/null | awk '{print $1}' || echo "N/A")
    
    is_gtfo="False"
    if [[ "$sfile" =~ $gtfobins_pattern ]]; then
        is_gtfo="True"
        log_warn "High-risk GTFOBin SUID binary detected: ${sfile} (Perms: ${perms}, Owner: ${owner})"
    fi
    
    echo "\"${sfile}\",\"${perms}\",\"${owner}\",\"${group}\",\"${size}\",\"${sha}\",\"${is_gtfo}\"" >> "${CSV_DIR}/SUIDBinaries.csv"
done < "$suid_out"

# ------------------------------------------------------------------------------
# 2. Extended Linux File Capabilities (getcap)
# ------------------------------------------------------------------------------
log_info "Auditing extended POSIX file capabilities (getcap)..."
echo "Path,Capabilities" > "${CSV_DIR}/FileCapabilities.csv"
if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null > "${OUTPUT_DIR}/capabilities_raw.txt" || true
    while read -r line; do
        [ -n "$line" ] || continue
        cpath=$(echo "$line" | awk '{print $1}')
        caps=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^[[:space:]]*//' | sed 's/"/\\"/g')
        echo "\"${cpath}\",\"${caps}\"" >> "${CSV_DIR}/FileCapabilities.csv"
        log_info "POSIX capability detected: ${cpath} = ${caps}"
    done < "${OUTPUT_DIR}/capabilities_raw.txt"
fi

# ------------------------------------------------------------------------------
# 3. Temporary Staging Directories (/tmp, /dev/shm, /var/tmp, /run/user)
# ------------------------------------------------------------------------------
log_info "Scanning world-writable staging directories (/tmp, /dev/shm, /var/tmp)..."
echo "Path,Size,Permissions,Owner,FileType,SHA256,IsExecutable" > "${CSV_DIR}/StagingFiles.csv"

for st_dir in /tmp /dev/shm /var/tmp /run/user /dev/mqueue; do
    [ -d "$st_dir" ] || continue
    mkdir -p "${OUTPUT_DIR}/Staging_Dumps/${st_dir//\//_}"
    
    find "$st_dir" -maxdepth 4 -type f 2>/dev/null | while read -r tf; do
        [ -f "$tf" ] || continue
        size=$(stat -c "%s" "$tf" 2>/dev/null || echo "0")
        perms=$(stat -c "%a" "$tf" 2>/dev/null || echo "")
        owner=$(stat -c "%U" "$tf" 2>/dev/null || echo "")
        ftype=$(file -b "$tf" 2>/dev/null | sed 's/"/\\"/g' || echo "Unknown")
        sha=$(sha256sum "$tf" 2>/dev/null | awk '{print $1}' || echo "N/A")
        
        is_exe="False"
        if [ -x "$tf" ] || [[ "$ftype" =~ ELF ]] || [[ "$ftype" =~ script ]]; then
            is_exe="True"
            log_warn "Executable binary/script detected in staging: ${tf} (${ftype})"
            # Copy to dump folder for offline analysis
            cp -p "$tf" "${OUTPUT_DIR}/Staging_Dumps/${st_dir//\//_}/$(basename "$tf")_${size}" 2>/dev/null || true
        fi
        
        echo "\"${tf}\",\"${size}\",\"${perms}\",\"${owner}\",\"${ftype}\",\"${sha}\",\"${is_exe}\"" >> "${CSV_DIR}/StagingFiles.csv"
    done
done

# ------------------------------------------------------------------------------
# 4. Hidden Files & Directories with Suspicious Names
# ------------------------------------------------------------------------------
log_info "Searching for anomalous hidden file/directory names (e.g. ..., . , /dev/.*)..."
find /tmp /dev/shm /var/tmp /dev /home /root -maxdepth 3 \( -name "\.\.\.*" -o -name "\. *" -o -name "\.\.\." \) 2>/dev/null > "${OUTPUT_DIR}/suspicious_hidden_names.txt" || true
if [ -s "${OUTPUT_DIR}/suspicious_hidden_names.txt" ]; then
    log_warn "Anomalous hidden filenames detected!"
fi

# ------------------------------------------------------------------------------
# 5. Recently Modified Binaries in $PATH
# ------------------------------------------------------------------------------
log_info "Searching for binaries modified within the last ${WINDOW_DAYS} day(s) in \$PATH..."
echo "Path,ModifiedTime,Owner,Permissions,SHA256" > "${CSV_DIR}/RecentlyModifiedBinaries.csv"

for bin_dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt; do
    [ -d "$bin_dir" ] || continue
    find "$bin_dir" -maxdepth 3 -mtime -"${WINDOW_DAYS}" -type f 2>/dev/null | while read -r rbin; do
        [ -f "$rbin" ] || continue
        mtime=$(stat -c "%y" "$rbin" 2>/dev/null || echo "")
        owner=$(stat -c "%U" "$rbin" 2>/dev/null || echo "")
        perms=$(stat -c "%a" "$rbin" 2>/dev/null || echo "")
        sha=$(sha256sum "$rbin" 2>/dev/null | awk '{print $1}' || echo "N/A")
        
        echo "\"${rbin}\",\"${mtime}\",\"${owner}\",\"${perms}\",\"${sha}\"" >> "${CSV_DIR}/RecentlyModifiedBinaries.csv"
        log_info "Recently modified binary: ${rbin} (${mtime})"
    done
done

# ------------------------------------------------------------------------------
# 6. Immutable File Attributes (chattr +i)
# ------------------------------------------------------------------------------
log_info "Auditing extended file immutability flags (chattr +i)..."
if command -v lsattr >/dev/null 2>&1; then
    lsattr -d -R /etc /bin /sbin /usr/bin /tmp /var/tmp /dev/shm 2>/dev/null | grep -E '^....i' > "${OUTPUT_DIR}/immutable_files.txt" || true
    if [ -s "${OUTPUT_DIR}/immutable_files.txt" ]; then
        log_warn "Immutable files (+i) detected!"
    fi
fi

log_success "File system triage completed successfully."
