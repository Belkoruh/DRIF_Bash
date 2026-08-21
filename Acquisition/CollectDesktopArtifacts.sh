#!/usr/bin/env bash
# ==============================================================================
# Script: CollectDesktopArtifacts.sh
# Description: Linux GUI, Workstation, Trash, Recent Files & Desktop Forensics
# Documentation: Collects recently opened files (recently-used.xbel), Linux Trash can
#                deleted files and metadata, cache thumbnails, and input monitoring tools.
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
OUTPUT_DIR="${TARGET_DIR}/DesktopForensics"
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

echo -e "${CYAN}${BOLD}=== Linux Desktop, Trash & GUI Artifacts Acquisition ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "User,FilePath,MIMEType,Application,LastVisitedUTC" > "${CSV_DIR}/RecentFiles.csv"
echo "User,OriginalPath,DeletionDateUTC,TrashFilePath,FileSize" > "${CSV_DIR}/TrashArtifacts.csv"

# ------------------------------------------------------------------------------
# 1. Recently Used Files (~/.local/share/recently-used.xbel)
# ------------------------------------------------------------------------------
log_info "Collecting recently opened files from recently-used.xbel..."
mkdir -p "${OUTPUT_DIR}/RecentFiles"

for uhome in /root /home/*; do
    [ -d "$uhome" ] || continue
    u_name=$(basename "$uhome")
    xbel="${uhome}/.local/share/recently-used.xbel"
    
    if [ -f "$xbel" ]; then
        cp -p "$xbel" "${OUTPUT_DIR}/RecentFiles/${u_name}_recently-used.xbel" 2>/dev/null || true
        log_info "Parsing recently-used.xbel for user: ${u_name}"
        
        # Simple extraction of bookmarks
        grep -oP '<bookmark href="\K[^"]+' "$xbel" 2>/dev/null | head -n 100 | while read -r f_href; do
            clean_href=$(echo "$f_href" | sed 's/"/\\"/g')
            echo "\"${u_name}\",\"${clean_href}\",\"Unknown\",\"N/A\",\"N/A\"" >> "${CSV_DIR}/RecentFiles.csv"
        done
    fi
done

# ------------------------------------------------------------------------------
# 2. Linux Trash Can Forensics (~/.local/share/Trash)
# ------------------------------------------------------------------------------
log_info "Auditing Linux Trash directories and deletion metadata..."
mkdir -p "${OUTPUT_DIR}/Trash"

for uhome in /root /home/*; do
    [ -d "$uhome" ] || continue
    u_name=$(basename "$uhome")
    trash_info_dir="${uhome}/.local/share/Trash/info"
    trash_files_dir="${uhome}/.local/share/Trash/files"
    
    if [ -d "$trash_info_dir" ]; then
        find "$trash_info_dir" -maxdepth 2 -type f -name "*.trashinfo" 2>/dev/null | while read -r tinfo; do
            orig_path=$(grep -oP '^Path=\K.*' "$tinfo" 2>/dev/null || echo "UNKNOWN")
            del_date=$(grep -oP '^DeletionDate=\K.*' "$tinfo" 2>/dev/null || echo "UNKNOWN")
            t_base=$(basename "$tinfo" .trashinfo)
            t_file="${trash_files_dir}/${t_base}"
            
            fsize="0"
            [ -e "$t_file" ] && fsize=$(stat -c "%s" "$t_file" 2>/dev/null || echo "0")
            
            clean_orig=$(echo "$orig_path" | sed 's/"/\\"/g')
            clean_tfile=$(echo "$t_file" | sed 's/"/\\"/g')
            
            echo "\"${u_name}\",\"${clean_orig}\",\"${del_date}\",\"${clean_tfile}\",\"${fsize}\"" >> "${CSV_DIR}/TrashArtifacts.csv"
        done
        
        # Copy metadata files
        mkdir -p "${OUTPUT_DIR}/Trash/${u_name}_info"
        cp -rp "${trash_info_dir}"/* "${OUTPUT_DIR}/Trash/${u_name}_info/" 2>/dev/null || true
        log_success "Trash metadata collected for user: ${u_name}"
    fi
done

# ------------------------------------------------------------------------------
# 3. Thumbnails Cache Inventory (~/.cache/thumbnails)
# ------------------------------------------------------------------------------
log_info "Auditing thumbnail image caches..."
mkdir -p "${OUTPUT_DIR}/Thumbnails"

for uhome in /root /home/*; do
    [ -d "$uhome" ] || continue
    u_name=$(basename "$uhome")
    thumb_dir="${uhome}/.cache/thumbnails"
    
    if [ -d "$thumb_dir" ]; then
        find "$thumb_dir" -type f -name "*.png" 2>/dev/null | head -n 200 > "${OUTPUT_DIR}/Thumbnails/${u_name}_thumbnails_list.txt" 2>&1 || true
    fi
done

# ------------------------------------------------------------------------------
# 4. X11 / Wayland Input Monitoring & Keylogger Checks
# ------------------------------------------------------------------------------
log_info "Checking for virtual input devices & keylogger hooks (xinput)..."
mkdir -p "${OUTPUT_DIR}/InputDevices"

if command -v xinput >/dev/null 2>&1; then
    xinput list > "${OUTPUT_DIR}/InputDevices/xinput_list.txt" 2>&1 || true
fi

for uhome in /root /home/*; do
    [ -f "${uhome}/.xsession-errors" ] && cp -p "${uhome}/.xsession-errors" "${OUTPUT_DIR}/InputDevices/$(basename "$uhome")_xsession-errors.txt" 2>/dev/null || true
done

log_success "Desktop, Trash, and GUI artifacts triage completed."
