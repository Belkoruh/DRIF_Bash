#!/usr/bin/env bash
# ==============================================================================
# Script: GenerateEvidenceManifest.sh
# Description: Generates forensic evidence manifest and chain of custody checksums
# Documentation: Calculates SHA-256 hashes for all acquired evidence files,
#                generates checksums.sha256 and manifest.json with full host context
#                (OS, Kernel, UTC timestamp, Collector User, Elevation status).
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

if [ ! -d "$TARGET_DIR" ]; then
    echo -e "${RED}[!] Error: Target directory '$TARGET_DIR' does not exist.${NC}" >&2
    exit 1
fi

echo -e "${CYAN}${BOLD}=== Forensic Evidence Manifest & Chain of Custody Generator ===${NC}"
echo -e "${BLUE}Target Directory: ${TARGET_DIR}${NC}\n"

MANIFEST_JSON="${TARGET_DIR}/manifest.json"
CHECKSUMS_FILE="${TARGET_DIR}/checksums.sha256"

# Remove any existing control files
rm -f "$MANIFEST_JSON" "$CHECKSUMS_FILE"

# ------------------------------------------------------------------------------
# 1. Collect Host Context & Metadata
# ------------------------------------------------------------------------------
hostname_val=$(hostname -s 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "UNKNOWN")
fqdn_val=$(hostname -f 2>/dev/null || echo "$hostname_val")
kernel_release=$(uname -r 2>/dev/null || echo "UNKNOWN")
kernel_version=$(uname -v 2>/dev/null || echo "UNKNOWN")
arch_val=$(uname -m 2>/dev/null || echo "UNKNOWN")
current_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
timezone_val=$(cat /etc/timezone 2>/dev/null || date +"%Z %z")
uptime_val=$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo "UNKNOWN")

os_pretty="Linux OS"
if [ -f /etc/os-release ]; then
    os_pretty=$(grep -oP '^PRETTY_NAME="\K[^"]+' /etc/os-release 2>/dev/null || echo "Linux OS")
fi

collector_user=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "UNKNOWN")
collector_uid=$(id -u 2>/dev/null || echo "0")
is_root="False"
[ "$collector_uid" -eq 0 ] && is_root="True"

# ------------------------------------------------------------------------------
# 2. Compute SHA-256 Hashes for All Files
# ------------------------------------------------------------------------------
echo -e "${CYAN}[*] Computing SHA-256 checksums for all evidence files...${NC}"

total_files=0
total_bytes=0

# Temporary file to store JSON file entries
tmp_file_list=$(mktemp)

cd "$TARGET_DIR"

# Iterate over all regular files
find . -type f ! -name "manifest.json" ! -name "checksums.sha256" ! -name "*.tmp" | sort | while read -r rel_path; do
    clean_path="${rel_path#./}"
    
    file_sha=$(sha256sum "$clean_path" 2>/dev/null | awk '{print $1}')
    file_bytes=$(stat -c "%s" "$clean_path" 2>/dev/null || echo "0")
    file_mtime_utc=$(date -u -r "$clean_path" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "UNKNOWN")
    
    # Write to standard checksums.sha256
    echo "${file_sha}  ${clean_path}" >> "checksums.sha256"
    
    # Write to JSON temp list
    echo "{\"path\": \"${clean_path}\", \"size_bytes\": ${file_bytes}, \"sha256\": \"${file_sha}\", \"modified_utc\": \"${file_mtime_utc}\"}," >> "$tmp_file_list"
done

# Calculate total files and total byte size
if [ -f "checksums.sha256" ]; then
    total_files=$(wc -l < "checksums.sha256" | tr -d ' ')
    total_bytes=$(find . -type f ! -name "manifest.json" -exec stat -c "%s" {} + 2>/dev/null | awk '{s+=$1} END {print s}' || echo "0")
fi

# Clean trailing comma from JSON list
if [ -s "$tmp_file_list" ]; then
    sed -i '$ s/,$//' "$tmp_file_list"
fi

# ------------------------------------------------------------------------------
# 3. Assemble JSON Chain of Custody Manifest
# ------------------------------------------------------------------------------
cat <<EOF > "$MANIFEST_JSON"
{
  "manifest_version": "1.0.0",
  "generated_utc": "${current_utc}",
  "timezone": "${timezone_val}",
  "system_context": {
    "hostname": "${hostname_val}",
    "fqdn": "${fqdn_val}",
    "os_name": "${os_pretty}",
    "kernel_release": "${kernel_release}",
    "kernel_version": "${kernel_version}",
    "architecture": "${arch_val}",
    "uptime": "${uptime_val}"
  },
  "collector_context": {
    "user": "${collector_user}",
    "uid": ${collector_uid},
    "is_elevated_root": ${is_root}
  },
  "evidence_summary": {
    "total_files": ${total_files},
    "total_bytes": ${total_bytes}
  },
  "files": [
$(cat "$tmp_file_list")
  ]
}
EOF

rm -f "$tmp_file_list"

echo -e "${GREEN}[+] Manifest generated successfully: ${MANIFEST_JSON}${NC}"
echo -e "${GREEN}[+] Checksums file: ${CHECKSUMS_FILE} (${total_files} files hashed)${NC}"
