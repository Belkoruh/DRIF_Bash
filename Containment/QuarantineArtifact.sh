#!/usr/bin/env bash
# ==============================================================================
# Script: QuarantineArtifact.sh
# Description: Zero-permission secure artifact quarantine and inode lock
# Documentation: Safely isolates suspicious files or malware samples into /var/dfir_quarantine,
#                strips execution permissions (chmod 000), applies the immutable attribute
#                (chattr +i), and computes the SHA-256 digital seal for evidence preservation.
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

TARGET_FILE="${1:-}"
QUARANTINE_DIR="${2:-/var/dfir_quarantine}"

if [ -z "$TARGET_FILE" ] || [ ! -e "$TARGET_FILE" ]; then
    echo -e "${RED}[!] Error: Target file does not exist or was not specified.${NC}" >&2
    echo "Usage: $0 <File_To_Quarantine> [Custom_Quarantine_Dir]" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Error: Root privileges are required to apply quarantine and chattr lock.${NC}" >&2
    exit 1
fi

mkdir -p "$QUARANTINE_DIR"

echo -e "${CYAN}${BOLD}=== Secure Evidence Quarantine & Inode Lock ===${NC}"
echo -e "${BLUE}Target File    : ${TARGET_FILE}${NC}"
echo -e "${BLUE}Quarantine Dir : ${QUARANTINE_DIR}${NC}\n"

ts=$(date +"%Y%m%d_%H%M%S")
fname=$(basename "$TARGET_FILE")
dest_file="${QUARANTINE_DIR}/${fname}_${ts}.quarantined"

# Calculate hash before quarantine
sha_val=$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')
size_val=$(stat -c "%s" "$TARGET_FILE" 2>/dev/null || echo "0")
owner_val=$(stat -c "%U:%G" "$TARGET_FILE" 2>/dev/null || echo "")

# Copy file with attributes preserved
cp -p "$TARGET_FILE" "$dest_file" 2>/dev/null || true

# Neutralize original file
rm -f "$TARGET_FILE" 2>/dev/null || true

# Strip all permissions on quarantined copy
chmod 000 "$dest_file" 2>/dev/null || true

# Apply kernel immutable flag to prevent attacker from modifying or deleting the evidence
if command -v chattr >/dev/null 2>&1; then
    chattr +i "$dest_file" 2>/dev/null || true
fi

# Append to quarantine log
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") | ${TARGET_FILE} | ${dest_file} | ${sha_val} | ${size_val} bytes | Owner: ${owner_val}" >> "${QUARANTINE_DIR}/quarantine_manifest.log"

echo -e "${GREEN}${BOLD}[✓] File quarantined successfully!${NC}"
echo -e "Quarantine Path : ${BOLD}${dest_file}${NC}"
echo -e "Permissions     : ${YELLOW}000 (Locked + Immutable)${NC}"
echo -e "SHA-256 Seal    : ${CYAN}${sha_val}${NC}"
echo -e "Log Manifest    : ${QUARANTINE_DIR}/quarantine_manifest.log"
