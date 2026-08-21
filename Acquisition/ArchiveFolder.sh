#!/usr/bin/env bash
# ==============================================================================
# Script: ArchiveFolder.sh
# Description: Forensic archiving and digital sealing for Linux evidence directories
# Documentation: Compresses the DFIR output directory into a .tar.gz archive while strictly
#                preserving file permissions, owners, and MACB timestamps (atime/mtime).
#                Computes the final SHA-256 digital seal hash of the archive.
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

TARGET_DIR="${1:-}"

if [ -z "$TARGET_DIR" ] || [ ! -d "$TARGET_DIR" ]; then
    echo -e "${RED}[!] Error: Please specify a valid directory to archive.${NC}" >&2
    echo "Usage: $0 <DFIR_Folder_Path> [Output_Archive.tar.gz]" >&2
    exit 1
fi

PARENT_DIR=$(dirname "$TARGET_DIR")
BASE_NAME=$(basename "$TARGET_DIR")
ARCHIVE_OUT="${2:-${PARENT_DIR}/${BASE_NAME}.tar.gz}"

echo -e "${CYAN}${BOLD}=== Forensic Digital Archiving & Sealing ===${NC}"
echo -e "${BLUE}Source Directory: ${TARGET_DIR}${NC}"
echo -e "${BLUE}Target Archive  : ${ARCHIVE_OUT}${NC}\n"

echo -e "${CYAN}[*] Creating tar.gz archive preserving all filesystem metadata...${NC}"

# Use tar with metadata and timestamp preservation
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
    tar -czf "$ARCHIVE_OUT" --atime-preserve -p -C "$PARENT_DIR" "$BASE_NAME" 2>/dev/null
else
    tar -czf "$ARCHIVE_OUT" -p -C "$PARENT_DIR" "$BASE_NAME" 2>/dev/null
fi

if [ -f "$ARCHIVE_OUT" ]; then
    archive_size=$(stat -c "%s" "$ARCHIVE_OUT" 2>/dev/null || stat -f "%z" "$ARCHIVE_OUT" 2>/dev/null || echo "0")
    archive_sha=$(sha256sum "$ARCHIVE_OUT" 2>/dev/null | awk '{print $1}')
    
    echo -e "\n${GREEN}[+] Archive created successfully!${NC}"
    echo -e "${BOLD}Archive Size :${NC} ${archive_size} bytes"
    echo -e "${BOLD}SHA-256 Seal :${NC} ${CYAN}${archive_sha}${NC}"
    
    # Save digital seal next to archive
    echo "${archive_sha}  $(basename "$ARCHIVE_OUT")" > "${ARCHIVE_OUT}.sha256"
    echo -e "${GREEN}[+] Digital Seal File: ${ARCHIVE_OUT}.sha256${NC}"
else
    echo -e "${RED}[!] Failed to create tar.gz archive${NC}" >&2
    exit 1
fi
