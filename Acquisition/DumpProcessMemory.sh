#!/usr/bin/env bash
# ==============================================================================
# Script: DumpProcessMemory.sh
# Description: Targeted process memory and virtual address space forensic dumper
# Documentation: Dumps virtual memory segments from /proc/[pid]/mem and /proc/[pid]/maps
#                or gcore for a specific suspect PID to extract decrypted payloads,
#                C2 configurations, encryption keys, and injected shellcodes.
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

TARGET_PID="${1:-}"
OUTPUT_DIR="${2:-./ProcessMemoryDumps}"

if [ -z "$TARGET_PID" ]; then
    echo -e "${RED}[!] Error: Please specify the PID to dump.${NC}" >&2
    echo "Usage: $0 <PID> [Output_Directory]" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Error: Root privileges are required to read /proc/[pid]/mem.${NC}" >&2
    exit 1
fi

if [ ! -d "/proc/${TARGET_PID}" ]; then
    echo -e "${RED}[!] Process PID ${TARGET_PID} does not exist.${NC}" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
PNAME=$(cat "/proc/${TARGET_PID}/comm" 2>/dev/null || echo "unknown")
DUMP_FILE="${OUTPUT_DIR}/pid_${TARGET_PID}_${PNAME}.dmp"

echo -e "${CYAN}${BOLD}=== Targeted Process Memory Dumper (Linux) ===${NC}"
echo -e "${BLUE}Target PID : ${BOLD}${TARGET_PID}${NC} (${PNAME})"
echo -e "${BLUE}Output File: ${DUMP_FILE}${NC}\n"

# 1. Save process metadata
log_info "Saving process execution context..."
cp -p "/proc/${TARGET_PID}/status" "${OUTPUT_DIR}/pid_${TARGET_PID}_status.txt" 2>/dev/null || true
cp -p "/proc/${TARGET_PID}/maps" "${OUTPUT_DIR}/pid_${TARGET_PID}_maps.txt" 2>/dev/null || true
cp -p "/proc/${TARGET_PID}/smaps" "${OUTPUT_DIR}/pid_${TARGET_PID}_smaps.txt" 2>/dev/null || true
[ -f "/proc/${TARGET_PID}/cmdline" ] && tr '\0' ' ' < "/proc/${TARGET_PID}/cmdline" > "${OUTPUT_DIR}/pid_${TARGET_PID}_cmdline.txt" 2>/dev/null || true
[ -f "/proc/${TARGET_PID}/environ" ] && tr '\0' '\n' < "/proc/${TARGET_PID}/environ" > "${OUTPUT_DIR}/pid_${TARGET_PID}_environ.txt" 2>/dev/null || true

# 2. Memory acquisition via gcore if available
if command -v gcore >/dev/null 2>&1; then
    log_info "Using gcore utility to dump complete ELF core image..."
    gcore -o "${OUTPUT_DIR}/pid_${TARGET_PID}_core" "$TARGET_PID" >/dev/null 2>&1 || true
    if [ -f "${OUTPUT_DIR}/pid_${TARGET_PID}_core.${TARGET_PID}" ]; then
        mv "${OUTPUT_DIR}/pid_${TARGET_PID}_core.${TARGET_PID}" "$DUMP_FILE"
    fi
fi

# 3. Direct memory extraction via /proc/PID/mem and /proc/PID/maps if gcore not generated
if [ ! -f "$DUMP_FILE" ] && [ -r "/proc/${TARGET_PID}/mem" ] && [ -r "/proc/${TARGET_PID}/maps" ]; then
    log_info "Extracting readable virtual memory pages directly from /proc/${TARGET_PID}/mem..."
    rm -f "$DUMP_FILE"
    
    while read -r line; do
        range=$(echo "$line" | awk '{print $1}')
        perms=$(echo "$line" | awk '{print $2}')
        
        # Only dump readable segments (r--)
        [[ "$perms" =~ ^r ]] || continue
        
        start_hex="0x${range%%-*}"
        end_hex="0x${range##*-}"
        
        start_dec=$((start_hex))
        end_dec=$((end_hex))
        length=$((end_dec - start_dec))
        
        # Guard against absurd ranges (e.g. kernel vsyscall)
        [ $length -gt 0 ] && [ $length -lt 536870912 ] || continue
        
        dd if="/proc/${TARGET_PID}/mem" bs=1 skip="$start_dec" count="$length" >> "$DUMP_FILE" 2>/dev/null || true
    done < "/proc/${TARGET_PID}/maps"
fi

if [ -f "$DUMP_FILE" ] && [ -s "$DUMP_FILE" ]; then
    dmp_size=$(stat -c "%s" "$DUMP_FILE" 2>/dev/null || echo "0")
    dmp_sha=$(sha256sum "$DUMP_FILE" 2>/dev/null | awk '{print $1}')
    
    echo -e "\n${GREEN}${BOLD}[✓] Process memory successfully dumped!${NC}"
    echo -e "Dump File  : ${BOLD}${DUMP_FILE}${NC}"
    echo -e "Dump Size  : ${dmp_size} bytes"
    echo -e "SHA-256    : ${CYAN}${dmp_sha}${NC}"
else
    echo -e "${RED}[!] Unable to dump process memory (pTrace protection or process terminated).${NC}" >&2
fi
