#!/usr/bin/env bash
# ==============================================================================
# Script: Generate-MACTimeline.sh
# Description: Forensic MACB Timeline & Bodyfile generator for Linux
# Documentation: Generates a standard SleuthKit Bodyfile and a detailed CSV supertimeline
#                capturing Modified (M), Accessed (A), Changed Inode (C), and Birth/Creation (B)
#                timestamps for files modified within the incident response time window.
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

TARGET_PATHS="${1:-/tmp,/dev/shm,/var/tmp,/etc,/root,/home,/bin,/sbin,/usr/bin,/usr/sbin}"
WINDOW_DAYS="${2:-7}"
OUTPUT_FILE="${3:-./MACTimeline.csv}"
BODYFILE_OUT="${4:-./filesystem.bodyfile}"

echo -e "${CYAN}${BOLD}=== Forensic MACB Timeline & Bodyfile Generator ===${NC}"
echo -e "${BLUE}Search Window : Last ${WINDOW_DAYS} day(s)${NC}"
echo -e "${BLUE}Output CSV    : ${OUTPUT_FILE}${NC}"
echo -e "${BLUE}Bodyfile      : ${BODYFILE_OUT}${NC}\n"

echo "Timestamp_UTC,ActivityType,FilePath,FileSize,Permissions,UID,GID,Inode,BirthTime" > "$OUTPUT_FILE"
rm -f "$BODYFILE_OUT"

total_entries=0

IFS=',' read -ra PATH_ARRAY <<< "$TARGET_PATHS"
for t_path in "${PATH_ARRAY[@]}"; do
    [ -e "$t_path" ] || continue
    echo -e "${CYAN}[*] Scanning path: ${t_path}...${NC}"
    
    find "$t_path" -maxdepth 4 -mtime -"${WINDOW_DAYS}" -o -ctime -"${WINDOW_DAYS}" 2>/dev/null | while read -r f; do
        [ -e "$f" ] || continue
        
        # Extract stat attributes
        # %n: filename, %s: size, %a: octal perms, %u: uid, %g: gid, %i: inode, %X: atime, %Y: mtime, %Z: ctime, %W: btime
        stat_out=$(stat -c "%s|%a|%u|%g|%i|%X|%Y|%Z|%W" "$f" 2>/dev/null || true)
        [ -n "$stat_out" ] || continue
        
        IFS='|' read -r size perms uid gid inode atime mtime ctime btime <<< "$stat_out"
        
        clean_name=$(echo "$f" | sed 's/"/\\"/g')
        
        # Write to Bodyfile (MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime)
        echo "0|${f}|${inode}|${perms}|${uid}|${gid}|${size}|${atime}|${mtime}|${ctime}|${btime}" >> "$BODYFILE_OUT"
        
        # Convert epoch timestamps to UTC ISO8601
        mtime_utc=$(date -u -d "@${mtime}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "$mtime")
        ctime_utc=$(date -u -d "@${ctime}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "$ctime")
        atime_utc=$(date -u -d "@${atime}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "$atime")
        
        btime_display="N/A"
        [ "$btime" != "0" ] && btime_display=$(date -u -d "@${btime}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "N/A")
        
        # Append events to CSV supertimeline
        echo "\"${mtime_utc}\",\"MODIFIED (Content Change)\",\"${clean_name}\",\"${size}\",\"${perms}\",\"${uid}\",\"${gid}\",\"${inode}\",\"${btime_display}\"" >> "$OUTPUT_FILE"
        echo "\"${ctime_utc}\",\"CHANGED (Inode/Perms Change)\",\"${clean_name}\",\"${size}\",\"${perms}\",\"${uid}\",\"${gid}\",\"${inode}\",\"${btime_display}\"" >> "$OUTPUT_FILE"
        
        ((total_entries++))
    done
done

echo -e "\n${GREEN}${BOLD}[✓] Timeline generation complete!${NC}"
echo -e "Total Events Exported: $(wc -l < "$OUTPUT_FILE") lines"
echo -e "CSV Supertimeline    : ${OUTPUT_FILE}"
echo -e "SleuthKit Bodyfile   : ${BODYFILE_OUT}"
