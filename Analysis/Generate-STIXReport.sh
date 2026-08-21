#!/usr/bin/env bash
# ==============================================================================
# Script: Generate-STIXReport.sh
# Description: STIX 2.1 Threat Intelligence Bundle & MISP/OpenCTI IOC Exporter
# Documentation: Extracts Indicators of Compromise (IOCs: SHA-256 hashes, remote C2 IPs,
#                malicious commands, compromised users) from DFIR CSV results and formats them
#                into a standardized STIX 2.1 JSON Bundle and flat CSV IOC feed.
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

EVIDENCE_PATH="${1:-.}"
OUTPUT_JSON="${2:-}"
OUTPUT_CSV="${3:-}"

if [ ! -d "$EVIDENCE_PATH" ]; then
    echo -e "${RED}[!] Error: Target evidence directory '$EVIDENCE_PATH' does not exist.${NC}" >&2
    exit 1
fi

CSV_DIR="${EVIDENCE_PATH}/CSV_Results"
HOSTNAME_VAL="Unknown-Host"
[ -f "${EVIDENCE_PATH}/manifest.json" ] && HOSTNAME_VAL=$(grep -oP '"hostname":\s*"\K[^"]+' "${EVIDENCE_PATH}/manifest.json" 2>/dev/null || echo "Unknown-Host")

TIMESTAMP_VAL=$(date +"%Y%m%d_%H%M%S")
[ -z "$OUTPUT_JSON" ] && OUTPUT_JSON="${EVIDENCE_PATH}/stix_bundle_${HOSTNAME_VAL}_${TIMESTAMP_VAL}.json"
[ -z "$OUTPUT_CSV" ] && OUTPUT_CSV="${EVIDENCE_PATH}/Extracted_IOCs_${HOSTNAME_VAL}_${TIMESTAMP_VAL}.csv"

echo -e "${CYAN}${BOLD}=== STIX 2.1 & Threat Intelligence Exporter ===${NC}"
echo -e "${BLUE}Evidence Directory: ${EVIDENCE_PATH}${NC}"
echo -e "${BLUE}STIX 2.1 Output   : ${OUTPUT_JSON}${NC}"
echo -e "${BLUE}IOC CSV Feed      : ${OUTPUT_CSV}${NC}\n"

echo "IOCType,Value,Context,Severity" > "$OUTPUT_CSV"

tmp_stix_objs=$(mktemp)
current_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

ioc_count=0

# 1. Extract File Hashes from Checksums / Manifest / Deleted Binaries
if [ -f "${EVIDENCE_PATH}/checksums.sha256" ]; then
    grep -Ei '(quarantin|staging|tmp|shm|miner|evil)' "${EVIDENCE_PATH}/checksums.sha256" 2>/dev/null | head -n 50 | while read -r sha_val f_path; do
        [ -n "$sha_val" ] || continue
        ((ioc_count++))
        clean_fpath=$(echo "$f_path" | sed 's/"/\\"/g')
        echo "\"file:hashes.SHA-256\",\"${sha_val}\",\"Path: ${clean_fpath}\",\"HIGH\"" >> "$OUTPUT_CSV"
        
        # Add STIX Indicator object
        cat <<EOF >> "$tmp_stix_objs"
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "hash-${ioc_count}")",
      "created": "${current_utc}",
      "modified": "${current_utc}",
      "name": "Malicious File Hash - ${clean_fpath}",
      "pattern": "[file:hashes.'SHA-256' = '${sha_val}']",
      "pattern_type": "stix",
      "valid_from": "${current_utc}"
    },
EOF
    done
fi

# 2. Extract Remote Sockets / IPs
if [ -f "${CSV_DIR}/OpenSockets.csv" ]; then
    tail -n +2 "${CSV_DIR}/OpenSockets.csv" | while IFS=, read -r proto state lip lport rip rport pname pid user; do
        clean_rip=$(echo "$rip" | tr -d '"')
        if [ -n "$clean_rip" ] && [ "$clean_rip" != "-" ] && [ "$clean_rip" != "0.0.0.0" ] && [ "$clean_rip" != "127.0.0.1" ] && [ "$clean_rip" != "::1" ]; then
            ((ioc_count++))
            echo "\"ipv4-addr:value\",\"${clean_rip}\",\"Remote connection from PID ${pid} (${pname}) on port ${rport}\",\"MEDIUM\"" >> "$OUTPUT_CSV"
            
            cat <<EOF >> "$tmp_stix_objs"
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "ip-${ioc_count}")",
      "created": "${current_utc}",
      "modified": "${current_utc}",
      "name": "Suspicious Remote C2 IP - ${clean_rip}",
      "pattern": "[ipv4-addr:value = '${clean_rip}']",
      "pattern_type": "stix",
      "valid_from": "${current_utc}"
    },
EOF
        fi
    done
fi

# 3. Clean trailing comma from temp STIX objects
if [ -s "$tmp_stix_objs" ]; then
    sed -i '$ s/,$//' "$tmp_stix_objs"
fi

# Assemble complete STIX 2.1 Bundle
bundle_uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "dfir-bundle-1")
cat <<EOF > "$OUTPUT_JSON"
{
  "type": "bundle",
  "id": "bundle--${bundle_uuid}",
  "objects": [
$(cat "$tmp_stix_objs")
  ]
}
EOF

rm -f "$tmp_stix_objs"

total_iocs=$( [ -f "$OUTPUT_CSV" ] && tail -n +2 "$OUTPUT_CSV" | wc -l || echo "0" )

echo -e "${GREEN}${BOLD}[✓] Threat Intelligence export completed!${NC}"
echo -e "Total IOCs Extracted : ${BOLD}${total_iocs}${NC}"
echo -e "STIX 2.1 JSON Bundle : ${CYAN}${OUTPUT_JSON}${NC}"
echo -e "MISP / OpenCTI Feed  : ${CYAN}${OUTPUT_CSV}${NC}"
