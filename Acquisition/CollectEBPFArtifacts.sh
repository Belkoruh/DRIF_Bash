#!/usr/bin/env bash
# ==============================================================================
# Script: CollectEBPFArtifacts.sh
# Description: eBPF program, probe, map, and stealth rootkit forensic acquisition
# Documentation: Audits loaded extended Berkeley Packet Filters (eBPF), XDP programs,
#                kprobes, tracepoints, cgroup socket filters, and /sys/fs/bpf pinned objects
#                to identify advanced stealth rootkits (Symbiote, BPFDoor, TripleCross).
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
OUTPUT_DIR="${TARGET_DIR}/EBPF_Artifacts"
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

echo -e "${CYAN}${BOLD}=== eBPF Programs & Stealth Kernel Filters Acquisition ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "ProgID,Type,Name,Tag,LoadedByUID,MapCount,AttachedLinks,AnomalyFlag" > "${CSV_DIR}/EBPFPrograms.csv"

# ------------------------------------------------------------------------------
# 1. Pinned eBPF Filesystem Objects (/sys/fs/bpf)
# ------------------------------------------------------------------------------
log_info "Auditing pinned eBPF objects in /sys/fs/bpf..."
if [ -d /sys/fs/bpf ]; then
    ls -laR /sys/fs/bpf > "${OUTPUT_DIR}/pinned_bpf_objects.txt" 2>&1 || true
    pinned_count=$(find /sys/fs/bpf -type f 2>/dev/null | wc -l || echo "0")
    if [ "$pinned_count" -gt 0 ]; then
        log_warn "Detected ${pinned_count} pinned eBPF object(s) in /sys/fs/bpf!"
    fi
fi

# ------------------------------------------------------------------------------
# 2. Audit Loaded eBPF Programs via bpftool
# ------------------------------------------------------------------------------
log_info "Collecting loaded eBPF programs, maps, and links via bpftool..."
mkdir -p "${OUTPUT_DIR}/bpftool_dumps"

if command -v bpftool >/dev/null 2>&1; then
    # Full JSON dumps
    bpftool prog list -j > "${OUTPUT_DIR}/bpftool_dumps/bpf_progs.json" 2>&1 || true
    bpftool map list -j > "${OUTPUT_DIR}/bpftool_dumps/bpf_maps.json" 2>&1 || true
    bpftool link list -j > "${OUTPUT_DIR}/bpftool_dumps/bpf_links.json" 2>&1 || true
    bpftool net list -j > "${OUTPUT_DIR}/bpftool_dumps/bpf_net.json" 2>&1 || true
    
    # Human readable lists
    bpftool prog list > "${OUTPUT_DIR}/bpftool_dumps/bpf_progs_human.txt" 2>&1 || true
    bpftool map list > "${OUTPUT_DIR}/bpftool_dumps/bpf_maps_human.txt" 2>&1 || true
    bpftool link list > "${OUTPUT_DIR}/bpftool_dumps/bpf_links_human.txt" 2>&1 || true
    bpftool net list > "${OUTPUT_DIR}/bpftool_dumps/bpf_net_human.txt" 2>&1 || true

    # Parse loaded programs into CSV
    bpftool prog list 2>/dev/null | while read -r line; do
        [ -n "$line" ] || continue
        if [[ "$line" =~ ^([0-9]+):\ ([a-zA-Z0-9_]+)\ +name\ ([a-zA-Z0-9_]+)?\ +tag\ ([a-f0-9]+)\ +gpl ]]; then
            pid_val="${BASH_REMATCH[1]}"
            ptype="${BASH_REMATCH[2]}"
            pname="${BASH_REMATCH[3]:-unnamed}"
            ptag="${BASH_REMATCH[4]}"
            
            anomaly="False"
            # Flag kprobe, tracepoint, raw_tracepoint, or socket filter not belonging to known services
            if [[ "$ptype" =~ (kprobe|raw_tp|tracepoint|xdp|socket_filter) ]]; then
                anomaly="SUSPICIOUS_PROBE_TYPE"
            fi
            
            echo "\"${pid_val}\",\"${ptype}\",\"${pname}\",\"${ptag}\",\"0\",\"N/A\",\"N/A\",\"${anomaly}\"" >> "${CSV_DIR}/EBPFPrograms.csv"
        fi
    done
    log_success "bpftool telemetry parsed into CSV."
else
    log_warn "bpftool utility not installed. Inspecting /proc and sysfs directly..."
    # Fallback: Check kernel symbols for active tracepoints and kprobes
    if [ -f /sys/kernel/debug/tracing/kprobe_events ]; then
        cp -p /sys/kernel/debug/tracing/kprobe_events "${OUTPUT_DIR}/active_kprobes.txt" 2>/dev/null || true
    fi
    if [ -f /sys/kernel/debug/kprobes/list ]; then
        cp -p /sys/kernel/debug/kprobes/list "${OUTPUT_DIR}/kprobes_list.txt" 2>/dev/null || true
    fi
fi

# ------------------------------------------------------------------------------
# 3. Kernel Unprivileged eBPF Security Status
# ------------------------------------------------------------------------------
log_info "Checking kernel unprivileged eBPF mitigation flags..."
if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
    bpf_disabled=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "UNKNOWN")
    echo "unprivileged_bpf_disabled: ${bpf_disabled}" > "${OUTPUT_DIR}/bpf_security_flags.txt"
    if [ "$bpf_disabled" = "0" ]; then
        log_warn "RISK: unprivileged_bpf_disabled is 0 (Unprivileged users can load eBPF filters)!"
    fi
fi

log_success "eBPF artifacts acquisition completed."
