#!/usr/bin/env bash
# ==============================================================================
# Script: DetectCryptominers.sh
# Description: Automated cryptominer, Stratum protocol, and resource hijacking hunter
# Documentation: Detects illicit cryptocurrency miners (XMRig, kworker disguise, Stratum protocols),
#                monitors high CPU/GPU utilization, mining configuration files on disk,
#                and active socket connections to known mining pool endpoints.
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

echo -e "${CYAN}${BOLD}=== Cryptominer & Resource Hijacking Threat Hunter ===${NC}\n"

MINING_PORTS="3333|4444|5555|7777|8888|9999|14444|18080|33333|44444"
MINING_POOLS="minexmr|nanopool|supportxmr|hashvault|c3pool|monerohash|dwarfpool|unmineable|f2pool|ethermine"
MINING_KEYWORDS='(stratum\+tcp|donate-level|cryptonight|randomx|rx/0|hashrate|pool_address|xmrig|cpuminer)'

detected_alerts=0

# ------------------------------------------------------------------------------
# 1. Inspect High-CPU Processes & Kernel Disguises
# ------------------------------------------------------------------------------
echo -e "${BLUE}[1] Auditing High CPU Processes & Fake Kernel Threads:${NC}"
ps -eo pid,ppid,user,%cpu,%mem,comm,args --sort=-%cpu | head -n 15 | while read -r line; do
    [ -n "$line" ] || continue
    cpu_val=$(echo "$line" | awk '{print $4}')
    comm_val=$(echo "$line" | awk '{print $6}')
    pid_val=$(echo "$line" | awk '{print $1}')
    
    # Check if a userland process is disguised as a bracketed kernel thread (e.g. [kworker/0:0])
    if [ -d "/proc/${pid_val}" ] && [[ "$comm_val" =~ ^\[.*\]$ ]]; then
        # Real kernel threads have empty /proc/PID/cmdline
        if [ -s "/proc/${pid_val}/cmdline" ]; then
            ((detected_alerts++))
            echo -e " - ${RED}[CRITICAL ANOMALY]${NC} Fake kernel thread detected! PID: ${pid_val} (${comm_val}) CPU: ${cpu_val}%"
            echo -e "   - Cmdline: $(cat "/proc/${pid_val}/cmdline" 2>/dev/null | tr '\0' ' ')"
        fi
    fi
    
    # Flag processes consuming > 75% CPU
    if (( $(echo "$cpu_val > 75.0" | awk '{print ($1 > 75)}' 2>/dev/null || echo 0) )); then
        echo -e " - ${YELLOW}[HIGH CPU]${NC} PID ${pid_val} (${comm_val}) using ${cpu_val}% CPU"
    fi
done
echo ""

# ------------------------------------------------------------------------------
# 2. Check Active Network Connections to Mining Ports / Domains
# ------------------------------------------------------------------------------
echo -e "${BLUE}[2] Checking Active Network Sockets for Stratum Protocol & Pool Connections:${NC}"
if command -v ss >/dev/null 2>&1; then
    ss -tupna 2>/dev/null | grep -E "(${MINING_PORTS})" | while read -r s_line; do
        ((detected_alerts++))
        echo -e " - ${RED}[MINER SOCKET DETECTED]${NC} ${s_line}"
    done
fi

# Check DNS cache or /etc/hosts for known pools
if grep -Eiq "$MINING_POOLS" /etc/hosts 2>/dev/null; then
    ((detected_alerts++))
    echo -e " - ${RED}[MINING POOL IN /etc/hosts]${NC} $(grep -Ei "$MINING_POOLS" /etc/hosts)"
fi
echo ""

# ------------------------------------------------------------------------------
# 3. Scan for Miner Configuration Files on Disk
# ------------------------------------------------------------------------------
echo -e "${BLUE}[3] Scanning Disk for Cryptominer Configuration Files (JSON/YAML):${NC}"
find /tmp /dev/shm /var/tmp /root /home /opt /etc -maxdepth 4 -type f \( -name "*.json" -o -name "*.conf" -o -name "*.cfg" \) 2>/dev/null | while read -r cfg_f; do
    if grep -Eiq "$MINING_KEYWORDS" "$cfg_f" 2>/dev/null; then
        ((detected_alerts++))
        sha_val=$(sha256sum "$cfg_f" 2>/dev/null | awk '{print $1}')
        echo -e " - ${RED}[MINER CONFIG FOUND]${NC} ${cfg_f} (SHA-256: ${sha_val})"
    fi
done
echo ""

# ------------------------------------------------------------------------------
# 4. GPU Utilization Audit
# ------------------------------------------------------------------------------
echo -e "${BLUE}[4] GPU Hardware Utilization Check:${NC}"
if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia-smi --query-gpu=name,utilization.gpu,utilization.memory,temperature.gpu --format=csv,noheader 2>/dev/null | while read -r gpu_info; do
        echo -e " - NVIDIA GPU: ${gpu_info}"
    done
else
    echo "No proprietary GPU utility (nvidia-smi) found."
fi

echo ""
if [ "$detected_alerts" -eq 0 ]; then
    echo -e "${GREEN}[+] No obvious active cryptominer indicators or Stratum connections detected.${NC}"
else
    echo -e "${RED}[!] WARNING: ${detected_alerts} cryptomining indicator(s) identified on the system!${NC}"
fi
