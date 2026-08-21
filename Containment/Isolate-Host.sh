#!/usr/bin/env bash
# ==============================================================================
# Script: Isolate-Host.sh
# Description: Emergency host and network containment script for Linux systems
# Documentation: Immediately isolates a compromised machine using firewall rules
#                (iptables/nftables) by dropping all inbound/outbound traffic
#                while preserving access for SOC / SIEM analyst IPs.
#                Includes automated backup and clean release option (--release).
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

BACKUP_RULES="/var/tmp/dfir_iptables_pre_containment.rules"
ISOLATION_FLAG="/var/tmp/dfir_host_isolated.flag"

usage() {
    echo -e "${CYAN}${BOLD}=== Emergency Linux Network Isolation Tool ===${NC}"
    echo "Usage:"
    echo "  $0 --isolate [--allowed-ips <IP1,IP2...>] [--allow-dns]"
    echo "  $0 --release"
    echo "  $0 --status"
    echo ""
    echo "Options:"
    echo "  --isolate             Activates emergency network isolation (DROP all except whitelist)"
    echo "  --allowed-ips <list>  Allowed IP addresses or subnets (e.g. SOC, SIEM, Analyst IP)"
    echo "  --allow-dns           Allows outbound DNS queries (Port 53 UDP/TCP)"
    echo "  --release             Restores previous firewall state and lifts isolation"
    echo "  --status              Displays current isolation status"
    echo ""
    echo "Examples:"
    echo "  $0 --isolate --allowed-ips \"10.0.0.50,192.168.1.100\""
    echo "  $0 --release"
    exit 1
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] Error: Root privileges are required to modify firewall rules.${NC}" >&2
        exit 1
    fi
}

isolate_host() {
    local allowed_ips="$1"
    local allow_dns="$2"
    
    echo -e "${YELLOW}[!] WARNING: Activating network containment on this host...${NC}"
    
    # 1. Backup existing rules
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "$BACKUP_RULES" 2>/dev/null
        echo -e "${GREEN}[+] Saved existing firewall rules to: ${BACKUP_RULES}${NC}"
    fi
    
    # 2. Flush current rules
    iptables -F
    iptables -X
    iptables -t nat -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
    
    # 3. Set default policies to DROP
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    
    # 4. Allow Loopback interface
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # 5. Allow Established and Related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # 6. Allow DNS if explicitly requested
    if [ "$allow_dns" = "true" ]; then
        echo -e "${CYAN}[*] Allowing outbound DNS queries (Port 53)...${NC}"
        iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    fi
    
    # 7. Add allowed management / SOC / SIEM IPs
    if [ -n "$allowed_ips" ]; then
        IFS=',' read -ra IP_ARRAY <<< "$allowed_ips"
        for ip in "${IP_ARRAY[@]}"; do
            clean_ip=$(echo "$ip" | tr -d ' ')
            [ -n "$clean_ip" ] || continue
            echo -e "${CYAN}[*] Allowing bidirectional traffic with whitelist IP: ${GREEN}${clean_ip}${NC}"
            iptables -A INPUT -s "$clean_ip" -j ACCEPT
            iptables -A OUTPUT -d "$clean_ip" -j ACCEPT
        done
    fi
    
    # Set isolation status flag
    date -u +"%Y-%m-%dT%H:%M:%SZ" > "$ISOLATION_FLAG"
    
    echo -e "\n${RED}${BOLD}[✓] HOST NETWORK ISOLATED SUCCESSFULLY!${NC}"
    echo -e "${YELLOW}Only loopback and explicitly allowed IPs can communicate.${NC}"
}

release_host() {
    echo -e "${CYAN}[*] Restoring original network and firewall configuration...${NC}"
    
    if [ -f "$BACKUP_RULES" ] && command -v iptables-restore >/dev/null 2>&1; then
        iptables-restore < "$BACKUP_RULES"
        rm -f "$BACKUP_RULES"
        echo -e "${GREEN}[+] Original firewall rules restored from backup.${NC}"
    else
        # Permissive fallback if no backup was found
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -F
        echo -e "${YELLOW}[!] Firewall rules restored to default ACCEPT policy.${NC}"
    fi
    
    rm -f "$ISOLATION_FLAG"
    echo -e "${GREEN}${BOLD}[✓] Network isolation lifted.${NC}"
}

status_host() {
    if [ -f "$ISOLATION_FLAG" ]; then
        iso_time=$(cat "$ISOLATION_FLAG")
        echo -e "${RED}${BOLD}[!] STATUS: HOST IS CURRENTLY ISOLATED (since ${iso_time})${NC}"
    else
        echo -e "${GREEN}[+] STATUS: Host is operating with standard network access.${NC}"
    fi
}

# ------------------------------------------------------------------------------
# Main Entry Point & Argument Parsing
# ------------------------------------------------------------------------------
[ $# -eq 0 ] && usage

MODE=""
ALLOWED_IPS=""
ALLOW_DNS="false"

while [ $# -gt 0 ]; do
    case "$1" in
        --isolate)
            MODE="isolate"
            shift
            ;;
        --release)
            MODE="release"
            shift
            ;;
        --status)
            MODE="status"
            shift
            ;;
        --allowed-ips)
            ALLOWED_IPS="$2"
            shift 2
            ;;
        --allow-dns)
            ALLOW_DNS="true"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}[!] Unknown option: $1${NC}" >&2
            usage
            ;;
    esac
done

case "$MODE" in
    isolate)
        check_root
        isolate_host "$ALLOWED_IPS" "$ALLOW_DNS"
        ;;
    release)
        check_root
        release_host
        ;;
    status)
        status_host
        ;;
    *)
        usage
        ;;
esac
