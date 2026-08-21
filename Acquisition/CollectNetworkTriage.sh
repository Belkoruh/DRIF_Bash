#!/usr/bin/env bash
# ==============================================================================
# Script: CollectNetworkTriage.sh
# Description: Full network forensics triage and artifact acquisition for Linux
# Documentation: Collects active listening and established sockets, routing tables,
#                ARP/neighbor cache, DNS configuration, firewall rules (iptables/nftables),
#                and eBPF active filters. Outputs raw files and SIEM-ready CSVs.
# Author: Bellk0ruh
# License: BSD 3-Clause
# ==============================================================================

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TARGET_DIR="${1:-.}"
OUTPUT_DIR="${TARGET_DIR}/Network"
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

echo -e "${CYAN}${BOLD}=== Linux Network Artifacts Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

# ------------------------------------------------------------------------------
# 1. Network Interfaces & IP Addresses
# ------------------------------------------------------------------------------
log_info "Collecting network interfaces and IP addresses..."
if command -v ip >/dev/null 2>&1; then
    ip -d addr show > "${OUTPUT_DIR}/ip_addresses.txt" 2>&1
    ip link show > "${OUTPUT_DIR}/ip_links.txt" 2>&1
elif command -v ifconfig >/dev/null 2>&1; then
    ifconfig -a > "${OUTPUT_DIR}/ip_addresses.txt" 2>&1
fi

# Export interfaces to CSV
echo "Interface,State,MTU,MAC,IPv4,IPv6" > "${CSV_DIR}/NetworkInterfaces.csv"
if command -v ip >/dev/null 2>&1; then
    ip -o link show 2>/dev/null | while read -r line; do
        iface=$(echo "$line" | awk -F': ' '{print $2}' | cut -d'@' -f1)
        state=$(echo "$line" | grep -oP 'state \K\w+' || echo "UNKNOWN")
        mtu=$(echo "$line" | grep -oP 'mtu \K\d+' || echo "")
        mac=$(echo "$line" | grep -oP 'link/\w+ \K[0-9a-f:]{17}' || echo "")
        ipv4=$(ip -o -4 addr show "$iface" 2>/dev/null | awk '{print $4}' | paste -sd ';' - || echo "")
        ipv6=$(ip -o -6 addr show "$iface" 2>/dev/null | awk '{print $4}' | paste -sd ';' - || echo "")
        echo "\"${iface}\",\"${state}\",\"${mtu}\",\"${mac}\",\"${ipv4}\",\"${ipv6}\"" >> "${CSV_DIR}/NetworkInterfaces.csv"
    done
fi

# ------------------------------------------------------------------------------
# 2. Routing Tables
# ------------------------------------------------------------------------------
log_info "Collecting routing tables..."
if command -v ip >/dev/null 2>&1; then
    ip route show table all > "${OUTPUT_DIR}/ip_route_all.txt" 2>&1
    ip route show > "${OUTPUT_DIR}/ip_route_main.txt" 2>&1
    ip -6 route show > "${OUTPUT_DIR}/ip_route_v6.txt" 2>&1
fi
if command -v route >/dev/null 2>&1; then
    route -n -e > "${OUTPUT_DIR}/route_legacy.txt" 2>&1
fi

# Export routing table to CSV
echo "Destination,Gateway,Interface,Metric,Protocol,Scope" > "${CSV_DIR}/RouteTable.csv"
if command -v ip >/dev/null 2>&1; then
    ip route show 2>/dev/null | while read -r line; do
        dst=$(echo "$line" | awk '{print $1}')
        gw=$(echo "$line" | grep -oP 'via \K[\d\.]+' || echo "DIRECT")
        dev=$(echo "$line" | grep -oP 'dev \K\S+' || echo "")
        metric=$(echo "$line" | grep -oP 'metric \K\d+' || echo "0")
        proto=$(echo "$line" | grep -oP 'proto \K\S+' || echo "")
        scope=$(echo "$line" | grep -oP 'scope \K\S+' || echo "")
        echo "\"${dst}\",\"${gw}\",\"${dev}\",\"${metric}\",\"${proto}\",\"${scope}\"" >> "${CSV_DIR}/RouteTable.csv"
    done
fi

# ------------------------------------------------------------------------------
# 3. ARP Cache & Neighbor Table
# ------------------------------------------------------------------------------
log_info "Collecting ARP cache and network neighbors..."
if command -v ip >/dev/null 2>&1; then
    ip neigh show > "${OUTPUT_DIR}/ip_neighbors.txt" 2>&1
fi
if command -v arp >/dev/null 2>&1; then
    arp -an -v > "${OUTPUT_DIR}/arp_cache.txt" 2>&1
fi
[ -f /proc/net/arp ] && cp -p /proc/net/arp "${OUTPUT_DIR}/proc_net_arp.txt"

# Export ARP cache to CSV
echo "IP_Address,MAC_Address,Interface,State" > "${CSV_DIR}/ARPTable.csv"
if [ -f /proc/net/arp ]; then
    tail -n +2 /proc/net/arp | while read -r ip hw flags mac mask dev; do
        state="REACHABLE"
        [ "$flags" = "0x0" ] && state="INCOMPLETE"
        [ "$flags" = "0x2" ] && state="STATIC"
        echo "\"${ip}\",\"${mac}\",\"${dev}\",\"${state}\"" >> "${CSV_DIR}/ARPTable.csv"
    done
fi

# ------------------------------------------------------------------------------
# 4. Active Sockets & Network Connections (TCP/UDP/RAW/Unix)
# ------------------------------------------------------------------------------
log_info "Collecting active sockets and open connections..."
if command -v ss >/dev/null 2>&1; then
    ss -tupna -e -i > "${OUTPUT_DIR}/ss_all_connections.txt" 2>&1
    ss -tulpn -e > "${OUTPUT_DIR}/ss_listening_ports.txt" 2>&1
    ss -x -a -p > "${OUTPUT_DIR}/ss_unix_sockets.txt" 2>&1
fi

if command -v netstat >/dev/null 2>&1; then
    netstat -tulpn -e > "${OUTPUT_DIR}/netstat_listening.txt" 2>&1
    netstat -anp -e > "${OUTPUT_DIR}/netstat_all.txt" 2>&1
fi

if command -v lsof >/dev/null 2>&1; then
    lsof -i -n -P > "${OUTPUT_DIR}/lsof_network.txt" 2>&1
fi

# Copy raw kernel /proc/net tables
for pfile in tcp tcp6 udp udp6 raw raw6 packet netlink dev; do
    [ -f "/proc/net/${pfile}" ] && cp -p "/proc/net/${pfile}" "${OUTPUT_DIR}/proc_net_${pfile}.txt" 2>/dev/null
done

# Export open sockets to CSV
echo "Protocol,State,Local_Address,Local_Port,Remote_Address,Remote_Port,Process_Name,PID,User" > "${CSV_DIR}/OpenSockets.csv"
if command -v ss >/dev/null 2>&1; then
    ss -tulpn -H 2>/dev/null | while read -r proto state recvq sendq local remote users; do
        loc_ip="${local%:*}"
        loc_port="${local##*:}"
        rem_ip="${remote%:*}"
        rem_port="${remote##*:}"
        
        pname=""
        pid=""
        puser=""
        if [ -n "$users" ]; then
            pname=$(echo "$users" | grep -oP 'users:\(\("\K[^"]+' || echo "")
            pid=$(echo "$users" | grep -oP 'pid=\K\d+' || echo "")
        fi
        
        echo "\"${proto}\",\"${state}\",\"${loc_ip}\",\"${loc_port}\",\"${rem_ip}\",\"${rem_port}\",\"${pname}\",\"${pid}\",\"${puser}\"" >> "${CSV_DIR}/OpenSockets.csv"
    done
fi

# ------------------------------------------------------------------------------
# 5. DNS Configuration & Local Resolvers
# ------------------------------------------------------------------------------
log_info "Collecting DNS configuration and host resolution files..."
[ -f /etc/resolv.conf ] && cp -p /etc/resolv.conf "${OUTPUT_DIR}/resolv.conf" 2>/dev/null
[ -f /etc/hosts ] && cp -p /etc/hosts "${OUTPUT_DIR}/hosts.txt" 2>/dev/null
[ -f /etc/hosts.allow ] && cp -p /etc/hosts.allow "${OUTPUT_DIR}/hosts.allow.txt" 2>/dev/null
[ -f /etc/hosts.deny ] && cp -p /etc/hosts.deny "${OUTPUT_DIR}/hosts.deny.txt" 2>/dev/null
[ -f /etc/nsswitch.conf ] && cp -p /etc/nsswitch.conf "${OUTPUT_DIR}/nsswitch.conf" 2>/dev/null

if command -v resolvectl >/dev/null 2>&1; then
    resolvectl status > "${OUTPUT_DIR}/systemd_resolvectl_status.txt" 2>&1
    resolvectl statistics > "${OUTPUT_DIR}/systemd_resolvectl_stats.txt" 2>&1
elif command -v systemd-resolve >/dev/null 2>&1; then
    systemd-resolve --status > "${OUTPUT_DIR}/systemd_resolve_status.txt" 2>&1
fi

# ------------------------------------------------------------------------------
# 6. Firewall & Packet Filtering Rules
# ------------------------------------------------------------------------------
log_info "Collecting firewall rules (iptables, nftables, ufw, firewalld)..."
if command -v iptables-save >/dev/null 2>&1; then
    iptables-save -c > "${OUTPUT_DIR}/iptables_rules.txt" 2>&1
fi
if command -v ip6tables-save >/dev/null 2>&1; then
    ip6tables-save -c > "${OUTPUT_DIR}/ip6tables_rules.txt" 2>&1
fi
if command -v nft >/dev/null 2>&1; then
    nft list ruleset > "${OUTPUT_DIR}/nftables_ruleset.txt" 2>&1
fi
if command -v ufw >/dev/null 2>&1; then
    ufw status verbose > "${OUTPUT_DIR}/ufw_status.txt" 2>&1
fi
if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --list-all-zones > "${OUTPUT_DIR}/firewalld_all_zones.txt" 2>&1
fi

# ------------------------------------------------------------------------------
# 7. eBPF Programs & Network Probes (eBPF rootkit & network hook audit)
# ------------------------------------------------------------------------------
log_info "Auditing eBPF programs and network filters..."
if command -v bpftool >/dev/null 2>&1; then
    bpftool prog list > "${OUTPUT_DIR}/ebpf_programs.txt" 2>&1
    bpftool map list > "${OUTPUT_DIR}/ebpf_maps.txt" 2>&1
    bpftool net list > "${OUTPUT_DIR}/ebpf_net_filters.txt" 2>&1
    bpftool link list > "${OUTPUT_DIR}/ebpf_links.txt" 2>&1
else
    echo "bpftool not available on host" > "${OUTPUT_DIR}/ebpf_programs.txt"
fi

log_success "Network triage completed successfully."
