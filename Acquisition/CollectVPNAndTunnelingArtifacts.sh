#!/usr/bin/env bash
# ==============================================================================
# Script: CollectVPNAndTunnelingArtifacts.sh
# Description: VPN, Encrypted Tunnel, and Reverse Proxy forensic artifact acquisition
# Documentation: Collects WireGuard, OpenVPN, Tailscale, ZeroTier, Cloudflare Tunnel (cloudflared),
#                Ngrok, Chisel, FRP, Ligolo-ng, IPsec policies, and virtual tunnel interfaces.
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
OUTPUT_DIR="${TARGET_DIR}/TunnelingAndVPN"
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

echo -e "${CYAN}${BOLD}=== VPN, Encrypted Tunnels & Reverse Proxy Acquisition ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "TunnelType,Interface,RemotePeer,ConfigFile,Status" > "${CSV_DIR}/TunnelingArtifacts.csv"

# ------------------------------------------------------------------------------
# 1. Virtual Tunnel Network Interfaces (tun, tap, wg, zt, tailscale)
# ------------------------------------------------------------------------------
log_info "Auditing virtual tunnel network interfaces (tun, tap, wg, tailscale)..."
if command -v ip >/dev/null 2>&1; then
    ip -d link show 2>/dev/null | grep -E '(tun|tap|wireguard|vxlan|gre|ip6tnl)' > "${OUTPUT_DIR}/virtual_tunnel_links.txt" || true
fi

# ------------------------------------------------------------------------------
# 2. WireGuard VPN
# ------------------------------------------------------------------------------
log_info "Checking WireGuard VPN configuration and active peers..."
mkdir -p "${OUTPUT_DIR}/WireGuard"

if command -v wg >/dev/null 2>&1; then
    wg show > "${OUTPUT_DIR}/WireGuard/wg_show.txt" 2>&1 || true
    if [ -s "${OUTPUT_DIR}/WireGuard/wg_show.txt" ]; then
        log_warn "Active WireGuard interface detected!"
        echo "\"WireGuard\",\"wg0\",\"ActivePeers\",\"/etc/wireguard/\",\"ACTIVE\"" >> "${CSV_DIR}/TunnelingArtifacts.csv"
    fi
fi
[ -d /etc/wireguard ] && cp -rp /etc/wireguard "${OUTPUT_DIR}/WireGuard/configs" 2>/dev/null || true

# ------------------------------------------------------------------------------
# 3. OpenVPN
# ------------------------------------------------------------------------------
log_info "Checking OpenVPN configurations and clients..."
mkdir -p "${OUTPUT_DIR}/OpenVPN"

[ -d /etc/openvpn ] && cp -rp /etc/openvpn "${OUTPUT_DIR}/OpenVPN/etc_openvpn" 2>/dev/null || true
for uhome in /root /home/*; do
    find "${uhome}" -maxdepth 3 -type f -name "*.ovpn" 2>/dev/null | while read -r ovpn; do
        cp -p "$ovpn" "${OUTPUT_DIR}/OpenVPN/$(basename "$uhome")_$(basename "$ovpn")" 2>/dev/null || true
        log_info "OpenVPN client config found: ${ovpn}"
        echo "\"OpenVPN\",\"tun\",\"N/A\",\"${ovpn}\",\"CONFIG_FOUND\"" >> "${CSV_DIR}/TunnelingArtifacts.csv"
    done
done

# ------------------------------------------------------------------------------
# 4. Tailscale & ZeroTier
# ------------------------------------------------------------------------------
log_info "Auditing Tailscale and ZeroTier mesh networks..."
mkdir -p "${OUTPUT_DIR}/MeshVPN"

if command -v tailscale >/dev/null 2>&1; then
    tailscale status > "${OUTPUT_DIR}/MeshVPN/tailscale_status.txt" 2>&1 || true
    tailscale ip > "${OUTPUT_DIR}/MeshVPN/tailscale_ips.txt" 2>&1 || true
    echo "\"Tailscale\",\"tailscale0\",\"MeshNetwork\",\"/var/lib/tailscale/\",\"ACTIVE\"" >> "${CSV_DIR}/TunnelingArtifacts.csv"
    log_warn "Tailscale node detected on host!"
fi
[ -d /var/lib/tailscale ] && cp -rp /var/lib/tailscale "${OUTPUT_DIR}/MeshVPN/tailscale_lib" 2>/dev/null || true

if command -v zerotier-cli >/dev/null 2>&1; then
    zerotier-cli listnetworks > "${OUTPUT_DIR}/MeshVPN/zerotier_networks.txt" 2>&1 || true
    echo "\"ZeroTier\",\"zt*\",\"MeshNetwork\",\"/var/lib/zerotier-one/\",\"ACTIVE\"" >> "${CSV_DIR}/TunnelingArtifacts.csv"
    log_warn "ZeroTier node detected on host!"
fi

# ------------------------------------------------------------------------------
# 5. Reverse Tunnels & C2 Proxies (Cloudflared, Ngrok, Chisel, FRP, Ligolo)
# ------------------------------------------------------------------------------
log_info "Auditing reverse proxy & tunneling tools (Cloudflared, Ngrok, Chisel, FRP, Ligolo)..."
mkdir -p "${OUTPUT_DIR}/ReverseTunnels"

# Cloudflare Tunnel
for cf_dir in /etc/cloudflared /root/.cloudflared /home/*/.cloudflared; do
    if [ -d "$cf_dir" ]; then
        cp -rp "$cf_dir" "${OUTPUT_DIR}/ReverseTunnels/$(basename "$cf_dir")" 2>/dev/null || true
        echo "\"CloudflareTunnel\",\"cloudflared\",\"CloudflareEdge\",\"${cf_dir}\",\"CONFIG_FOUND\"" >> "${CSV_DIR}/TunnelingArtifacts.csv"
        log_warn "Cloudflare Tunnel (cloudflared) configuration found in ${cf_dir}!"
    fi
done

# Ngrok
for ng_cfg in /root/.config/ngrok/ngrok.yml /home/*/.config/ngrok/ngrok.yml /root/.ngrok2/ngrok.yml /home/*/.ngrok2/ngrok.yml; do
    if [ -f "$ng_cfg" ]; then
        cp -p "$ng_cfg" "${OUTPUT_DIR}/ReverseTunnels/" 2>/dev/null || true
        echo "\"Ngrok\",\"ngrok\",\"NgrokCloud\",\"${ng_cfg}\",\"CONFIG_FOUND\"" >> "${CSV_DIR}/TunnelingArtifacts.csv"
        log_warn "Ngrok tunnel configuration found: ${ng_cfg}!"
    fi
done

# Search running processes for Chisel, FRP, Ligolo, Socat tunnels
ps auxww 2>/dev/null | grep -Ei '(chisel|frpc|frps|ligolo|gost|rathole|bore|wstunnel|socat.*tcp-listen)' | grep -v 'grep' | while read -r p_line; do
    [ -n "$p_line" ] || continue
    t_comm=$(echo "$p_line" | awk '{print $11}')
    clean_pline=$(echo "$p_line" | sed 's/"/\\"/g')
    echo "\"C2_Tunnel_Process\",\"N/A\",\"${t_comm}\",\"${clean_pline}\",\"RUNNING\"" >> "${CSV_DIR}/TunnelingArtifacts.csv"
    log_warn "SUSPICIOUS C2 TUNNEL PROCESS DETECTED: ${p_line}"
done

# ------------------------------------------------------------------------------
# 6. IPsec Security Associations & Policies (ip xfrm)
# ------------------------------------------------------------------------------
log_info "Auditing IPsec Security Associations and Policies..."
mkdir -p "${OUTPUT_DIR}/IPsec"

if command -v ip >/dev/null 2>&1; then
    ip xfrm state > "${OUTPUT_DIR}/IPsec/xfrm_state.txt" 2>&1 || true
    ip xfrm policy > "${OUTPUT_DIR}/IPsec/xfrm_policy.txt" 2>&1 || true
fi
[ -f /etc/ipsec.conf ] && cp -p /etc/ipsec.conf "${OUTPUT_DIR}/IPsec/" 2>/dev/null || true
[ -d /etc/strongswan ] && cp -rp /etc/strongswan "${OUTPUT_DIR}/IPsec/" 2>/dev/null || true

log_success "VPN, tunnels, and reverse proxy triage completed."
