#!/usr/bin/env bash
# ==============================================================================
# Script: CollectSSHArtifacts.sh
# Description: SSH artifacts and configuration forensic triage for Linux
# Documentation: Collects OpenSSH server/client configurations, authorized keys
#                (authorized_keys), known hosts (known_hosts), private/public key inventory,
#                host key fingerprints, and active SSH network connections.
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
OUTPUT_DIR="${TARGET_DIR}/SSH"
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

echo -e "${CYAN}${BOLD}=== SSH Artifacts Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

# ------------------------------------------------------------------------------
# 1. OpenSSH Daemon Configuration (/etc/ssh)
# ------------------------------------------------------------------------------
log_info "Collecting OpenSSH server and client configuration files..."
mkdir -p "${OUTPUT_DIR}/ServerConfig"
[ -f /etc/ssh/sshd_config ] && cp -p /etc/ssh/sshd_config "${OUTPUT_DIR}/ServerConfig/"
[ -d /etc/ssh/sshd_config.d ] && cp -rp /etc/ssh/sshd_config.d "${OUTPUT_DIR}/ServerConfig/" 2>/dev/null
[ -f /etc/ssh/ssh_config ] && cp -p /etc/ssh/ssh_config "${OUTPUT_DIR}/ServerConfig/" 2>/dev/null

echo "Parameter,Value,SourceFile" > "${CSV_DIR}/SSHServerConfig.csv"
find /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ -type f 2>/dev/null | while read -r cf; do
    grep -v '^[#[:space:]]*$' "$cf" 2>/dev/null | while read -r param val; do
        [ -n "$param" ] || continue
        clean_val=$(echo "$val" | sed 's/"/\\"/g')
        echo "\"${param}\",\"${clean_val}\",\"${cf}\"" >> "${CSV_DIR}/SSHServerConfig.csv"
    done
done

# Host key fingerprints
mkdir -p "${OUTPUT_DIR}/HostKeys"
for pub in /etc/ssh/ssh_host_*_key.pub; do
    if [ -f "$pub" ]; then
        cp -p "$pub" "${OUTPUT_DIR}/HostKeys/" 2>/dev/null
        if command -v ssh-keygen >/dev/null 2>&1; then
            ssh-keygen -l -f "$pub" >> "${OUTPUT_DIR}/HostKeys/fingerprints.txt" 2>&1 || true
        fi
    fi
done

# ------------------------------------------------------------------------------
# 2. User SSH Artifacts (authorized_keys, known_hosts, config, id_*)
# ------------------------------------------------------------------------------
log_info "Collecting user SSH keys and authorized_keys..."
mkdir -p "${OUTPUT_DIR}/UserSSH"

echo "User,KeyType,PublicKeyHash,Comment,Options,SourceFile" > "${CSV_DIR}/SSHAuthorizedKeys.csv"
echo "User,HostEntry,KeyType,SourceFile" > "${CSV_DIR}/SSHKnownHosts.csv"
echo "User,FileName,Permissions,SHA256,IsPrivateKey" > "${CSV_DIR}/SSHKeyInventory.csv"

for uhome in /root /home/*; do
    [ -d "$uhome" ] || continue
    u_name=$(basename "$uhome")
    ssh_dir="${uhome}/.ssh"
    
    [ -d "$ssh_dir" ] || continue
    dest_u="${OUTPUT_DIR}/UserSSH/${u_name}"
    mkdir -p "$dest_u"
    
    # Authorized Keys
    for ak in authorized_keys authorized_keys2; do
        ak_path="${ssh_dir}/${ak}"
        if [ -f "$ak_path" ]; then
            cp -p "$ak_path" "${dest_u}/${ak}" 2>/dev/null
            grep -v '^[#[:space:]]*$' "$ak_path" 2>/dev/null | while read -r line; do
                [ -n "$line" ] || continue
                
                # Check for options (e.g. from="10.0.0.1",command="...")
                options=""
                ktype=""
                kdata=""
                kcomment=""
                
                first_tok=$(echo "$line" | awk '{print $1}')
                if [[ "$first_tok" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-|ssh-dss) ]]; then
                    ktype="$first_tok"
                    kdata=$(echo "$line" | awk '{print $2}')
                    kcomment=$(echo "$line" | awk '{$1=""; $2=""; print $0}' | sed 's/^[[:space:]]*//' | sed 's/"/\\"/g')
                else
                    options="$first_tok"
                    ktype=$(echo "$line" | awk '{print $2}')
                    kdata=$(echo "$line" | awk '{print $3}')
                    kcomment=$(echo "$line" | awk '{$1=""; $2=""; $3=""; print $0}' | sed 's/^[[:space:]]*//' | sed 's/"/\\"/g')
                fi
                
                khash=$(echo -n "$kdata" | sha256sum | awk '{print $1}')
                echo "\"${u_name}\",\"${ktype}\",\"${khash}\",\"${kcomment}\",\"${options}\",\"${ak_path}\"" >> "${CSV_DIR}/SSHAuthorizedKeys.csv"
                log_info "Authorized key found for user [${u_name}] (${ktype}): ${kcomment:-No comment}"
            done
        fi
    done
    
    # Known Hosts
    for kh in known_hosts known_hosts.old; do
        kh_path="${ssh_dir}/${kh}"
        if [ -f "$kh_path" ]; then
            cp -p "$kh_path" "${dest_u}/${kh}" 2>/dev/null
            grep -v '^[#[:space:]]*$' "$kh_path" 2>/dev/null | while read -r kentry; do
                [ -n "$kentry" ] || continue
                hentry=$(echo "$kentry" | awk '{print $1}' | sed 's/"/\\"/g')
                htype=$(echo "$kentry" | awk '{print $2}')
                echo "\"${u_name}\",\"${hentry}\",\"${htype}\",\"${kh_path}\"" >> "${CSV_DIR}/SSHKnownHosts.csv"
            done
        fi
    done
    
    # SSH Config
    [ -f "${ssh_dir}/config" ] && cp -p "${ssh_dir}/config" "${dest_u}/config" 2>/dev/null
    
    # Key inventory in .ssh (recording metadata without exposing private keys in plaintext)
    for kfile in "${ssh_dir}"/*; do
        [ -f "$kfile" ] || continue
        kbase=$(basename "$kfile")
        perms=$(stat -c "%a" "$kfile" 2>/dev/null || stat -f "%OLp" "$kfile" 2>/dev/null || echo "")
        ksha=$(sha256sum "$kfile" 2>/dev/null | awk '{print $1}')
        
        is_priv="False"
        if grep -q 'BEGIN .*PRIVATE KEY' "$kfile" 2>/dev/null; then
            is_priv="True"
            log_warn "Private SSH key identified in [${u_name}]: ${kbase} (Perms: ${perms})"
        fi
        
        echo "\"${u_name}\",\"${kbase}\",\"${perms}\",\"${ksha}\",\"${is_priv}\"" >> "${CSV_DIR}/SSHKeyInventory.csv"
    done
done

# ------------------------------------------------------------------------------
# 3. Active SSH Network Sockets
# ------------------------------------------------------------------------------
log_info "Searching for active SSH network connections..."
if command -v ss >/dev/null 2>&1; then
    ss -tupn '( dport = :22 or sport = :22 )' > "${OUTPUT_DIR}/active_ssh_sockets.txt" 2>&1 || true
fi

log_success "SSH artifacts triage completed successfully."
