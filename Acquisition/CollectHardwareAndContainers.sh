#!/usr/bin/env bash
# ==============================================================================
# Script: CollectHardwareAndContainers.sh
# Description: Connected devices, storage mounts, containers, and crash dump forensics
# Documentation: Collects USB device history, PCI devices, block devices & mounts (fstab),
#                Container engines (Docker, Podman, CRI-O, Kubernetes, LXC),
#                and system core crash dumps (coredumpctl).
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
OUTPUT_DIR="${TARGET_DIR}/HardwareAndContainers"
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

echo -e "${CYAN}${BOLD}=== Connected Devices, Mounts & Containers Acquisition ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "DeviceType,DeviceID,Vendor,Model,SerialNumber,BusInfo" > "${CSV_DIR}/ConnectedDevices.csv"
echo "Device,MountPoint,FSType,Options,Dump,Pass" > "${CSV_DIR}/MountPoints.csv"
echo "Runtime,ContainerID,Name,Image,Status,Created,Ports" > "${CSV_DIR}/Containers.csv"
echo "PID,UID,GID,Executable,Timestamp,Signal,CoreFileSize" > "${CSV_DIR}/SystemCoredumps.csv"

# ------------------------------------------------------------------------------
# 1. Connected Devices (USB, PCI, Hardware Peripherals)
# ------------------------------------------------------------------------------
log_info "Collecting connected hardware devices (USB, PCI)..."
mkdir -p "${OUTPUT_DIR}/Devices"

# USB Devices
if command -v lsusb >/dev/null 2>&1; then
    lsusb > "${OUTPUT_DIR}/Devices/lsusb.txt" 2>&1 || true
    lsusb -v > "${OUTPUT_DIR}/Devices/lsusb_verbose.txt" 2>&1 || true
    
    lsusb 2>/dev/null | while read -r line; do
        bus=$(echo "$line" | grep -oP 'Bus \d+ Device \d+' || echo "")
        id=$(echo "$line" | grep -oP 'ID \K[0-9a-f:]+' || echo "")
        descr=$(echo "$line" | sed -E 's/Bus [0-9]+ Device [0-9]+: ID [0-9a-f:]+ //')
        clean_descr=$(echo "$descr" | sed 's/"/\\"/g')
        echo "\"USB\",\"${id}\",\"${clean_descr}\",\"N/A\",\"N/A\",\"${bus}\"" >> "${CSV_DIR}/ConnectedDevices.csv"
    done
fi

# USB history from dmesg/journal
if [ -d /sys/bus/usb/devices ]; then
    ls -la /sys/bus/usb/devices/ > "${OUTPUT_DIR}/Devices/sys_usb_devices.txt" 2>&1 || true
fi

# PCI Devices
if command -v lspci >/dev/null 2>&1; then
    lspci -v > "${OUTPUT_DIR}/Devices/lspci.txt" 2>&1 || true
fi

# DMI / Hardware Information
if command -v dmidecode >/dev/null 2>&1; then
    dmidecode > "${OUTPUT_DIR}/Devices/dmidecode.txt" 2>&1 || true
fi

# ------------------------------------------------------------------------------
# 2. Block Devices, Partitions & Mount Points
# ------------------------------------------------------------------------------
log_info "Collecting block storage devices, partitions, and active mounts..."
mkdir -p "${OUTPUT_DIR}/Storage"

[ -f /etc/fstab ] && cp -p /etc/fstab "${OUTPUT_DIR}/Storage/fstab" 2>/dev/null
[ -f /proc/mounts ] && cp -p /proc/mounts "${OUTPUT_DIR}/Storage/proc_mounts.txt" 2>/dev/null

if command -v lsblk >/dev/null 2>&1; then
    lsblk -a -O > "${OUTPUT_DIR}/Storage/lsblk_all.txt" 2>&1 || true
fi
if command -v findmnt >/dev/null 2>&1; then
    findmnt -a > "${OUTPUT_DIR}/Storage/findmnt.txt" 2>&1 || true
fi
if command -v df >/dev/null 2>&1; then
    df -hT > "${OUTPUT_DIR}/Storage/disk_usage.txt" 2>&1 || true
fi

# Export mounts to CSV
if [ -f /proc/mounts ]; then
    while read -r dev mnt fstype opts dump pass; do
        echo "\"${dev}\",\"${mnt}\",\"${fstype}\",\"${opts}\",\"${dump}\",\"${pass}\"" >> "${CSV_DIR}/MountPoints.csv"
    done < /proc/mounts
fi

# ------------------------------------------------------------------------------
# 3. Containers & Virtualization (Docker, Podman, Kubernetes, LXC)
# ------------------------------------------------------------------------------
log_info "Auditing container runtimes (Docker, Podman, Kubernetes, LXC)..."
mkdir -p "${OUTPUT_DIR}/Containers"

# Docker
if command -v docker >/dev/null 2>&1; then
    log_info "Docker client detected..."
    docker info > "${OUTPUT_DIR}/Containers/docker_info.txt" 2>&1 || true
    docker ps -a --no-trunc > "${OUTPUT_DIR}/Containers/docker_ps.txt" 2>&1 || true
    docker images --no-trunc > "${OUTPUT_DIR}/Containers/docker_images.txt" 2>&1 || true
    docker network ls > "${OUTPUT_DIR}/Containers/docker_networks.txt" 2>&1 || true
    
    # Export Docker containers to CSV
    docker ps -a --format '{{.ID}},{{.Names}},{{.Image}},{{.Status}},{{.CreatedAt}},{{.Ports}}' 2>/dev/null | while IFS=, read -r cid cname cimg cstat ctime cports; do
        [ -n "$cid" ] || continue
        echo "\"Docker\",\"${cid}\",\"${cname}\",\"${cimg}\",\"${cstat}\",\"${ctime}\",\"${cports}\"" >> "${CSV_DIR}/Containers.csv"
    done || true
fi
[ -f /etc/docker/daemon.json ] && cp -p /etc/docker/daemon.json "${OUTPUT_DIR}/Containers/" 2>/dev/null

# Podman
if command -v podman >/dev/null 2>&1; then
    log_info "Podman client detected..."
    podman info > "${OUTPUT_DIR}/Containers/podman_info.txt" 2>&1 || true
    podman ps -a --no-trunc > "${OUTPUT_DIR}/Containers/podman_ps.txt" 2>&1 || true
    
    podman ps -a --format '{{.ID}},{{.Names}},{{.Image}},{{.Status}},{{.Created}},{{.Ports}}' 2>/dev/null | while IFS=, read -r cid cname cimg cstat ctime cports; do
        [ -n "$cid" ] || continue
        echo "\"Podman\",\"${cid}\",\"${cname}\",\"${cimg}\",\"${cstat}\",\"${ctime}\",\"${cports}\"" >> "${CSV_DIR}/Containers.csv"
    done || true
fi

# Kubernetes / Kubelet
if [ -d /etc/kubernetes ]; then
    mkdir -p "${OUTPUT_DIR}/Containers/kubernetes_config"
    cp -rp /etc/kubernetes/* "${OUTPUT_DIR}/Containers/kubernetes_config/" 2>/dev/null || true
fi
for uhome in /root /home/*; do
    if [ -f "${uhome}/.kube/config" ]; then
        mkdir -p "${OUTPUT_DIR}/Containers/kubeconfig_$(basename "$uhome")"
        cp -p "${uhome}/.kube/config" "${OUTPUT_DIR}/Containers/kubeconfig_$(basename "$uhome")/" 2>/dev/null || true
    fi
done

# LXC / LXD
if command -v lxc >/dev/null 2>&1; then
    lxc list > "${OUTPUT_DIR}/Containers/lxc_list.txt" 2>&1 || true
fi

# ------------------------------------------------------------------------------
# 4. System Core Dumps & Crash Logs (coredumpctl)
# ------------------------------------------------------------------------------
log_info "Auditing system crash dumps and core dumps..."
mkdir -p "${OUTPUT_DIR}/CrashDumps"

if command -v coredumpctl >/dev/null 2>&1; then
    coredumpctl list --no-pager > "${OUTPUT_DIR}/CrashDumps/coredumpctl_list.txt" 2>&1 || true
    
    coredumpctl list --no-legend --no-pager 2>/dev/null | head -n 50 | while read -r line; do
        [ -n "$line" ] || continue
        pid=$(echo "$line" | awk '{print $5}')
        uid=$(echo "$line" | awk '{print $6}')
        gid=$(echo "$line" | awk '{print $7}')
        sig=$(echo "$line" | awk '{print $8}')
        exe=$(echo "$line" | awk '{print $10}')
        echo "\"${pid}\",\"${uid}\",\"${gid}\",\"${exe}\",\"N/A\",\"${sig}\",\"N/A\"" >> "${CSV_DIR}/SystemCoredumps.csv"
    done
fi

for crash_dir in /var/crash /var/lib/systemd/coredump; do
    if [ -d "$crash_dir" ]; then
        ls -la "$crash_dir" > "${OUTPUT_DIR}/CrashDumps/$(basename "$crash_dir")_listing.txt" 2>&1 || true
    fi
done

log_success "Hardware, storage, containers, and coredumps triage completed."
