#!/usr/bin/env bash
# ==============================================================================
# Script: DFIR-Script.sh
# Description: Automated Linux Digital Forensics & Incident Response Triage Engine
# Documentation: High-performance incident response and forensic triage orchestrator
#                for Linux systems (Servers & Workstations). Collects evidence adhering
#                to the RFC 3227 order of volatility, exports SIEM-ready CSVs,
#                generates an interactive HTML report, and builds a sealed archive.
# Author: Bellk0ruh
# Version: 2.3.0 (Linux High-Performance Edition)
# License: BSD 3-Clause
# ==============================================================================

set -uo pipefail

# Colors & Formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="2.3.0 (Linux High-Performance Edition)"

# ASCII Banner
show_banner() {
    cat << "EOF"
  _____  ______ _____ _____    ____             _     
 |  __ \|  ____|_   _|  __ \  |  _ \           | |    
 | |  | | |__    | | | |__) | | |_) | __ _ ___| |__  
 | |  | |  __|   | | |  _  /  |  _ < / _` / __| '_ \ 
 | |__| | |     _| |_| | \ \  | |_) | (_| \__ \ | | |
 |_____/|_|    |_____|_|  \_\ |____/ \__,_|___/_| |_|
EOF
    echo -e "${CYAN}Version : ${VERSION}${NC}"
    echo -e "${CYAN}DFIR Bash | Automated Linux Forensic Triage & Memory Engine${NC}"
    echo -e "${CYAN}Author  : Bellk0ruh${NC}"
    echo -e "${CYAN}License : BSD 3-Clause License${NC}"
    echo -e "${BLUE}====================================================================${NC}\n"
}

usage() {
    show_banner
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -w, --window <days>    Sets event and log search window in days (Default: 2)"
    echo "  -o, --output <dir>     Specifies a custom evidence output directory"
    echo "  -c, --compress         Automatically compresses evidence into sealed .tar.gz"
    echo "  -a, --analyze          Generates standalone interactive HTML report (Default: true)"
    echo "  -q, --quick            Quick triage mode (Skips heavy browser databases)"
    echo "  -m, --modules <list>   Runs only specified modules (e.g. network,process,rootkit)"
    echo "  -h, --help             Displays this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0"
    echo "  sudo $0 -w 7 -c"
    echo "  sudo $0 -o /mnt/usb/evidence -c"
    echo "  sudo $0 -m network,process,rootkit"
    exit 0
}

# Default parameters
WINDOW_DAYS=2
CUSTOM_OUTPUT=""
DO_COMPRESS=true
DO_ANALYZE=true
QUICK_MODE=false
SELECTED_MODULES=""

# Parse command line arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -w|--window|--window-days|-sw)
            WINDOW_DAYS="$2"
            shift 2
            ;;
        -o|--output)
            CUSTOM_OUTPUT="$2"
            shift 2
            ;;
        -c|--compress)
            DO_COMPRESS=true
            shift
            ;;
        --no-compress)
            DO_COMPRESS=false
            shift
            ;;
        -a|--analyze)
            DO_ANALYZE=true
            shift
            ;;
        --no-analyze)
            DO_ANALYZE=false
            shift
            ;;
        -q|--quick)
            QUICK_MODE=true
            shift
            ;;
        -m|--modules)
            SELECTED_MODULES="$2"
            shift 2
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

show_banner

START_TIME_EPOCH=$(date +%s)
HOSTNAME_VAL=$(hostname -s 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "linux-host")
CURRENT_DATE=$(date +"%Y-%m-%d_%H%M%S")

# Detect OS and Kernel information
KERNEL_VAL=$(uname -r 2>/dev/null || echo "Unknown Kernel")
OS_NAME="Linux"
if [ -f /etc/os-release ]; then
    OS_NAME=$(grep -oP '^PRETTY_NAME="\K[^"]+' /etc/os-release 2>/dev/null || echo "Linux")
fi

echo -e "Host   : ${BOLD}${HOSTNAME_VAL}${NC} | OS : ${CYAN}${OS_NAME}${NC} (Kernel: ${KERNEL_VAL})"

# Check privilege level
CURRENT_USER=$(whoami 2>/dev/null || id -un 2>/dev/null || echo "unknown")
CURRENT_UID=$(id -u 2>/dev/null || echo "1000")

if [ "$CURRENT_UID" -eq 0 ]; then
    echo -e "Status : ${GREEN}[+] Running with elevated ROOT privileges.${NC}"
else
    echo -e "Status : ${YELLOW}[!] Running with standard privileges (${CURRENT_USER}). System-level artifacts will be skipped.${NC}"
fi

# Create evidence output directory
if [ -n "$CUSTOM_OUTPUT" ]; then
    OUTPUT_FOLDER="$CUSTOM_OUTPUT"
else
    OUTPUT_FOLDER="${PWD}/DFIR-${HOSTNAME_VAL}-${CURRENT_DATE}"
fi

mkdir -p "${OUTPUT_FOLDER}"
CSV_FOLDER="${OUTPUT_FOLDER}/CSV_Results"
mkdir -p "${CSV_FOLDER}"

echo -e "Output Directory : ${BOLD}${CYAN}${OUTPUT_FOLDER}${NC}"
echo -e "SIEM CSV Exports : ${OUTPUT_FOLDER}/CSV_Results/\n"
echo -e "${CYAN}Starting forensic acquisition (Search window: ${WINDOW_DAYS} day(s))...${NC}\n"

# ------------------------------------------------------------------------------
# Modular Acquisition Execution (RFC 3227 Order of Volatility)
# ------------------------------------------------------------------------------
ACQ_DIR="${SCRIPT_DIR}/Acquisition"
ANALYSIS_DIR="${SCRIPT_DIR}/Analysis"

should_run() {
    local mod_name="$1"
    if [ -z "$SELECTED_MODULES" ]; then
        return 0
    fi
    if [[ ",$SELECTED_MODULES," =~ ,"$mod_name", ]]; then
        return 0
    fi
    return 1
}

# 1. Network & Sockets Triage (Maximum Volatility)
if should_run "network" && [ -f "${ACQ_DIR}/CollectNetworkTriage.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectNetworkTriage.sh" "${OUTPUT_FOLDER}"
fi

# 2. Execution, Processes, /proc & Memory Triage (High Volatility)
if should_run "process" && [ -f "${ACQ_DIR}/CollectExecutionArtifacts.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectExecutionArtifacts.sh" "${OUTPUT_FOLDER}"
fi

# 3. Rootkit Indicators & Kernel Integrity
if should_run "rootkit" && [ -f "${ACQ_DIR}/CollectRootkitIndicators.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectRootkitIndicators.sh" "${OUTPUT_FOLDER}"
fi

# 4. User Activity, Sudo & Command Histories
if should_run "user" && [ -f "${ACQ_DIR}/CollectUserActivity.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectUserActivity.sh" "${OUTPUT_FOLDER}"
fi

# 5. Persistence Mechanisms (Systemd, Cron, ld.so.preload, Shell Hooks)
if should_run "persistence" && [ -f "${ACQ_DIR}/CollectPersistence.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectPersistence.sh" "${OUTPUT_FOLDER}"
fi

# 6. SSH Artifacts (Keys, authorized_keys, configurations)
if should_run "ssh" && [ -f "${ACQ_DIR}/CollectSSHArtifacts.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectSSHArtifacts.sh" "${OUTPUT_FOLDER}"
fi

# 7. System Logs & Security Events (Journalctl, Auditd, Auth)
if should_run "logs" && [ -f "${ACQ_DIR}/CollectSystemLogs.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectSystemLogs.sh" "${OUTPUT_FOLDER}" "${WINDOW_DAYS}"
fi

# 8. Mandatory Access Control & Security Subsystems (AppArmor, SELinux, Mitigations)
if should_run "security" && [ -f "${ACQ_DIR}/CollectSecuritySubsystems.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectSecuritySubsystems.sh" "${OUTPUT_FOLDER}"
fi

# 9. Connected Devices, Mounts & Containers (USB, Block, Docker, Podman, K8s, Coredumps)
if should_run "hardware" && [ -f "${ACQ_DIR}/CollectHardwareAndContainers.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectHardwareAndContainers.sh" "${OUTPUT_FOLDER}"
fi

# 10. VPN, Encrypted Tunnels & Reverse Proxies (WireGuard, OpenVPN, Tailscale, Ngrok, Chisel)
if should_run "tunnels" && [ -f "${ACQ_DIR}/CollectVPNAndTunnelingArtifacts.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectVPNAndTunnelingArtifacts.sh" "${OUTPUT_FOLDER}"
fi

# 11. Cloud Metadata & Identity (AWS IMDSv2, Azure, GCP, Cloud-Init)
if should_run "cloud" && [ -f "${ACQ_DIR}/CollectCloudMetadata.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectCloudMetadata.sh" "${OUTPUT_FOLDER}"
fi

# 12. Web Servers & Databases (Nginx, Apache, SSL Certs, Redis, MySQL, PostgreSQL)
if should_run "web" && [ -f "${ACQ_DIR}/CollectWebserverAndDatabaseArtifacts.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectWebserverAndDatabaseArtifacts.sh" "${OUTPUT_FOLDER}"
fi

# 13. eBPF Programs & Stealth Kernel Filters
if should_run "ebpf" && [ -f "${ACQ_DIR}/CollectEBPFArtifacts.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectEBPFArtifacts.sh" "${OUTPUT_FOLDER}"
fi

# 14. Developer Ecosystem & Supply Chain (NPM, PyPI, Cargo, Git Hooks)
if should_run "dev" && [ -f "${ACQ_DIR}/CollectDeveloperEcosystem.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectDeveloperEcosystem.sh" "${OUTPUT_FOLDER}"
fi

# 15. Mail Servers & Spool Queues (Postfix, Exim, Aliases)
if should_run "mail" && [ -f "${ACQ_DIR}/CollectMailArtifacts.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectMailArtifacts.sh" "${OUTPUT_FOLDER}"
fi

# 16. Desktop GUI, Trash & Recent Files (Workstations)
if [ "$QUICK_MODE" = "false" ] && should_run "desktop" && [ -f "${ACQ_DIR}/CollectDesktopArtifacts.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectDesktopArtifacts.sh" "${OUTPUT_FOLDER}"
fi

# 17. File System Artifacts (SUID, Capabilities, /tmp Staging)
if should_run "filesystem" && [ -f "${ACQ_DIR}/CollectFileSystemArtifacts.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectFileSystemArtifacts.sh" "${OUTPUT_FOLDER}" "${WINDOW_DAYS}"
fi

# 18. AI & LLM Tooling Artifacts
if should_run "ai" && [ -f "${ACQ_DIR}/CollectAIArtifacts.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectAIArtifacts.sh" "${OUTPUT_FOLDER}"
fi

# 19. Web Browsers (Chrome, Firefox, Brave, Edge...)
if [ "$QUICK_MODE" = "false" ] && should_run "browsers" && [ -f "${ACQ_DIR}/CollectBrowserArtifacts.sh" ]; then
    echo -e "${BLUE}--------------------------------------------------------------------${NC}"
    bash "${ACQ_DIR}/CollectBrowserArtifacts.sh" "${OUTPUT_FOLDER}"
fi

# ------------------------------------------------------------------------------
# Generate Forensic Manifest & SHA-256 Checksums (Chain of Custody)
# ------------------------------------------------------------------------------
echo -e "${BLUE}====================================================================${NC}"
if [ -f "${ACQ_DIR}/GenerateEvidenceManifest.sh" ]; then
    bash "${ACQ_DIR}/GenerateEvidenceManifest.sh" "${OUTPUT_FOLDER}"
fi

# ------------------------------------------------------------------------------
# Generate Interactive HTML Forensic Report & STIX 2.1 Threat Intel Bundle
# ------------------------------------------------------------------------------
if [ "$DO_ANALYZE" = "true" ]; then
    echo -e "${BLUE}====================================================================${NC}"
    if [ -f "${ANALYSIS_DIR}/Generate-DFIRHtmlReport.sh" ]; then
        REPORT_FILE="${OUTPUT_FOLDER}/DFIR-Report-${HOSTNAME_VAL}-${CURRENT_DATE}.html"
        bash "${ANALYSIS_DIR}/Generate-DFIRHtmlReport.sh" "${OUTPUT_FOLDER}" "${REPORT_FILE}"
    fi
    if [ -f "${ANALYSIS_DIR}/Generate-STIXReport.sh" ]; then
        bash "${ANALYSIS_DIR}/Generate-STIXReport.sh" "${OUTPUT_FOLDER}"
    fi
fi

# ------------------------------------------------------------------------------
# Forensic Packaging & Digital Seal (.tar.gz)
# ------------------------------------------------------------------------------
ARCHIVE_PATH=""
if [ "$DO_COMPRESS" = "true" ] && [ -f "${ACQ_DIR}/ArchiveFolder.sh" ]; then
    echo -e "${BLUE}====================================================================${NC}"
    ARCHIVE_PATH="${OUTPUT_FOLDER}.tar.gz"
    bash "${ACQ_DIR}/ArchiveFolder.sh" "${OUTPUT_FOLDER}" "${ARCHIVE_PATH}"
fi

# ------------------------------------------------------------------------------
# Final Execution Summary
# ------------------------------------------------------------------------------
END_TIME_EPOCH=$(date +%s)
ELAPSED_SEC=$((END_TIME_EPOCH - START_TIME_EPOCH))

echo -e "\n${BLUE}====================================================================${NC}"
echo -e "${GREEN}${BOLD}✓ LINUX FORENSIC ACQUISITION COMPLETED SUCCESSFULLY${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "Execution Time     : ${ELAPSED_SEC} second(s)"
echo -e "Evidence Folder    : ${CYAN}${OUTPUT_FOLDER}${NC}"
if [ -n "$ARCHIVE_PATH" ] && [ -f "$ARCHIVE_PATH" ]; then
    echo -e "Sealed Archive     : ${GREEN}${ARCHIVE_PATH}${NC}"
    echo -e "Digital Seal       : ${GREEN}${ARCHIVE_PATH}.sha256${NC}"
fi
if [ "$DO_ANALYZE" = "true" ] && [ -f "${REPORT_FILE:-}" ]; then
    echo -e "Interactive Report : ${MAGENTA}${REPORT_FILE}${NC}"
fi
echo -e "SIEM CSV Results   : ${OUTPUT_FOLDER}/CSV_Results/"
echo -e "${BLUE}====================================================================${NC}\n"
