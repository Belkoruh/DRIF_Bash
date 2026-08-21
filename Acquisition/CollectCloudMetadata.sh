#!/usr/bin/env bash
# ==============================================================================
# Script: CollectCloudMetadata.sh
# Description: Cloud instance identity, IAM credentials, and Cloud-Init forensic acquisition
# Documentation: Audits and acquires cloud instance metadata for AWS (IMDSv2), Azure (IMDS),
#                Google Cloud Platform (GCP Metadata), and collects cloud-init provisioning logs.
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
OUTPUT_DIR="${TARGET_DIR}/CloudMetadata"
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

echo -e "${CYAN}${BOLD}=== Cloud Instance & IAM Metadata Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "Provider,MetadataKey,Value,SourceURL" > "${CSV_DIR}/CloudMetadata.csv"

# ------------------------------------------------------------------------------
# 1. AWS (Amazon Web Services) IMDSv2 / IMDSv1
# ------------------------------------------------------------------------------
log_info "Testing for AWS EC2 instance metadata (IMDS)..."
mkdir -p "${OUTPUT_DIR}/AWS"

aws_token=""
if command -v curl >/dev/null 2>&1; then
    # Try IMDSv2 token acquisition
    aws_token=$(curl -s --connect-timeout 2 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
    
    hdr_opt=()
    [ -n "$aws_token" ] && hdr_opt=(-H "X-aws-ec2-metadata-token: $aws_token")
    
    # Check if IMDS responds
    ami_id=$(curl -s --connect-timeout 2 "${hdr_opt[@]}" "http://169.254.169.254/latest/meta-data/ami-id" 2>/dev/null || true)
    if [ -n "$ami_id" ] && [[ ! "$ami_id" =~ 404|html ]]; then
        log_success "AWS EC2 instance detected! Acquiring metadata..."
        
        # Instance Identity Document
        curl -s "${hdr_opt[@]}" "http://169.254.169.254/latest/dynamic/instance-identity/document" > "${OUTPUT_DIR}/AWS/instance_identity.json" 2>/dev/null || true
        
        # IAM Security Credentials
        iam_role=$(curl -s "${hdr_opt[@]}" "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null || true)
        if [ -n "$iam_role" ] && [[ ! "$iam_role" =~ 404 ]]; then
            log_warn "AWS IAM Role attached: ${iam_role}"
            curl -s "${hdr_opt[@]}" "http://169.254.169.254/latest/meta-data/iam/security-credentials/${iam_role}" > "${OUTPUT_DIR}/AWS/iam_credentials_dump.json" 2>/dev/null || true
            echo "\"AWS\",\"IAM_Role\",\"${iam_role}\",\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"" >> "${CSV_DIR}/CloudMetadata.csv"
        fi
        
        # Host info
        inst_type=$(curl -s "${hdr_opt[@]}" "http://169.254.169.254/latest/meta-data/instance-type" 2>/dev/null || echo "")
        echo "\"AWS\",\"InstanceType\",\"${inst_type}\",\"http://169.254.169.254/latest/meta-data/instance-type\"" >> "${CSV_DIR}/CloudMetadata.csv"
        echo "\"AWS\",\"AMI_ID\",\"${ami_id}\",\"http://169.254.169.254/latest/meta-data/ami-id\"" >> "${CSV_DIR}/CloudMetadata.csv"
    fi
fi

# ------------------------------------------------------------------------------
# 2. Azure Instance Metadata Service (IMDS)
# ------------------------------------------------------------------------------
log_info "Testing for Microsoft Azure VM instance metadata..."
mkdir -p "${OUTPUT_DIR}/Azure"

if command -v curl >/dev/null 2>&1; then
    azure_md=$(curl -s --connect-timeout 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null || true)
    if [ -n "$azure_md" ] && [[ "$azure_md" =~ compute ]]; then
        log_success "Microsoft Azure VM detected! Saving metadata..."
        echo "$azure_md" > "${OUTPUT_DIR}/Azure/instance_metadata.json"
        
        vm_id=$(echo "$azure_md" | grep -oP '"vmId":"\K[^"]+' || echo "")
        vm_size=$(echo "$azure_md" | grep -oP '"vmSize":"\K[^"]+' || echo "")
        sub_id=$(echo "$azure_md" | grep -oP '"subscriptionId":"\K[^"]+' || echo "")
        
        echo "\"Azure\",\"VM_ID\",\"${vm_id}\",\"http://169.254.169.254/metadata/instance\"" >> "${CSV_DIR}/CloudMetadata.csv"
        echo "\"Azure\",\"VM_Size\",\"${vm_size}\",\"http://169.254.169.254/metadata/instance\"" >> "${CSV_DIR}/CloudMetadata.csv"
        echo "\"Azure\",\"SubscriptionId\",\"${sub_id}\",\"http://169.254.169.254/metadata/instance\"" >> "${CSV_DIR}/CloudMetadata.csv"
    fi
fi

# ------------------------------------------------------------------------------
# 3. Google Cloud Platform (GCP) Metadata
# ------------------------------------------------------------------------------
log_info "Testing for Google Cloud Platform (GCP) compute metadata..."
mkdir -p "${OUTPUT_DIR}/GCP"

if command -v curl >/dev/null 2>&1; then
    gcp_proj=$(curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id" 2>/dev/null || true)
    if [ -n "$gcp_proj" ] && [[ ! "$gcp_proj" =~ 404|html ]]; then
        log_success "GCP Compute Engine instance detected! Project: ${gcp_proj}"
        echo "\"GCP\",\"ProjectID\",\"${gcp_proj}\",\"http://metadata.google.internal/computeMetadata/v1/\"" >> "${CSV_DIR}/CloudMetadata.csv"
        
        # Instance info
        curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true" > "${OUTPUT_DIR}/GCP/instance_metadata.json" 2>/dev/null || true
        
        # Service Accounts
        sa_list=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" 2>/dev/null || true)
        if [ -n "$sa_list" ]; then
            echo "$sa_list" > "${OUTPUT_DIR}/GCP/service_accounts.txt"
            echo "\"GCP\",\"ServiceAccounts\",\"${sa_list}\",\"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/\"" >> "${CSV_DIR}/CloudMetadata.csv"
        fi
    fi
fi

# ------------------------------------------------------------------------------
# 4. Cloud-Init Logs and Provisioning Artifacts
# ------------------------------------------------------------------------------
log_info "Collecting Cloud-Init provisioning logs and instance configs..."
mkdir -p "${OUTPUT_DIR}/CloudInit"

for cl_log in /var/log/cloud-init.log /var/log/cloud-init-output.log; do
    [ -f "$cl_log" ] && cp -p "$cl_log" "${OUTPUT_DIR}/CloudInit/" 2>/dev/null || true
done

if [ -d /var/lib/cloud/instance ]; then
    mkdir -p "${OUTPUT_DIR}/CloudInit/instance_data"
    cp -rp /var/lib/cloud/instance/* "${OUTPUT_DIR}/CloudInit/instance_data/" 2>/dev/null || true
fi

log_success "Cloud metadata and identity triage completed."
