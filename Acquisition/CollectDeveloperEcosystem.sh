#!/usr/bin/env bash
# ==============================================================================
# Script: CollectDeveloperEcosystem.sh
# Description: Supply chain, developer secrets, package managers & Git hooks forensics
# Documentation: Audits NPM (.npmrc), Python (.pypirc, .pth persistence), Rust Cargo,
#                Go binaries, Git global hooks, and credential stores for supply chain compromise.
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
OUTPUT_DIR="${TARGET_DIR}/DeveloperEcosystem"
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

echo -e "${CYAN}${BOLD}=== Developer Ecosystem & Supply Chain Artifacts Acquisition ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "Ecosystem,ArtifactType,Path,HasCredentials,RiskAlert" > "${CSV_DIR}/DeveloperEcosystem.csv"

# ------------------------------------------------------------------------------
# 1. Node.js & NPM Artifacts
# ------------------------------------------------------------------------------
log_info "Auditing NPM configurations, global packages, and .npmrc tokens..."
mkdir -p "${OUTPUT_DIR}/NPM"

if command -v npm >/dev/null 2>&1; then
    npm list -g --depth=0 > "${OUTPUT_DIR}/NPM/npm_global_packages.txt" 2>&1 || true
fi

for uhome in /root /home/*; do
    [ -d "$uhome" ] || continue
    u_name=$(basename "$uhome")
    npmrc="${uhome}/.npmrc"
    
    if [ -f "$npmrc" ]; then
        cp -p "$npmrc" "${OUTPUT_DIR}/NPM/${u_name}_npmrc" 2>/dev/null || true
        has_token="False"
        grep -q '_authToken' "$npmrc" 2>/dev/null && has_token="True"
        if [ "$has_token" = "True" ]; then
            log_warn "NPM authentication token detected in ${npmrc}!"
            echo "\"NPM\",\"ConfigFile\",\"${npmrc}\",\"True\",\"AUTH_TOKEN_PRESENT\"" >> "${CSV_DIR}/DeveloperEcosystem.csv"
        else
            echo "\"NPM\",\"ConfigFile\",\"${npmrc}\",\"False\",\"StandardConfig\"" >> "${CSV_DIR}/DeveloperEcosystem.csv"
        fi
    fi
done

# ------------------------------------------------------------------------------
# 2. Python & PyPI Artifacts (.pth persistence files)
# ------------------------------------------------------------------------------
log_info "Auditing Python packages and .pth auto-execution persistence files..."
mkdir -p "${OUTPUT_DIR}/Python"

if command -v pip >/dev/null 2>&1; then
    pip list > "${OUTPUT_DIR}/Python/pip_list.txt" 2>&1 || true
elif command -v pip3 >/dev/null 2>&1; then
    pip3 list > "${OUTPUT_DIR}/Python/pip_list.txt" 2>&1 || true
fi

# PyPI config
for uhome in /root /home/*; do
    pypirc="${uhome}/.pypirc"
    if [ -f "$pypirc" ]; then
        cp -p "$pypirc" "${OUTPUT_DIR}/Python/$(basename "$uhome")_pypirc" 2>/dev/null || true
        log_warn "PyPI credentials file (.pypirc) found in ${uhome}!"
        echo "\"Python\",\"CredentialsFile\",\"${pypirc}\",\"True\",\"PYPI_CREDS_STORED\"" >> "${CSV_DIR}/DeveloperEcosystem.csv"
    fi
done

# Search for suspicious .pth files in site-packages (Python persistence vector)
find /usr/lib/python* /usr/local/lib/python* /root/.local/lib/python* /home/*/.local/lib/python* -name "*.pth" -type f 2>/dev/null | while read -r pth; do
    if grep -Eiq '(import|exec|eval|os\.system|subprocess)' "$pth" 2>/dev/null; then
        log_warn "SUSPICIOUS PYTHON .PTH CODE INJECTION: ${pth}"
        echo "\"Python\",\".pth_Persistence\",\"${pth}\",\"False\",\"CODE_EXECUTION_HOOK\"" >> "${CSV_DIR}/DeveloperEcosystem.csv"
        cp -p "$pth" "${OUTPUT_DIR}/Python/suspicious_$(basename "$pth")" 2>/dev/null || true
    fi
done

# ------------------------------------------------------------------------------
# 3. Rust Cargo & Go Binaries
# ------------------------------------------------------------------------------
log_info "Auditing Rust Cargo credentials and Go custom binaries..."
mkdir -p "${OUTPUT_DIR}/Cargo_Go"

for uhome in /root /home/*; do
    cargo_cred="${uhome}/.cargo/credentials.toml"
    [ -f "$cargo_cred" ] && cp -p "$cargo_cred" "${OUTPUT_DIR}/Cargo_Go/$(basename "$uhome")_cargo_credentials.toml" 2>/dev/null || true
    
    if [ -d "${uhome}/go/bin" ]; then
        ls -la "${uhome}/go/bin" > "${OUTPUT_DIR}/Cargo_Go/$(basename "$uhome")_go_bin_listing.txt" 2>&1 || true
    fi
done

# ------------------------------------------------------------------------------
# 4. Git Global Hooks & Credential Stores
# ------------------------------------------------------------------------------
log_info "Auditing Git global configurations, hooks, and stored credentials..."
mkdir -p "${OUTPUT_DIR}/Git"

for uhome in /root /home/*; do
    [ -d "$uhome" ] || continue
    u_name=$(basename "$uhome")
    
    git_cfg="${uhome}/.gitconfig"
    git_creds="${uhome}/.git-credentials"
    
    if [ -f "$git_cfg" ]; then
        cp -p "$git_cfg" "${OUTPUT_DIR}/Git/${u_name}_gitconfig" 2>/dev/null || true
        # Check for global hooks path
        if grep -q 'hooksPath' "$git_cfg" 2>/dev/null; then
            hook_path=$(grep -oP 'hooksPath\s*=\s*\K.*' "$git_cfg")
            log_warn "Custom global Git hooks configured: ${hook_path}"
            echo "\"Git\",\"GlobalHooks\",\"${hook_path}\",\"False\",\"CUSTOM_GLOBAL_HOOKS\"" >> "${CSV_DIR}/DeveloperEcosystem.csv"
        fi
    fi
    
    if [ -f "$git_creds" ]; then
        cp -p "$git_creds" "${OUTPUT_DIR}/Git/${u_name}_git-credentials" 2>/dev/null || true
        log_warn "Plaintext Git credentials file found: ${git_creds}"
        echo "\"Git\",\"CredentialsStore\",\"${git_creds}\",\"True\",\"PLAINTEXT_GIT_CREDENTIALS\"" >> "${CSV_DIR}/DeveloperEcosystem.csv"
    fi
done

log_success "Developer ecosystem and supply chain triage completed."
