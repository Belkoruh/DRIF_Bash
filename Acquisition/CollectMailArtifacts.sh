#!/usr/bin/env bash
# ==============================================================================
# Script: CollectMailArtifacts.sh
# Description: Mail server, MTA queues, Postfix, Exim, and local mailbox forensics
# Documentation: Collects mail transport configurations, outbound/inbound mail queues (mailq),
#                spool directories (/var/spool/mail), and aliases (/etc/aliases) to identify
#                email exfiltration, internal phishing campaigns, and alias hijacking.
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
OUTPUT_DIR="${TARGET_DIR}/MailArtifacts"
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

echo -e "${CYAN}${BOLD}=== Mail Server & MTA Queues Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "MTA,QueueSize,ConfigPath,SecurityAlert" > "${CSV_DIR}/MailArtifacts.csv"

# ------------------------------------------------------------------------------
# 1. Postfix Mail Server
# ------------------------------------------------------------------------------
log_info "Auditing Postfix configuration and mail queues..."
mkdir -p "${OUTPUT_DIR}/Postfix"

if [ -d /etc/postfix ]; then
    cp -rp /etc/postfix/* "${OUTPUT_DIR}/Postfix/" 2>/dev/null || true
    echo "\"Postfix\",\"N/A\",\"/etc/postfix/main.cf\",\"N/A\"" >> "${CSV_DIR}/MailArtifacts.csv"
fi

# ------------------------------------------------------------------------------
# 2. Exim & Sendmail
# ------------------------------------------------------------------------------
log_info "Auditing Exim and Sendmail configurations..."
mkdir -p "${OUTPUT_DIR}/Exim_Sendmail"

[ -d /etc/exim4 ] && cp -rp /etc/exim4 "${OUTPUT_DIR}/Exim_Sendmail/" 2>/dev/null || true
[ -d /etc/mail ] && cp -rp /etc/mail "${OUTPUT_DIR}/Exim_Sendmail/" 2>/dev/null || true

# ------------------------------------------------------------------------------
# 3. Mail Queues & Spool Directories (mailq / postqueue)
# ------------------------------------------------------------------------------
log_info "Checking active mail queues (mailq)..."
mkdir -p "${OUTPUT_DIR}/Queues"

if command -v mailq >/dev/null 2>&1; then
    mailq > "${OUTPUT_DIR}/Queues/mailq_output.txt" 2>&1 || true
    q_lines=$(wc -l < "${OUTPUT_DIR}/Queues/mailq_output.txt" 2>/dev/null || echo "0")
    if [ "$q_lines" -gt 1 ]; then
        log_warn "Active messages detected in mail queue (${q_lines} lines)!"
    fi
elif command -v postqueue >/dev/null 2>&1; then
    postqueue -p > "${OUTPUT_DIR}/Queues/postqueue_output.txt" 2>&1 || true
fi

# ------------------------------------------------------------------------------
# 4. Mail Aliases (/etc/aliases)
# ------------------------------------------------------------------------------
log_info "Auditing mail aliases for pipe command executions..."
mkdir -p "${OUTPUT_DIR}/Aliases"

for alias_f in /etc/aliases /etc/mail/aliases /etc/postfix/aliases; do
    if [ -f "$alias_f" ]; then
        cp -p "$alias_f" "${OUTPUT_DIR}/Aliases/$(basename "$(dirname "$alias_f")")_aliases" 2>/dev/null || true
        # Check for pipe to external script/binary in aliases
        if grep -E '^\s*[^#]+:\s*\|' "$alias_f" >/dev/null 2>&1; then
            log_warn "SUSPICIOUS PIPE COMMAND EXECUTION IN ALIASES: ${alias_f}"
            grep -E '^\s*[^#]+:\s*\|' "$alias_f" | while read -r p_rule; do
                clean_prule=$(echo "$p_rule" | sed 's/"/\\"/g')
                echo "\"MailAliases\",\"N/A\",\"${alias_f}\",\"PIPE_COMMAND_EXEC: ${clean_prule}\"" >> "${CSV_DIR}/MailArtifacts.csv"
            done
        fi
    fi
done

# ------------------------------------------------------------------------------
# 5. Local Mailbox Inventories (/var/mail, /var/spool/mail)
# ------------------------------------------------------------------------------
log_info "Auditing local user mailbox file sizes..."
for mbox_dir in /var/mail /var/spool/mail; do
    if [ -d "$mbox_dir" ]; then
        ls -la "$mbox_dir" > "${OUTPUT_DIR}/Queues/$(basename "$mbox_dir")_listing.txt" 2>&1 || true
    fi
done

log_success "Mail server and MTA queue acquisition completed."
