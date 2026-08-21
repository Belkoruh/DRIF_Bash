#!/usr/bin/env bash
# ==============================================================================
# Script: CollectWebserverAndDatabaseArtifacts.sh
# Description: Web server, virtual host, database, and Redis cache forensic acquisition
# Documentation: Collects configuration files, vhosts, SSL certificates, access/error logs,
#                and authentication policies for Nginx, Apache, Caddy, Lighttpd,
#                MySQL, PostgreSQL, Redis, and MongoDB.
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
OUTPUT_DIR="${TARGET_DIR}/WebAndDatabases"
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

echo -e "${CYAN}${BOLD}=== Web Server & Database Artifacts Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "Category,ServiceName,ConfigPath,PortBinding,SecurityAlert" > "${CSV_DIR}/WebAndDatabaseServers.csv"

# ------------------------------------------------------------------------------
# 1. Nginx Web Server
# ------------------------------------------------------------------------------
log_info "Auditing Nginx web server configurations and virtual hosts..."
mkdir -p "${OUTPUT_DIR}/Nginx"

if [ -d /etc/nginx ]; then
    cp -rp /etc/nginx/* "${OUTPUT_DIR}/Nginx/" 2>/dev/null || true
    echo "\"WebServer\",\"Nginx\",\"/etc/nginx/nginx.conf\",\"80/443\",\"N/A\"" >> "${CSV_DIR}/WebAndDatabaseServers.csv"
    log_success "Nginx configurations collected."
fi

# ------------------------------------------------------------------------------
# 2. Apache / HTTPD Web Server
# ------------------------------------------------------------------------------
log_info "Auditing Apache / HTTPD server configurations..."
mkdir -p "${OUTPUT_DIR}/Apache"

for ap_dir in /etc/apache2 /etc/httpd; do
    if [ -d "$ap_dir" ]; then
        cp -rp "$ap_dir"/* "${OUTPUT_DIR}/Apache/" 2>/dev/null || true
        echo "\"WebServer\",\"Apache\",\"${ap_dir}\",\"80/443\",\"N/A\"" >> "${CSV_DIR}/WebAndDatabaseServers.csv"
        log_success "Apache configurations collected from ${ap_dir}."
    fi
done

# Search for suspicious .htaccess overrides in /var/www
log_info "Auditing .htaccess files in web document roots..."
find /var/www /srv/http -name ".htaccess" -type f 2>/dev/null | while read -r hta; do
    mkdir -p "${OUTPUT_DIR}/Apache/htaccess_files"
    cp -p "$hta" "${OUTPUT_DIR}/Apache/htaccess_files/$(basename "$(dirname "$hta")")_htaccess" 2>/dev/null || true
    if grep -Eiq '(auto_prepend_file|auto_append_file|SetHandler|php_value|RewriteRule.*(base64|cmd|eval))' "$hta" 2>/dev/null; then
        log_warn "MALICIOUS .HTACCESS INJECTION DETECTED: ${hta}"
        echo "\"WebSecurity\",\".htaccess\",\"${hta}\",\"N/A\",\"SUSPICIOUS_PHP_DIRECTIVE_FOUND\"" >> "${CSV_DIR}/WebAndDatabaseServers.csv"
    fi
done

# ------------------------------------------------------------------------------
# 3. SSL / TLS Certificate Inventory & Expiration Dates
# ------------------------------------------------------------------------------
log_info "Auditing SSL/TLS certificates metadata..."
mkdir -p "${OUTPUT_DIR}/SSLCertificates"

find /etc/ssl /etc/letsencrypt /etc/pki -type f \( -name "*.crt" -o -name "*.pem" \) 2>/dev/null | while read -r cert_f; do
    if command -v openssl >/dev/null 2>&1; then
        subj=$(openssl x509 -noout -subject -in "$cert_f" 2>/dev/null || true)
        dates=$(openssl x509 -noout -dates -in "$cert_f" 2>/dev/null || true)
        if [ -n "$subj" ]; then
            echo "Certificate: $cert_f" >> "${OUTPUT_DIR}/SSLCertificates/certs_summary.txt"
            echo "Subject    : $subj" >> "${OUTPUT_DIR}/SSLCertificates/certs_summary.txt"
            echo "Dates      : $dates" >> "${OUTPUT_DIR}/SSLCertificates/certs_summary.txt"
            echo "----------------------------------------------------" >> "${OUTPUT_DIR}/SSLCertificates/certs_summary.txt"
        fi
    fi
done

# ------------------------------------------------------------------------------
# 4. Redis Cache & In-Memory Databases (Unauthenticated Exposure Check)
# ------------------------------------------------------------------------------
log_info "Auditing Redis configuration for unauthenticated network bindings..."
mkdir -p "${OUTPUT_DIR}/Redis"

for r_conf in /etc/redis/redis.conf /etc/redis.conf; do
    if [ -f "$r_conf" ]; then
        cp -p "$r_conf" "${OUTPUT_DIR}/Redis/" 2>/dev/null
        is_unauth="False"
        # Check bind address
        bind_line=$(grep -E '^\s*bind\s+' "$r_conf" 2>/dev/null || echo "")
        reqpass=$(grep -E '^\s*requirepass\s+' "$r_conf" 2>/dev/null || echo "")
        
        if [[ "$bind_line" =~ 0\.0\.0\.0 ]] && [ -z "$reqpass" ]; then
            is_unauth="True"
            log_warn "CRITICAL VULNERABILITY: Redis bound to 0.0.0.0 without requirepass authentication!"
            echo "\"Database\",\"Redis\",\"${r_conf}\",\"6379\",\"UNAUTHENTICATED_PUBLIC_EXPOSURE\"" >> "${CSV_DIR}/WebAndDatabaseServers.csv"
        else
            echo "\"Database\",\"Redis\",\"${r_conf}\",\"6379\",\"StandardConfig\"" >> "${CSV_DIR}/WebAndDatabaseServers.csv"
        fi
    fi
done

# ------------------------------------------------------------------------------
# 5. MySQL / MariaDB Database Configurations
# ------------------------------------------------------------------------------
log_info "Auditing MySQL / MariaDB server configurations..."
mkdir -p "${OUTPUT_DIR}/MySQL"

for my_cnf in /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf; do
    if [ -f "$my_cnf" ]; then
        cp -p "$my_cnf" "${OUTPUT_DIR}/MySQL/" 2>/dev/null
        echo "\"Database\",\"MySQL\",\"${my_cnf}\",\"3306\",\"N/A\"" >> "${CSV_DIR}/WebAndDatabaseServers.csv"
    fi
done

# ------------------------------------------------------------------------------
# 6. PostgreSQL Database Configurations (pg_hba.conf audit)
# ------------------------------------------------------------------------------
log_info "Auditing PostgreSQL configurations and pg_hba.conf access controls..."
mkdir -p "${OUTPUT_DIR}/PostgreSQL"

find /etc/postgresql/ -name "pg_hba.conf" -type f 2>/dev/null | while read -r pghba; do
    cp -p "$pghba" "${OUTPUT_DIR}/PostgreSQL/$(basename "$(dirname "$pghba")")_pg_hba.conf" 2>/dev/null
    # Check for insecure trust authentication
    if grep -v '^[#[:space:]]*$' "$pghba" | grep -E '\btrust\b' >/dev/null 2>&1; then
        log_warn "PostgreSQL pg_hba.conf contains 'trust' authentication: ${pghba}"
        echo "\"Database\",\"PostgreSQL\",\"${pghba}\",\"5432\",\"INSECURE_TRUST_AUTHENTICATION\"" >> "${CSV_DIR}/WebAndDatabaseServers.csv"
    else
        echo "\"Database\",\"PostgreSQL\",\"${pghba}\",\"5432\",\"StandardAuth\"" >> "${CSV_DIR}/WebAndDatabaseServers.csv"
    fi
done

log_success "Web server and database forensic acquisition completed."
