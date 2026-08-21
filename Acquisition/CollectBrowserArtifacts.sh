#!/usr/bin/env bash
# ==============================================================================
# Script: CollectBrowserArtifacts.sh
# Description: Web browser forensic artifact acquisition for Linux
# Documentation: Collects SQLite history databases, downloads, extensions,
#                cookies, preferences, and session data for Chrome, Chromium,
#                Firefox, Brave, Edge, Opera, Vivaldi, and Tor Browser across all profiles.
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
OUTPUT_DIR="${TARGET_DIR}/Browsers"
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

echo -e "${CYAN}${BOLD}=== Web Browser Artifacts Acquisition Module (Linux) ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "User,Browser,Profile,URL,Title,VisitCount,LastVisitTime" > "${CSV_DIR}/BrowserHistory.csv"
echo "User,Browser,Profile,TargetFile,SourceURL,DownloadPath,ReceivedBytes,TotalBytes" > "${CSV_DIR}/BrowserDownloads.csv"
echo "User,Browser,Profile,ExtensionID,Name,Version,SourcePath" > "${CSV_DIR}/BrowserExtensions.csv"

# ------------------------------------------------------------------------------
# Process Chromium-based browsers
# (Google Chrome, Chromium, Brave, Microsoft Edge, Opera, Vivaldi)
# ------------------------------------------------------------------------------
process_chromium() {
    local u_name="$1"
    local browser_label="$2"
    local base_path="$3"
    
    [ -d "$base_path" ] || return 0
    log_info "Browser [${browser_label}] detected for user [${u_name}]..."
    
    # Iterate through profiles (Default, Profile 1, Profile 2...)
    for pdir in "$base_path"/Default "$base_path"/Profile\ * "$base_path"; do
        [ -d "$pdir" ] || continue
        # Verify it contains actual browser artifacts
        [ -f "$pdir/History" ] || [ -f "$pdir/Preferences" ] || [ -d "$pdir/Extensions" ] || continue
        
        prof_name=$(basename "$pdir")
        [ "$prof_name" = "$(basename "$base_path")" ] && prof_name="RootProfile"
        
        dest_prof="${OUTPUT_DIR}/${u_name}/${browser_label}/${prof_name}"
        mkdir -p "$dest_prof"
        
        # Copy core artifact files
        for art in History "Login Data" Cookies Bookmarks Preferences "Web Data" "Shortcuts" "Network Action Predictor"; do
            [ -f "${pdir}/${art}" ] && cp -p "${pdir}/${art}" "${dest_prof}/" 2>/dev/null || true
        done
        
        # Extensions
        if [ -d "${pdir}/Extensions" ]; then
            mkdir -p "${dest_prof}/Extensions"
            cp -rp "${pdir}/Extensions"/* "${dest_prof}/Extensions/" 2>/dev/null || true
            
            for ext_id_dir in "${pdir}/Extensions"/*; do
                [ -d "$ext_id_dir" ] || continue
                ext_id=$(basename "$ext_id_dir")
                echo "\"${u_name}\",\"${browser_label}\",\"${prof_name}\",\"${ext_id}\",\"Unknown\",\"N/A\",\"${ext_id_dir}\"" >> "${CSV_DIR}/BrowserExtensions.csv"
            done
        fi
        
        # SQLite extraction if sqlite3 utility is available
        if command -v sqlite3 >/dev/null 2>&1 && [ -f "${dest_prof}/History" ]; then
            # History URLs
            sqlite3 -separator ',' "${dest_prof}/History" "SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 1000;" 2>/dev/null | while IFS=, read -r url title vcount ltime; do
                [ -n "$url" ] || continue
                clean_url=$(echo "$url" | sed 's/"/\\"/g')
                clean_title=$(echo "$title" | sed 's/"/\\"/g')
                echo "\"${u_name}\",\"${browser_label}\",\"${prof_name}\",\"${clean_url}\",\"${clean_title}\",\"${vcount}\",\"${ltime}\"" >> "${CSV_DIR}/BrowserHistory.csv"
            done || true
            
            # Downloads
            sqlite3 -separator ',' "${dest_prof}/History" "SELECT target_path, current_path, received_bytes, total_bytes FROM downloads ORDER BY start_time DESC LIMIT 500;" 2>/dev/null | while IFS=, read -r tpath cpath rbytes tbytes; do
                [ -n "$tpath" ] || continue
                clean_tpath=$(echo "$tpath" | sed 's/"/\\"/g')
                echo "\"${u_name}\",\"${browser_label}\",\"${prof_name}\",\"${clean_tpath}\",\"N/A\",\"${clean_tpath}\",\"${rbytes}\",\"${tbytes}\"" >> "${CSV_DIR}/BrowserDownloads.csv"
            done || true
        fi
    done
}

# ------------------------------------------------------------------------------
# Process Mozilla Firefox & Geckodriver-based browsers
# ------------------------------------------------------------------------------
process_firefox() {
    local u_name="$1"
    local base_path="$2"
    
    [ -d "$base_path" ] || return 0
    log_info "Browser [Firefox] detected for user [${u_name}]..."
    
    for prof_dir in "$base_path"/*.default* "$base_path"/*.[dD]efault*; do
        [ -d "$prof_dir" ] || continue
        prof_name=$(basename "$prof_dir")
        dest_prof="${OUTPUT_DIR}/${u_name}/Firefox/${prof_name}"
        mkdir -p "$dest_prof"
        
        # Copy SQLite databases and JSON configuration files
        for art in places.sqlite cookies.sqlite formhistory.sqlite logins.json key4.db cert9.db permissions.sqlite extensions.json prefs.js sessionstore.jsonlz4; do
            [ -f "${prof_dir}/${art}" ] && cp -p "${prof_dir}/${art}" "${dest_prof}/" 2>/dev/null || true
        done
        
        # Extensions
        if [ -d "${prof_dir}/extensions" ]; then
            mkdir -p "${dest_prof}/extensions"
            cp -rp "${prof_dir}/extensions"/* "${dest_prof}/extensions/" 2>/dev/null || true
        fi
        
        # SQLite extraction
        if command -v sqlite3 >/dev/null 2>&1 && [ -f "${dest_prof}/places.sqlite" ]; then
            # History URLs
            sqlite3 -separator ',' "${dest_prof}/places.sqlite" "SELECT url, title, visit_count, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 1000;" 2>/dev/null | while IFS=, read -r url title vcount ltime; do
                [ -n "$url" ] || continue
                clean_url=$(echo "$url" | sed 's/"/\\"/g')
                clean_title=$(echo "$title" | sed 's/"/\\"/g')
                echo "\"${u_name}\",\"Firefox\",\"${prof_name}\",\"${clean_url}\",\"${clean_title}\",\"${vcount}\",\"${ltime}\"" >> "${CSV_DIR}/BrowserHistory.csv"
            done || true
            
            # Downloads
            sqlite3 -separator ',' "${dest_prof}/places.sqlite" "SELECT content, datetime(dateAdded/1000000,'unixepoch') FROM moz_annos WHERE anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileURI') LIMIT 500;" 2>/dev/null | while IFS=, read -r dl_uri dl_time; do
                [ -n "$dl_uri" ] || continue
                clean_uri=$(echo "$dl_uri" | sed 's/"/\\"/g')
                echo "\"${u_name}\",\"Firefox\",\"${prof_name}\",\"${clean_uri}\",\"N/A\",\"${clean_uri}\",\"0\",\"0\"" >> "${CSV_DIR}/BrowserDownloads.csv"
            done || true
        fi
    done
}

# ------------------------------------------------------------------------------
# Iterate through all user profiles
# ------------------------------------------------------------------------------
for uhome in /root /home/*; do
    [ -d "$uhome" ] || continue
    u_name=$(basename "$uhome")
    
    # Chromium / Chrome / Brave / Edge / Opera / Vivaldi
    process_chromium "$u_name" "Google_Chrome" "${uhome}/.config/google-chrome"
    process_chromium "$u_name" "Chromium" "${uhome}/.config/chromium"
    process_chromium "$u_name" "Brave" "${uhome}/.config/BraveSoftware/Brave-Browser"
    process_chromium "$u_name" "Microsoft_Edge" "${uhome}/.config/microsoft-edge"
    process_chromium "$u_name" "Opera" "${uhome}/.config/opera"
    process_chromium "$u_name" "Vivaldi" "${uhome}/.config/vivaldi"
    
    # Firefox
    process_firefox "$u_name" "${uhome}/.mozilla/firefox"
    
    # Tor Browser
    process_firefox "$u_name" "${uhome}/.local/share/torbrowser/tbb/x86_64/tor-browser/Browser/TorBrowser/Data/Browser"
done

log_success "Web browser triage completed successfully."
