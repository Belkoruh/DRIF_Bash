#!/usr/bin/env bash
# ==============================================================================
# Script: CollectAIArtifacts.sh
# Description: Artificial Intelligence (AI) and LLM forensic artifact acquisition for Linux
# Documentation: Collects configuration files, prompt histories, local model manifests,
#                MCP (Model Context Protocol) configs, tokens, and caches for Ollama,
#                Claude, Cursor IDE, Windsurf, Copilot, LM Studio, HuggingFace, Aider, and Gemini.
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
OUTPUT_DIR="${TARGET_DIR}/AI_Artifacts"
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

echo -e "${CYAN}${BOLD}=== AI & LLM Forensic Artifacts Acquisition Module ===${NC}"
echo -e "${BLUE}Output Directory: ${OUTPUT_DIR}${NC}\n"

echo "User,ToolName,Category,Path,ConfigFound" > "${CSV_DIR}/AIToolsDetected.csv"
echo "User,ToolName,SourceFile,FileSize,LineCount" > "${CSV_DIR}/AIPromptHistories.csv"
echo "User,TokenKeyName,MaskedValue,SourceLocation" > "${CSV_DIR}/AITokenPresence.csv"

# ------------------------------------------------------------------------------
# 1. System-wide Audit for Local LLM Servers (Ollama, LocalAI, vLLM)
# ------------------------------------------------------------------------------
log_info "Searching for local LLM inference servers (Ollama, LocalAI, vLLM)..."
mkdir -p "${OUTPUT_DIR}/System_AI"

# Ollama system service
if systemctl is-active ollama >/dev/null 2>&1; then
    log_warn "Ollama service is active on host!"
    systemctl status ollama > "${OUTPUT_DIR}/System_AI/ollama_service_status.txt" 2>&1 || true
    echo "\"System\",\"Ollama_Service\",\"Local_LLM_Server\",\"/etc/systemd/system/ollama.service\",\"True\"" >> "${CSV_DIR}/AIToolsDetected.csv"
fi

if command -v ollama >/dev/null 2>&1; then
    ollama list > "${OUTPUT_DIR}/System_AI/ollama_models_list.txt" 2>&1 || true
    ollama ps > "${OUTPUT_DIR}/System_AI/ollama_running_models.txt" 2>&1 || true
fi

# ------------------------------------------------------------------------------
# 2. Iterate User Profiles for AI Tooling Artifacts
# ------------------------------------------------------------------------------
for uhome in /root /home/*; do
    [ -d "$uhome" ] || continue
    u_name=$(basename "$uhome")
    dest_u="${OUTPUT_DIR}/Users/${u_name}"
    
    # 2.1 Ollama (User models and configs)
    if [ -d "${uhome}/.ollama" ]; then
        mkdir -p "${dest_u}/Ollama"
        log_info "Ollama artifacts found for user [${u_name}]"
        [ -f "${uhome}/.ollama/history" ] && cp -p "${uhome}/.ollama/history" "${dest_u}/Ollama/" 2>/dev/null
        [ -d "${uhome}/.ollama/models/manifests" ] && cp -rp "${uhome}/.ollama/models/manifests" "${dest_u}/Ollama/" 2>/dev/null
        echo "\"${u_name}\",\"Ollama\",\"Local_LLM\",\"${uhome}/.ollama\",\"True\"" >> "${CSV_DIR}/AIToolsDetected.csv"
    fi
    
    # 2.2 Claude Desktop & Claude Code
    for claude_dir in "${uhome}/.claude" "${uhome}/.anthropic" "${uhome}/.config/claude" "${uhome}/.config/Claude"; do
        if [ -d "$claude_dir" ]; then
            mkdir -p "${dest_u}/Claude"
            log_info "Claude artifacts found for [${u_name}] in ${claude_dir}"
            cp -rp "$claude_dir"/* "${dest_u}/Claude/" 2>/dev/null || true
            echo "\"${u_name}\",\"Claude\",\"Agent_LLM\",\"${claude_dir}\",\"True\"" >> "${CSV_DIR}/AIToolsDetected.csv"
        fi
    done
    [ -f "${uhome}/.claude.json" ] && cp -p "${uhome}/.claude.json" "${dest_u}/Claude/" 2>/dev/null || true
    
    # 2.3 Cursor IDE & Windsurf (AI-Assisted IDEs)
    for ide_dir in "${uhome}/.cursor" "${uhome}/.config/Cursor" "${uhome}/.codeium/windsurf" "${uhome}/.config/Windsurf"; do
        if [ -d "$ide_dir" ]; then
            ide_name=$(basename "$ide_dir")
            mkdir -p "${dest_u}/${ide_name}"
            log_info "AI IDE artifacts [${ide_name}] found for [${u_name}]"
            # Save configuration files and SQLite state databases
            find "$ide_dir" -maxdepth 3 -type f \( -name "*.json" -o -name "*.vscdb" -o -name "state.vscdb*" \) -exec cp -p {} "${dest_u}/${ide_name}/" \; 2>/dev/null || true
            echo "\"${u_name}\",\"${ide_name}\",\"AI_IDE\",\"${ide_dir}\",\"True\"" >> "${CSV_DIR}/AIToolsDetected.csv"
        fi
    done
    
    # 2.4 GitHub Copilot
    if [ -d "${uhome}/.config/github-copilot" ]; then
        mkdir -p "${dest_u}/GitHub_Copilot"
        log_info "GitHub Copilot artifacts found for [${u_name}]"
        cp -rp "${uhome}/.config/github-copilot"/* "${dest_u}/GitHub_Copilot/" 2>/dev/null || true
        echo "\"${u_name}\",\"GitHub_Copilot\",\"Code_Assistant\",\"${uhome}/.config/github-copilot\",\"True\"" >> "${CSV_DIR}/AIToolsDetected.csv"
    fi
    
    # 2.5 Hugging Face Cache & Token
    if [ -d "${uhome}/.cache/huggingface" ] || [ -d "${uhome}/.huggingface" ]; then
        mkdir -p "${dest_u}/HuggingFace"
        [ -f "${uhome}/.huggingface/token" ] && cp -p "${uhome}/.huggingface/token" "${dest_u}/HuggingFace/token.txt" 2>/dev/null
        [ -d "${uhome}/.cache/huggingface/hub" ] && ls -la "${uhome}/.cache/huggingface/hub" > "${dest_u}/HuggingFace/cached_models.txt" 2>&1 || true
        echo "\"${u_name}\",\"HuggingFace\",\"Model_Hub\",\"${uhome}/.cache/huggingface\",\"True\"" >> "${CSV_DIR}/AIToolsDetected.csv"
    fi
    
    # 2.6 Aider & Continue.dev
    if [ -d "${uhome}/.continue" ]; then
        mkdir -p "${dest_u}/Continue_dev"
        cp -rp "${uhome}/.continue"/* "${dest_u}/Continue_dev/" 2>/dev/null || true
        echo "\"${u_name}\",\"Continue_dev\",\"Code_Assistant\",\"${uhome}/.continue\",\"True\"" >> "${CSV_DIR}/AIToolsDetected.csv"
    fi
    
    # Aider chat history
    for aider_f in "${uhome}/.aider.conf.yml" "${uhome}/.aider.chat.history.md"; do
        if [ -f "$aider_f" ]; then
            mkdir -p "${dest_u}/Aider"
            cp -p "$aider_f" "${dest_u}/Aider/" 2>/dev/null
            f_size=$(stat -c "%s" "$aider_f" 2>/dev/null || echo "0")
            f_lines=$(wc -l < "$aider_f" 2>/dev/null || echo "0")
            echo "\"${u_name}\",\"Aider\",\"${aider_f}\",\"${f_size}\",\"${f_lines}\"" >> "${CSV_DIR}/AIPromptHistories.csv"
        fi
    done
    
    # 2.7 Antigravity / Gemini CLI
    if [ -d "${uhome}/.gemini" ]; then
        mkdir -p "${dest_u}/Antigravity_Gemini"
        cp -rp "${uhome}/.gemini"/* "${dest_u}/Antigravity_Gemini/" 2>/dev/null || true
        echo "\"${u_name}\",\"Antigravity_Gemini\",\"AI_Agent\",\"${uhome}/.gemini\",\"True\"" >> "${CSV_DIR}/AIToolsDetected.csv"
    fi
    
    # --------------------------------------------------------------------------
    # 3. Detect AI API Keys and Tokens in User Configurations
    # --------------------------------------------------------------------------
    token_keys="OPENAI_API_KEY ANTHROPIC_API_KEY GEMINI_API_KEY GROQ_API_KEY COHERE_API_KEY HF_TOKEN MISTRAL_API_KEY DEEPSEEK_API_KEY REPLICATE_API_TOKEN"
    for tk in $token_keys; do
        # Search in .bashrc, .profile, .zshrc, .env
        for cfg in "${uhome}/.bashrc" "${uhome}/.profile" "${uhome}/.zshrc" "${uhome}/.env"; do
            [ -f "$cfg" ] || continue
            if grep -q "$tk" "$cfg" 2>/dev/null; then
                raw_val=$(grep -oP "${tk}=\K[^\s\n\r'\"]+" "$cfg" 2>/dev/null | head -n 1 || echo "")
                if [ -n "$raw_val" ]; then
                    masked="${raw_val:0:4}...${raw_val: -4}"
                    echo "\"${u_name}\",\"${tk}\",\"${masked}\",\"${cfg}\"" >> "${CSV_DIR}/AITokenPresence.csv"
                    log_warn "API Key [${tk}] detected in ${cfg} for user [${u_name}]"
                fi
            fi
        done
    done
done

log_success "AI artifacts triage completed successfully."
