#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# FedRAMP-Auto: Ollama + Mistral 7B setup script
# Supports: macOS (Apple Silicon & Intel), Linux (x86_64 & arm64)
# Usage:  chmod +x setup_ollama.sh && ./setup_ollama.sh
# ──────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[x]${NC} $*"; exit 1; }

# ── 1. Detect OS ──────────────────────────────────────────────
info "Detecting OS..."
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin) PLATFORM="macOS ($ARCH)" ;;
  Linux)  PLATFORM="Linux ($ARCH)" ;;
  *)      error "Unsupported OS: $OS. This script supports macOS and Linux only." ;;
esac
info "Platform: $PLATFORM"

# ── 2. Install Ollama ─────────────────────────────────────────
info "Checking for Ollama..."

if command -v ollama &>/dev/null; then
  OLLAMA_VERSION="$(ollama --version 2>/dev/null | head -1)"
  warn "Ollama already installed: $OLLAMA_VERSION — skipping install."
else
  info "Installing Ollama..."

  if [[ "$OS" == "Darwin" ]]; then
    # macOS: prefer Homebrew, fall back to official installer
    if command -v brew &>/dev/null; then
      info "Installing via Homebrew..."
      brew install ollama
    else
      info "Homebrew not found. Downloading official macOS app..."
      TMP_DIR="$(mktemp -d)"
      curl -fsSL "https://ollama.com/download/Ollama-darwin.zip" -o "$TMP_DIR/ollama.zip"
      unzip -q "$TMP_DIR/ollama.zip" -d "$TMP_DIR"
      # Move CLI binary to /usr/local/bin so it's on PATH
      if [[ -f "$TMP_DIR/Ollama.app/Contents/Resources/ollama" ]]; then
        sudo cp "$TMP_DIR/Ollama.app/Contents/Resources/ollama" /usr/local/bin/ollama
        sudo chmod +x /usr/local/bin/ollama
      else
        warn "Could not find CLI binary in app bundle."
        warn "Please install Ollama manually from https://ollama.com/download"
        exit 1
      fi
      rm -rf "$TMP_DIR"
    fi

  elif [[ "$OS" == "Linux" ]]; then
    # Linux: official install script (handles x86_64 + arm64)
    if ! command -v curl &>/dev/null; then
      error "curl is required. Install it with: sudo apt install curl  OR  sudo yum install curl"
    fi
    info "Running official Linux installer (requires sudo)..."
    curl -fsSL https://ollama.com/install.sh | sh
  fi

  # Verify install succeeded
  if ! command -v ollama &>/dev/null; then
    error "Ollama installation failed. Visit https://ollama.com/download for manual instructions."
  fi
  info "Ollama installed: $(ollama --version 2>/dev/null | head -1)"
fi

# ── 3. Start Ollama server (background) ───────────────────────
info "Starting Ollama server..."

if pgrep -x "ollama" &>/dev/null; then
  warn "Ollama server already running — skipping."
else
  if [[ "$OS" == "Darwin" ]]; then
    # On macOS, 'ollama serve' is the correct command
    ollama serve &>/tmp/ollama_serve.log &
  else
    # On Linux, try systemd first, fall back to manual
    if command -v systemctl &>/dev/null && systemctl is-active --quiet ollama 2>/dev/null; then
      warn "Ollama systemd service already active."
    elif command -v systemctl &>/dev/null; then
      sudo systemctl enable --now ollama 2>/dev/null || {
        warn "systemctl failed, starting manually..."
        ollama serve &>/tmp/ollama_serve.log &
      }
    else
      ollama serve &>/tmp/ollama_serve.log &
    fi
  fi

  # Wait for the server to be ready (up to 30 seconds)
  info "Waiting for Ollama API to be ready..."
  TRIES=0
  until curl -sf http://localhost:11434/ &>/dev/null; do
    sleep 1
    TRIES=$((TRIES + 1))
    if [[ $TRIES -ge 30 ]]; then
      error "Ollama server did not start within 30 seconds. Check /tmp/ollama_serve.log"
    fi
  done
  info "Ollama API is ready on http://localhost:11434"
fi

# ── 4. Pull Mistral 7B ────────────────────────────────────────
MODEL="mistral"
info "Pulling $MODEL (~4.1 GB — this may take a few minutes)..."

if ollama list 2>/dev/null | grep -q "^mistral"; then
  warn "Mistral 7B already downloaded — skipping pull."
else
  ollama pull "$MODEL"
fi

info "Model ready: $(ollama list | grep mistral | awk '{print $1, $3, $4}')"

# ── 5. Smoke test ─────────────────────────────────────────────
info "Running verification prompt..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Prompt: 'In one sentence, what is NIST 800-53 AC-2?'"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

RESPONSE="$(ollama run "$MODEL" 'In one sentence, what is NIST 800-53 AC-2?' 2>/dev/null)"
echo "$RESPONSE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 6. FedRAMP-specific test ──────────────────────────────────
info "Running FedRAMP control mapping test..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Prompt: Terraform aws_s3_bucket → which NIST controls?"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

FEDRAMP_PROMPT='A Terraform aws_s3_bucket resource has: server_side_encryption enabled (AES-256), versioning enabled, public access blocked, and access logging enabled. List the NIST 800-53 Rev5 controls this configuration satisfies. Respond only with a JSON array where each item has "control_id" and "rationale" fields.'

FEDRAMP_RESPONSE="$(ollama run "$MODEL" "$FEDRAMP_PROMPT" 2>/dev/null)"
echo "$FEDRAMP_RESPONSE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 7. Summary ────────────────────────────────────────────────
echo ""
info "Setup complete. Summary:"
echo ""
echo "  Ollama version : $(ollama --version 2>/dev/null | head -1)"
echo "  Model          : $(ollama list | grep mistral | awk '{print $1}')"
echo "  API endpoint   : http://localhost:11434"
echo "  Run a prompt   : ollama run mistral 'your prompt here'"
echo "  Python usage   : pip install ollama"
echo "                   then: import ollama; ollama.chat(model='mistral', ...)"
echo ""
info "Next step: run the project scaffold script."
echo ""
