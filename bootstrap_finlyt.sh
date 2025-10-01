#!/usr/bin/env bash
set -euo pipefail

# bootstrap_finlyt.sh
# Idempotent helper to clone/update the Finlyt Hub toolkit, create venv, install deps,
# run detection (optionally), and launch the interactive orchestrator.

REPO_URL_DEFAULT="https://github.com/vidiva-vidiva/finops_rawdata.git"
REPO_URL="${REPO_URL:-$REPO_URL_DEFAULT}"
TARGET_DIR="${TARGET_DIR:-finlyt-hub}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
JUST_DETECT=0
NO_ORCH=0
FORCE_DETECT=0
# Default to quiet unless user asks for verbose
QUIET=1
VERBOSE=0

usage() {
  cat <<EOF
Usage: bash bootstrap_finlyt.sh [options]

Options:
  --just-detect        Run detection only (01) then exit
  --no-orchestrator    Skip launching orchestrator after detection
  --force-detect       Re-run detection even if split settings already exist
  --quiet              Suppress detailed output (default behavior)
  --verbose            Show detailed progress (inverse of --quiet)
  -h, --help           Show this help

Environment overrides:
  REPO_URL (default: $REPO_URL_DEFAULT)
  TARGET_DIR (default: finlyt-hub)
  PYTHON_BIN (default: python3)
  PIP_INDEX_URL / PIP_EXTRA_INDEX_URL (if you need custom indexes)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
  --just-detect) JUST_DETECT=1; shift ;;
  --no-orchestrator) NO_ORCH=1; shift ;;
  --force-detect) FORCE_DETECT=1; shift ;;
  --quiet) QUIET=1; VERBOSE=0; shift ;;
  --verbose) QUIET=0; VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[Finlyt] Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

info() { if [[ $QUIET -eq 0 ]]; then echo "[Finlyt] $*"; fi }
quiet_run() {
  if [[ $QUIET -eq 1 ]]; then
    "$@" >/dev/null 2>&1 || return $?
  else
    "$@" || return $?
  fi
}

if command -v git >/dev/null 2>&1; then
  if [[ -d "$TARGET_DIR/.git" ]]; then
    info "Updating existing repo in $TARGET_DIR";
    quiet_run git -C "$TARGET_DIR" fetch --quiet || true
    quiet_run git -C "$TARGET_DIR" pull --ff-only || true
  else
    info "Cloning repo into $TARGET_DIR";
    if [[ $QUIET -eq 1 ]]; then
      git clone --quiet "$REPO_URL" "$TARGET_DIR" >/dev/null 2>&1;
    else
      git clone "$REPO_URL" "$TARGET_DIR";
    fi
  fi
else
  info "git not found; attempting archive download (curl)";
  mkdir -p "$TARGET_DIR"
  curl -L "$REPO_URL" >/dev/null 2>&1 || {
    echo "[Finlyt] Unable to download repository without git; install git or manually upload files." >&2
    exit 1
  }
fi

cd "$TARGET_DIR"

if [[ ! -f requirements.txt ]]; then
  echo "[Finlyt] requirements.txt not found in $TARGET_DIR; aborting" >&2
  exit 1
fi

if [[ ! -d .venv ]]; then
  info "Creating virtual environment (.venv)";
  if [[ $QUIET -eq 1 ]]; then
    "$PYTHON_BIN" -m venv .venv >/dev/null 2>&1
  else
    "$PYTHON_BIN" -m venv .venv
  fi
fi
# shellcheck source=/dev/null
source .venv/bin/activate

export FINLYT_QUIET=$QUIET
info "Upgrading pip"
if [[ $QUIET -eq 1 ]]; then
  pip install --disable-pip-version-check --quiet --upgrade pip >/dev/null 2>&1 || true
else
  pip install --upgrade pip >/dev/null
fi

info "Installing dependencies"
if [[ $QUIET -eq 1 ]]; then
  pip install --disable-pip-version-check --quiet -r requirements.txt >/dev/null 2>&1 || true
else
  pip install -r requirements.txt
fi

SET_FILES=(user_settings.json finlyt_settings.json cm_export_settings.json)
MISSING=0
for f in "${SET_FILES[@]}"; do
  [[ -f "$f" ]] || MISSING=1
done

if [[ $FORCE_DETECT -eq 1 || $MISSING -eq 1 ]]; then
  info "Running detection (01_detect_finlythub.py)"
  if [[ $QUIET -eq 1 ]]; then
    python 01_detect_finlythub.py >/dev/null 2>&1 || {
      echo "[Finlyt] Detection failed" >&2
      exit 1
    }
  else
    python 01_detect_finlythub.py || {
    echo "[Finlyt] Detection failed" >&2
    exit 1
    }
  fi
else
  info "Split settings already present; skipping detection (use --force-detect to override)"
fi

if [[ $JUST_DETECT -eq 1 ]]; then
  info "Exiting after detection per --just-detect"
  exit 0
fi

if [[ $NO_ORCH -eq 1 ]]; then
  info "Skipping orchestrator per --no-orchestrator"
  exit 0
fi

if [[ -f 00_setup_finlythub.py ]]; then
  info "Launching orchestrator (00_setup_finlythub.py)"
  if [[ $QUIET -eq 1 ]]; then
    echo "[Finlyt] Ready."  # minimal cue before interactive menu
  fi
  python 00_setup_finlythub.py
else
  echo "[Finlyt] Orchestrator script missing" >&2
fi
