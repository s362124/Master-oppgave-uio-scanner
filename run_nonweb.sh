#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$ROOT_DIR/data/logs"
LOCK_DIR="$ROOT_DIR/data/locks"
LOG_FILE="$LOG_DIR/nonweb_pipeline.log"
LOCK_FILE="$LOCK_DIR/nonweb_pipeline.lock"

mkdir -p "$LOG_DIR" "$LOCK_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

run_pipeline() {
  echo "[$(timestamp)] start: run_nonweb.sh $*"
  "$PYTHON_BIN" "$ROOT_DIR/zmap_scan_all.py" --full-pipeline "$@"
  rc=$?
  echo "[$(timestamp)] done: rc=$rc"
  return "$rc"
}

if command -v flock >/dev/null 2>&1; then
  (
    flock -n 9 || {
      echo "[$(timestamp)] skip: another run is active" >>"$LOG_FILE"
      exit 0
    }
    run_pipeline "$@" >>"$LOG_FILE" 2>&1
  ) 9>"$LOCK_FILE"
else
  # Fallback lock strategy if flock is unavailable.
  LOCK_FALLBACK_DIR="${LOCK_FILE}.d"
  if ! mkdir "$LOCK_FALLBACK_DIR" 2>/dev/null; then
    echo "[$(timestamp)] skip: another run is active (fallback lock)" >>"$LOG_FILE"
    exit 0
  fi
  cleanup() {
    rmdir "$LOCK_FALLBACK_DIR" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT
  run_pipeline "$@" >>"$LOG_FILE" 2>&1
fi

