#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$ROOT_DIR/data/logs"
LOCK_DIR="$ROOT_DIR/data/locks"
STATE_DIR="$ROOT_DIR/data/automation"
LOG_FILE="$LOG_DIR/nonweb_pipeline.log"
LOCK_FILE="$LOCK_DIR/nonweb_pipeline.lock"
STATE_FILE="$STATE_DIR/nonweb_profile_state.txt"

mkdir -p "$LOG_DIR" "$LOCK_DIR" "$STATE_DIR"

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

set_profile_args() {
  case "$1" in
    high_coverage)
      PROFILE_NAME="high_coverage"
      NEXT_PROFILE="balanced"
      PROFILE_ARGS=(
        --bandwidth 8M
        --passes 3
        --seed 1
        --seed-step 1000
        --zmap-pass-timeout-sec 12000
      )
      ;;
    balanced|*)
      PROFILE_NAME="balanced"
      NEXT_PROFILE="high_coverage"
      PROFILE_ARGS=(
        --bandwidth 10M
        --passes 2
        --seed 1
        --seed-step 1000
      )
      ;;
  esac
}

resolve_run_args() {
  if [[ "${1:-}" != "--auto-alternate-profiles" ]]; then
    RUN_ARGS=("$@")
    return
  fi

  current_profile="high_coverage"
  if [[ -f "$STATE_FILE" ]]; then
    current_profile="$(tr -d '[:space:]' < "$STATE_FILE")"
  fi
  if [[ "$current_profile" != "high_coverage" && "$current_profile" != "balanced" ]]; then
    current_profile="high_coverage"
  fi

  set_profile_args "$current_profile"
  printf '%s\n' "$NEXT_PROFILE" > "$STATE_FILE"
  echo "[$(timestamp)] automation-profile: selected=$PROFILE_NAME next=$NEXT_PROFILE args=${PROFILE_ARGS[*]}" >>"$LOG_FILE"
  RUN_ARGS=("${PROFILE_ARGS[@]}")
}

resolve_run_args "$@"

if command -v flock >/dev/null 2>&1; then
  (
    flock -n 9 || {
      echo "[$(timestamp)] skip: another run is active" >>"$LOG_FILE"
      exit 0
    }
    run_pipeline "${RUN_ARGS[@]}" >>"$LOG_FILE" 2>&1
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
  run_pipeline "${RUN_ARGS[@]}" >>"$LOG_FILE" 2>&1
fi
