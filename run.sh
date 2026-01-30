#!/usr/bin/env bash
pkill -f uvicorn
pkill -f tail_ingest

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"
echo "📁 Project root: $ROOT_DIR"

# =========================
# LLM / Ledger
# =========================
export DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-sk-98549bf54d0c4c07afbf54310b5120ea}"
export DEEPSEEK_BASE_URL="${DEEPSEEK_BASE_URL:-https://api.deepseek.com/v1}"
export DEEPSEEK_MODEL="${DEEPSEEK_MODEL:-deepseek-chat}"
export LLM_LEDGER_JSONL="${LLM_LEDGER_JSONL:-$ROOT_DIR/data/llm_usage.jsonl}"
mkdir -p "$ROOT_DIR/data"
echo "🧾 LLM_LEDGER_JSONL=$LLM_LEDGER_JSONL"

# =========================
# Ops Copilot API endpoints
# =========================
export OPS_EVENT_API="${OPS_EVENT_API:-http://127.0.0.1:8000/api/ingest/syslog}"
export OPS_EVIDENCE_API="${OPS_EVIDENCE_API:-http://127.0.0.1:8000/api/evidence/ingest}"

# =========================
# Tail ingest config
# =========================
export RSYSLOG_REMOTE_LOG="${RSYSLOG_REMOTE_LOG:-/opt/homebrew/var/log/rsyslog-remote.log}"

# =========================
# Desensitizer config
# =========================
export ENABLE_DESENSITIZE="${ENABLE_DESENSITIZE:-1}"           # 1=enable, 0=disable
export DESENSITIZE_REVERSIBLE="${DESENSITIZE_REVERSIBLE:-0}"   # 1=reversible, 0=irreversible (recommended)
export DESENSITIZE_MAP_PATH="${DESENSITIZE_MAP_PATH:-$ROOT_DIR/data/desensitize_map.json}"
export KEEP_PRIVATE_RANGES="${KEEP_PRIVATE_RANGES:-0}"         # recommend 0

# Ensure a stable secret (otherwise mapping changes after restart)
if [ -z "${OPS_DESENSE_SECRET:-}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    export OPS_DESENSE_SECRET="$(openssl rand -hex 32)"
    echo "🔐 OPS_DESENSE_SECRET not set. Generated a TEMP secret for this run."
  else
    export OPS_DESENSE_SECRET="WEAK_DEFAULT_SECRET_CHANGE_ME_$(date +%s)"
    echo "⚠️  openssl not found. Using a weak TEMP secret. Please set OPS_DESENSE_SECRET manually."
  fi
else
  echo "🔐 OPS_DESENSE_SECRET is set (hidden)."
fi

echo ""
echo "🧩 Tail ingest env:"
echo "   RSYSLOG_REMOTE_LOG=$RSYSLOG_REMOTE_LOG"
echo "   OPS_EVENT_API=$OPS_EVENT_API"
echo "   OPS_EVIDENCE_API=$OPS_EVIDENCE_API"
echo "   ENABLE_DESENSITIZE=$ENABLE_DESENSITIZE"
echo "   DESENSITIZE_REVERSIBLE=$DESENSITIZE_REVERSIBLE"
echo "   DESENSITIZE_MAP_PATH=$DESENSITIZE_MAP_PATH"
echo "   KEEP_PRIVATE_RANGES=$KEEP_PRIVATE_RANGES"
echo ""

# =========================
# Python venv
# =========================
if [ ! -d ".venv" ]; then
  echo "🐍 Creating venv..."
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "📦 Installing requirements..."
pip install -r requirements.txt

# =========================
# Preflight: desensitizer self-test
# =========================
echo "🧪 Preflight: desensitizer self-test..."
python3 - <<'PY'
import os
from tools.desensitizer import Desensitizer, DesensitizeConfig

secret = os.environ.get("OPS_DESENSE_SECRET", "0123456789abcdef0123456789abcdef")
cfg = DesensitizeConfig(
    secret_key=secret,
    reversible=os.environ.get("DESENSITIZE_REVERSIBLE","0") in ("1","true","yes","True"),
    mapping_path=os.environ.get("DESENSITIZE_MAP_PATH","data/_tmp_map.json"),
    keep_private_ranges=os.environ.get("KEEP_PRIVATE_RANGES","0") in ("1","true","yes","True"),
)
des = Desensitizer(cfg)
s="date=2025-12-30 srcip=10.183.17.136 dstip=61.170.80.60 srcport=41200 dstport=80"
out,_ = des.desensitize_line(s+"\n")
print("   input :", s)
print("   output:", out.strip())
assert "10.183.17.136" not in out and "61.170.80.60" not in out, "IP not masked in preflight!"
print("✅ Preflight OK: IP masking works.")
PY
echo ""

# =========================
# Guard: free ports (optional but helpful)
# =========================
kill_port_if_listening () {
  local port="$1"
  local pids
  pids="$(lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    echo "⚠️  Port $port is in use by PID(s): $pids"
    echo "    Killing them to avoid 'Address already in use'..."
    kill -TERM $pids 2>/dev/null || true
    sleep 0.5
  fi
}
# Comment out if you don't want auto-kill:
kill_port_if_listening 8000
kill_port_if_listening 5173

# =========================
# Cleanup: kill the whole process group
# =========================
set -m  # job control, so kill 0 kills children of this script

cleanup() {
  echo ""
  echo "🧹 Stopping services..."
  # Kill the whole process group: includes uvicorn --reload worker/reloader
  kill 0 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# =========================
# Start services
# =========================
echo "🚀 Starting API..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
API_PID=$!
echo "✅ API PID: $API_PID"

echo "🔥 Starting syslog tail ingest..."
python3 -m tools.tail_ingest &
INGEST_PID=$!
echo "✅ INGEST PID: $INGEST_PID"

echo "🌐 Starting web server..."
python3 -m http.server 5173 --directory web &
WEB_PID=$!
echo "✅ WEB PID: $WEB_PID"

echo ""
echo "🎯 All services started"
echo "   API: http://127.0.0.1:8000"
echo "   Web: http://127.0.0.1:5173"
echo "   Log: $RSYSLOG_REMOTE_LOG"
echo ""
echo "📝 Note: If UI still shows clear IPs, you may be viewing OLD records. Wait for NEW logs or clear evidence/event storage."
echo ""

wait
