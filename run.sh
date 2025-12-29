#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"
echo "📁 Project root: $ROOT_DIR"

# =========================
# LLM / Ledger (你的原配置)
# =========================
export DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-sk-xxxxxxxxxxxxxxxxxxxxx}"
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
# 你真正要 tail 的 rsyslog 文件（默认保持你现在的路径）
export RSYSLOG_REMOTE_LOG="${RSYSLOG_REMOTE_LOG:-/opt/homebrew/var/log/rsyslog-remote.log}"

# 如果你想临时测试某个文件，取消下面这行注释并写你的路径：
# export RSYSLOG_REMOTE_LOG="/Users/hongyi.ou01/Downloads/ForwardTrafficLog-memory-2025-12-24T19_18_49.841176.log"

# =========================
# Desensitizer (脱敏中间件)
# =========================
export ENABLE_DESENSITIZE="${ENABLE_DESENSITIZE:-1}"           # 1=启用 0=禁用
export DESENSITIZE_REVERSIBLE="${DESENSITIZE_REVERSIBLE:-0}"   # 1=可逆(慎用) 0=不可逆(推荐)
export DESENSITIZE_MAP_PATH="${DESENSITIZE_MAP_PATH:-$ROOT_DIR/data/desensitize_map.json}"

# 强烈建议你自己在 shell 里设置 OPS_DESENSE_SECRET
# 如果没设置，这里会自动生成一个临时 secret（仅本次运行稳定，重启会变）
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

# 可选：不建议保留私网IP原样；默认 0
export KEEP_PRIVATE_RANGES="${KEEP_PRIVATE_RANGES:-0}"

echo ""
echo "🧩 Tail ingest env:"
echo "   RSYSLOG_REMOTE_LOG=$RSYSLOG_REMOTE_LOG"
echo "   OPS_EVENT_API=$OPS_EVENT_API"
echo "   OPS_EVIDENCE_API=$OPS_EVIDENCE_API"
echo "   ENABLE_DESENSITIZE=$ENABLE_DESENSITIZE"
echo "   DESENSITIZE_REVERSIBLE=$DESENSITIZE_REVERSIBLE"
echo "   DESENSITIZE_MAP_PATH=$DESENSITIZE_MAP_PATH"
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
# Start services
# =========================

echo "🚀 Starting API..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
API_PID=$!
echo "✅ API PID: $API_PID"

echo "🔥 Starting syslog tail ingest..."
python3 tools/tail_ingest.py &
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

# =========================
# Cleanup
# =========================
cleanup() {
  echo ""
  echo "🧹 Stopping services..."
  kill "$WEB_PID" "$INGEST_PID" "$API_PID" 2>/dev/null || true
}
trap cleanup EXIT

wait
