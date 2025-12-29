#!/usr/bin/env bash

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

export DEEPSEEK_API_KEY="sk-xxxxxxxxxxx"
export DEEPSEEK_BASE_URL="https://api.deepseek.com/v1"
export DEEPSEEK_MODEL="deepseek-chat"
export LLM_LEDGER_JSONL="$ROOT_DIR/data/llm_usage.jsonl"
echo "🧾 LLM_LEDGER_JSONL=$LLM_LEDGER_JSONL"
set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"
echo "📁 Project root: $ROOT_DIR"

# 1. 创建 venv（仅第一次）
if [ ! -d ".venv" ]; then
  echo "🐍 Creating venv..."
  python3 -m venv .venv
fi

# 2. 激活 venv
source .venv/bin/activate

# 3. 安装依赖（开发态可以每次装）
echo "📦 Installing requirements..."
pip install -r requirements.txt

# 4. 启动 API（后台）
echo "🚀 Starting API..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
API_PID=$!
echo "✅ API PID: $API_PID"

# 5. 启动 syslog tail ingest（后台）
echo "🔥 Starting syslog tail ingest..."
#export LOG_FILE="/Users/hongyi.ou01/Downloads/ForwardTrafficLog-memory-2025-12-24T19_18_49.841176.log"
python3 tools/tail_ingest.py &
INGEST_PID=$!
echo "✅ INGEST PID: $INGEST_PID"

echo ""
echo "🎯 All services started"
echo "   API:     http://127.0.0.1:8000"
echo "   LOGFILE: $LOG_FILE"
echo ""


# 6. 前端页面打开
python3 -m http.server 5173 --directory web &
INGEST_PID=$!
echo "✅ INGEST PID: $INGEST_PID"
echo "   web:     http://127.0.0.1:5173"
# 7. 退出时清理
cleanup() {
  echo ""
  echo "🧹 Stopping services..."
  kill "$INGEST_PID" "$API_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 8. 等待（否则脚本直接退出）
wait

