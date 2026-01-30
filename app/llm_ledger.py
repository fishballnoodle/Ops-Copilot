# app/llm_ledger.py
from pathlib import Path
import json

LEDGER_FILE = Path(__file__).parent / "data/llm_usage.jsonl"

def ledger_record(*args, **kwargs):
    # 直接写入日志文件，保存所有参数
    LEDGER_FILE.parent.mkdir(exist_ok=True)
    with open(LEDGER_FILE, "a") as f:
        f.write(json.dumps(kwargs) + "\n")