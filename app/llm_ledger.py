# app/llm_ledger.py

import json
from pathlib import Path

LEDGER_FILE = Path(__file__).parent / "data/llm_usage.jsonl"

def ledger_record(prompt, response):
    LEDGER_FILE.parent.mkdir(exist_ok=True)
    with open(LEDGER_FILE, "a") as f:
        f.write(json.dumps({"prompt": prompt, "response": response}) + "\n")