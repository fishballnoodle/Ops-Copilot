# app/telemetry.py
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import threading
import json
import os


@dataclass
class LLMUsageRecord:
    ts: str
    action: str                 # briefing/analyze/chat/ask/...
    endpoint: str               # /api/copilot/briefing etc.
    model: str
    ok: bool

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: int = 0

    event_id: Optional[str] = None
    session_id: Optional[str] = None
    intent: Optional[str] = None

    error: Optional[str] = None
    meta: Dict[str, Any] = None


class LLMUsageLedger:
    """
    内存账本（ring buffer），可选 JSONL 落盘。
    """
    def __init__(self, max_items: int = 5000, jsonl_path: Optional[str] = None):
        self.max_items = max_items
        self.jsonl_path = jsonl_path
        self._lock = threading.Lock()
        self._items: List[LLMUsageRecord] = []

        if self.jsonl_path:
            os.makedirs(os.path.dirname(self.jsonl_path), exist_ok=True)

    def add(self, rec: LLMUsageRecord) -> None:
        with self._lock:
            self._items.append(rec)
            if len(self._items) > self.max_items:
                self._items = self._items[-self.max_items :]

        if self.jsonl_path:
            try:
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")
            except Exception:
                # 落盘失败不影响主流程
                pass

    def list(self, window_s: int = 3600, limit: int = 200) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        out: List[LLMUsageRecord] = []
        with self._lock:
            for rec in reversed(self._items):
                try:
                    ts = datetime.fromisoformat(rec.ts.replace("Z", "+00:00"))
                except Exception:
                    continue
                if (now - ts).total_seconds() <= window_s:
                    out.append(rec)
                if len(out) >= limit:
                    break
        return [asdict(x) for x in out]

    def summary(self, window_s: int = 3600) -> Dict[str, Any]:
        rows = self.list(window_s=window_s, limit=self.max_items)
        total = sum(r.get("total_tokens", 0) for r in rows)
        calls = len(rows)
        avg_latency = int(sum(r.get("latency_ms", 0) for r in rows) / calls) if calls else 0

        by_action: Dict[str, Dict[str, int]] = {}
        by_endpoint: Dict[str, Dict[str, int]] = {}

        def bump(bucket: Dict[str, Dict[str, int]], key: str, r: Dict[str, Any]):
            if key not in bucket:
                bucket[key] = {"calls": 0, "tokens": 0, "prompt": 0, "completion": 0, "errors": 0, "latency_ms": 0}
            b = bucket[key]
            b["calls"] += 1
            b["tokens"] += int(r.get("total_tokens") or 0)
            b["prompt"] += int(r.get("prompt_tokens") or 0)
            b["completion"] += int(r.get("completion_tokens") or 0)
            b["latency_ms"] += int(r.get("latency_ms") or 0)
            if not r.get("ok", True):
                b["errors"] += 1

        for r in rows:
            bump(by_action, r.get("action") or "unknown", r)
            bump(by_endpoint, r.get("endpoint") or "unknown", r)

        # 计算平均 latency
        for b in list(by_action.values()) + list(by_endpoint.values()):
            b["avg_latency_ms"] = int(b["latency_ms"] / b["calls"]) if b["calls"] else 0
            b.pop("latency_ms", None)

        return {
            "window_s": window_s,
            "calls": calls,
            "total_tokens": total,
            "avg_latency_ms": avg_latency,
            "by_action": by_action,
            "by_endpoint": by_endpoint,
        }


# 全局实例（你也可以改成依赖注入）
ledger = LLMUsageLedger(
    max_items=int(os.getenv("LLM_LEDGER_MAX", "5000")),
    jsonl_path=os.getenv("LLM_LEDGER_JSONL")  # e.g. ./data/llm_usage.jsonl
)