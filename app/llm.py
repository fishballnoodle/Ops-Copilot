# app/llm.py
from __future__ import annotations

import os
import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from openai import OpenAI

SYSTEM_PROMPT = """
You are an on-call network operations copilot.

Rules:
- Output MUST be valid JSON and nothing else.
- Do NOT invent facts.
- Be concise and practical.
- Prefer network/firewall/switch interpretation.

Return JSON schema:
{
  "overall": {
    "summary": string,
    "risk_level": "LOW|MEDIUM|HIGH",
    "what_changed": [string],
    "quick_checks": [string]
  },
  "top": [
    {
      "event_id": string,
      "title": string,
      "category": string,
      "count": number,
      "first_seen": string|null,
      "last_seen": string|null,
      "why_it_matters": string,
      "next_steps": [string],
      "confidence": number
    }
  ]
}
""".strip()


# -----------------------------
# LLM client (DeepSeek OpenAI-compatible)
# -----------------------------
_client = OpenAI(
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url=os.environ.get("DEEPSEEK_BASE_URL"),
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# -----------------------------
# Usage Ledger (in-memory)
# -----------------------------
@dataclass
class LLMUsageRecord:
    ts: str
    ok: bool

    action: str
    endpoint: str
    model: str

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: int = 0

    # correlation
    event_id: Optional[str] = None
    session_id: Optional[str] = None
    intent: Optional[str] = None

    error: Optional[str] = None
    meta: Dict[str, Any] = None


class LLMUsageLedger:
    def __init__(self, max_items: int = 5000):
        self.max_items = max_items
        self._items: List[LLMUsageRecord] = []

    def add(self, rec: LLMUsageRecord) -> None:
        self._items.append(rec)
        if len(self._items) > self.max_items:
            self._items = self._items[-self.max_items :]

    def list(self, window_s: int = 3600, limit: int = 200) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        out: List[LLMUsageRecord] = []
        for rec in reversed(self._items):
            try:
                ts = datetime.fromisoformat(rec.ts.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                continue
            if (now - ts).total_seconds() <= window_s:
                out.append(rec)
            if len(out) >= limit:
                break
        return [asdict(x) for x in out]

    def summary(self, window_s: int = 3600) -> Dict[str, Any]:
        rows = self.list(window_s=window_s, limit=self.max_items)

        calls = len(rows)
        total_tokens = sum(int(r.get("total_tokens") or 0) for r in rows)
        avg_latency_ms = int(sum(int(r.get("latency_ms") or 0) for r in rows) / calls) if calls else 0
        errors = sum(1 for r in rows if not r.get("ok", True))

        by_action: Dict[str, Dict[str, Any]] = {}
        by_endpoint: Dict[str, Dict[str, Any]] = {}

        def bump(bucket: Dict[str, Dict[str, Any]], key: str, r: Dict[str, Any]) -> None:
            if key not in bucket:
                bucket[key] = {"calls": 0, "tokens": 0, "prompt": 0, "completion": 0, "errors": 0, "avg_latency_ms": 0, "_lat": 0}
            b = bucket[key]
            b["calls"] += 1
            b["tokens"] += int(r.get("total_tokens") or 0)
            b["prompt"] += int(r.get("prompt_tokens") or 0)
            b["completion"] += int(r.get("completion_tokens") or 0)
            b["_lat"] += int(r.get("latency_ms") or 0)
            if not r.get("ok", True):
                b["errors"] += 1

        for r in rows:
            bump(by_action, r.get("action") or "unknown", r)
            bump(by_endpoint, r.get("endpoint") or "unknown", r)

        for b in list(by_action.values()) + list(by_endpoint.values()):
            b["avg_latency_ms"] = int(b["_lat"] / b["calls"]) if b["calls"] else 0
            b.pop("_lat", None)

        return {
            "window_s": window_s,
            "calls": calls,
            "errors": errors,
            "total_tokens": total_tokens,
            "avg_latency_ms": avg_latency_ms,
            "by_action": by_action,
            "by_endpoint": by_endpoint,
        }


ledger = LLMUsageLedger(max_items=int(os.getenv("LLM_LEDGER_MAX", "5000")))


def ledger_list(window_s: int = 3600, limit: int = 200) -> List[Dict[str, Any]]:
    return ledger.list(window_s=window_s, limit=limit)


def ledger_summary(window_s: int = 3600) -> Dict[str, Any]:
    return ledger.summary(window_s=window_s)


# -----------------------------
# JSON extraction (robust)
# -----------------------------
def _extract_json(text: str) -> dict:
    t = (text or "").strip()

    if not t:
        raise ValueError("LLM returned empty content")

    # 1) pure JSON
    if t.startswith("{"):
        return json.loads(t)

    # 2) ```json ... ``` / ``` ... ```
    if "```" in t:
        parts = t.split("```")
        for p in parts:
            p = p.strip()
            if p.lower().startswith("json"):
                p = p[4:].strip()
            if p.startswith("{"):
                return json.loads(p)

    # 3) extract first {...}
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(t[start : end + 1])

    raise ValueError(f"No JSON found in LLM response (head): {t[:300]}")


# -----------------------------
# main callable
# -----------------------------
def call_llm_json(
    *,
    events_for_llm: Any,
    window: str,
    action: str = "unknown",
    endpoint: str = "unknown",
    event_id: Optional[str] = None,
    session_id: Optional[str] = None,
    intent: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> dict:
    """
    Calls DeepSeek(OpenAI-compatible) and MUST return JSON.
    Also records token usage + latency into in-memory ledger.
    """

    model = os.environ.get("DEEPSEEK_MODEL") or "deepseek-chat"

    user_payload = {"window": window, "events": events_for_llm}

    t0 = time.perf_counter()
    ok = False
    err: Optional[str] = None
    usage_prompt = 0
    usage_completion = 0
    usage_total = 0

    try:
        resp = _client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
            temperature=0.2,
        )

        # usage extraction (if provided)
        u = getattr(resp, "usage", None)
        if u is not None:
            usage_prompt = int(getattr(u, "prompt_tokens", 0) or 0)
            usage_completion = int(getattr(u, "completion_tokens", 0) or 0)
            usage_total = int(getattr(u, "total_tokens", 0) or 0)

        text = (resp.choices[0].message.content or "")
        data = _extract_json(text)
        ok = True
        return data

    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        raise

    finally:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        ledger.add(
            LLMUsageRecord(
                ts=_now_iso(),
                ok=ok,
                action=action,
                endpoint=endpoint,
                model=model,
                prompt_tokens=usage_prompt,
                completion_tokens=usage_completion,
                total_tokens=usage_total,
                latency_ms=latency_ms,
                event_id=event_id,
                session_id=session_id,
                intent=intent,
                error=err,
                meta=meta or {},
            )
        )