# app/llm.py
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional

from openai import OpenAI

from app.llm_ledger import append_row


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


_client = OpenAI(
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url=os.environ.get("DEEPSEEK_BASE_URL"),
)


def _extract_json(text: str) -> dict:
    t = (text or "").strip()
    if not t:
        raise ValueError("LLM returned empty content")

    # 1) 纯 JSON
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

    # 3) 文本里截取第一个 JSON 对象
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(t[start:end + 1])

    raise ValueError(f"No JSON found in LLM response (head): {t[:300]}")


def _usage_get(usage: Any, key: str, default: int = 0) -> int:
    """
    兼容 OpenAI SDK usage 可能是 dict 或对象
    """
    if usage is None:
        return default
    if isinstance(usage, dict):
        return int(usage.get(key) or default)
    return int(getattr(usage, key, default) or default)


def call_llm_json(*, events_for_llm: Any, window: str, meta: Optional[Dict[str, Any]] = None) -> dict:
    """
    events_for_llm: 你传入的 payload（通常是 dict，包含 intent/question/events）
    window: 字符串窗口描述，如 last_1h
    meta: 用于 ledger 统计（action/endpoint/event_id/intent）
    """
    user_payload = {"window": window, "events": events_for_llm}

    t0 = time.time()
    ok = False
    err: Optional[str] = None
    usage: Any = None

    try:
        resp = _client.chat.completions.create(
            model=os.environ.get("DEEPSEEK_MODEL"),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
            temperature=0.2,
        )

        usage = getattr(resp, "usage", None)
        text = (resp.choices[0].message.content or "")
        out = _extract_json(text)
        ok = True
        return out

    except Exception as e:
        err = str(e)
        raise

    finally:
        latency_ms = int((time.time() - t0) * 1000)

        row = {
            "ok": ok,
            "action": (meta or {}).get("action", "call_llm_json"),
            "endpoint": (meta or {}).get("endpoint", "-"),
            "event_id": (meta or {}).get("event_id", "-"),
            "intent": (meta or {}).get("intent", "-"),
            "prompt_tokens": _usage_get(usage, "prompt_tokens", 0),
            "completion_tokens": _usage_get(usage, "completion_tokens", 0),
            "total_tokens": _usage_get(usage, "total_tokens", 0),
            "latency_ms": latency_ms,
        }
        if err:
            row["error"] = err

        append_row(row)
