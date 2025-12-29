from __future__ import annotations

import os
import json
import time
from typing import Any, Dict, Optional

from openai import OpenAI
from fastapi.encoders import jsonable_encoder

from app.models import Event, AnalyzeRequest, Analysis
from app.llm_ledger import ledger_record


SYSTEM_PROMPT = """
You are an on-call network operations copilot.

Rules:
- Output MUST be valid JSON and nothing else.
- Do NOT invent facts.
- Be concise and practical.
- Prefer network/firewall/switch interpretation.

Return JSON schema:
{
  "summary": string,
  "risk": { "level": "LOW|MEDIUM|HIGH", "confidence": number, "impact": string, "spread": string },
  "possible_causes": [ { "rank": number, "cause": string, "confidence": number } ],
  "actions": [ { "priority": number, "action": string, "why": string } ],
  "evidence_refs": [ { "type": "log|metric", "id": string, "name": string, "ts": string } ],
  "narrative_timeline": [ { "ts": string, "note": string } ]
}
""".strip()


_client = OpenAI(
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url=os.environ.get("DEEPSEEK_BASE_URL"),
)


def _extract_json(text: str) -> Dict[str, Any]:
    t = (text or "").strip()
    if not t:
        raise ValueError("LLM returned empty content")

    if t.startswith("{"):
        return json.loads(t)

    if "```" in t:
        parts = t.split("```")
        for p in parts:
            p = p.strip()
            if p.lower().startswith("json"):
                p = p[4:].strip()
            if p.startswith("{"):
                return json.loads(p)

    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(t[start : end + 1])

    raise ValueError(f"No JSON found in LLM response (head): {t[:300]}")


def deepseek_analyze(
    e: Event,
    req: AnalyzeRequest,
    *,
    endpoint: str = "/api/copilot/analyze",
    action: Optional[str] = None,
    intent: Optional[str] = None,
) -> Analysis:
    """
    统一的 LLM 分析入口：
    - /api/copilot/analyze 调它
    - /api/copilot/chat 也应调它（这样 chat 一定记账）
    """
    started = time.time()
    ok = True
    err: Optional[str] = None
    usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    # action 默认用 question（你面板按 action 汇总会更直观）
    act = action or (req.question or "analyze")

    try:
        # ✅ 关键：任何 pydantic / datetime / set 等都强制变成 JSON-safe
        payload_obj = {
            "event": e,
            "request": req,
            "question": req.question,
            "context": req.context or {},
        }
        payload = jsonable_encoder(payload_obj)

        resp = _client.chat.completions.create(
            model=os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
            temperature=0.2,
        )

        if getattr(resp, "usage", None):
            usage["prompt_tokens"] = int(getattr(resp.usage, "prompt_tokens", 0) or 0)
            usage["completion_tokens"] = int(getattr(resp.usage, "completion_tokens", 0) or 0)
            usage["total_tokens"] = int(getattr(resp.usage, "total_tokens", 0) or 0)

        text = (resp.choices[0].message.content or "")
        obj = _extract_json(text)

        # ✅ 兼容你 Pydantic v2：优先 model_validate
        if hasattr(Analysis, "model_validate"):
            return Analysis.model_validate(obj)  # type: ignore
        return Analysis(**obj)  # type: ignore

    except Exception as ex:
        ok = False
        err = str(ex)
        raise

    finally:
        latency_ms = int((time.time() - started) * 1000)
        ledger_record(
            ok=ok,
            action=act,
            endpoint=endpoint,
            event_id=getattr(e, "event_id", None),
            intent=intent,
            latency_ms=latency_ms,
            prompt_tokens=usage["prompt_tokens"],
            completion_tokens=usage["completion_tokens"],
            total_tokens=usage["total_tokens"],
            error=err,
        )