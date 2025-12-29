# app/llm.py
from __future__ import annotations

import os
import json
import time
from typing import Any, Dict, Optional

from openai import OpenAI

from app.llm_ledger import ledger_record


def json_safe(x: Any) -> Any:
    """
    把任何对象尽量转换成可 JSON 序列化的结构，避免 TypeError: not JSON serializable
    - pydantic v2 BaseModel: 有 model_dump
    - dataclass / obj: 有 __dict__
    - set/tuple: 转 list
    - 其它: str()
    """
    if x is None:
        return None
    if isinstance(x, (str, int, float, bool)):
        return x
    if isinstance(x, dict):
        return {str(k): json_safe(v) for k, v in x.items()}
    if isinstance(x, (list, tuple, set)):
        return [json_safe(i) for i in x]

    # pydantic v2
    if hasattr(x, "model_dump"):
        try:
            return json_safe(x.model_dump())
        except Exception:
            pass

    # pydantic v1
    if hasattr(x, "dict"):
        try:
            return json_safe(x.dict())
        except Exception:
            pass

    # 普通对象
    if hasattr(x, "__dict__"):
        try:
            return json_safe(vars(x))
        except Exception:
            pass

    # 最后兜底
    try:
        return json_safe(str(x))
    except Exception:
        return "<unserializable>"


def _extract_json(text: str) -> Dict[str, Any]:
    """
    容忍 LLM 输出里带 ```json ``` 包裹或前后有杂质。
    """
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


_client = OpenAI(
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url=os.environ.get("DEEPSEEK_BASE_URL"),
)


def call_deepseek_json(
    *,
    system_prompt: str,
    user_payload: Dict[str, Any],
    action: str,
    endpoint: str,
    event_id: Optional[str] = None,
    intent: Optional[str] = None,
    temperature: float = 0.2,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """
    统一的 LLM 调用入口：返回 dict，并把用量写入 ledger（jsonl）。
    """
    model = model or os.environ.get("DEEPSEEK_MODEL") or "deepseek-chat"
    started = time.time()

    prompt_tokens = 0
    completion_tokens = 0
    total_tokens = 0

    try:
        payload_safe = json_safe(user_payload)

        resp = _client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt.strip()},
                {"role": "user", "content": json.dumps(payload_safe, ensure_ascii=False)},
            ],
            temperature=temperature,
        )

        latency_ms = int((time.time() - started) * 1000)

        # DeepSeek(OpenAI兼容)通常会返回 usage
        usage = getattr(resp, "usage", None)
        if usage:
            prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
            completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
            total_tokens = int(getattr(usage, "total_tokens", 0) or 0)

        text = (resp.choices[0].message.content or "")
        data = _extract_json(text)

        ledger_record(
            ok=True,
            action=action,
            endpoint=endpoint,
            event_id=event_id,
            intent=intent,
            model=model,
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            error=None,
            meta={},
        )
        return data

    except Exception as e:
        latency_ms = int((time.time() - started) * 1000)
        ledger_record(
            ok=False,
            action=action,
            endpoint=endpoint,
            event_id=event_id,
            intent=intent,
            model=model,
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            error=str(e),
            meta={},
        )
        raise