# app/llm.py
from __future__ import annotations

import os
import json
import time
import re
from typing import Any, Dict, Optional

try:
    # openai>=1.x
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore


# -----------------------------
# Config
# -----------------------------
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "sk-98549bf54d0c4c07afbf54310b5120ea")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

# NOTE: 你后面要做 token/成本统计，可以在这里接 llm_ledger（先保证能跑）
_CLIENT: Optional[Any] = None


def _get_client() -> Optional[Any]:
    global _CLIENT
    if _CLIENT is not None:
        return _CLIENT
    if not OpenAI:
        return None
    if not DEEPSEEK_API_KEY:
        return None
    _CLIENT = OpenAI(
        api_key=DEEPSEEK_API_KEY,
        base_url=DEEPSEEK_BASE_URL,
    )
    return _CLIENT


# -----------------------------
# Utilities
# -----------------------------
def json_safe(obj: Any) -> Any:
    """
    让 payload 可 JSON 序列化，避免你之前 deepseek_analyze json.dumps 报错：
    TypeError: Object of type ... is not JSON serializable
    """
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, list):
        return [json_safe(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}

    # pydantic
    if hasattr(obj, "model_dump"):
        try:
            return json_safe(obj.model_dump())
        except Exception:
            pass
    if hasattr(obj, "dict"):
        try:
            return json_safe(obj.dict())
        except Exception:
            pass

    # dataclass / others
    if hasattr(obj, "__dict__"):
        try:
            return json_safe(vars(obj))
        except Exception:
            pass

    return str(obj)


_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json(text: str) -> Dict[str, Any]:
    """
    DeepSeek 有时会输出 ```json ...``` 或者带解释文字。
    这里尽量从文本中抠出 JSON object。
    """
    text = (text or "").strip()
    if not text:
        return {}

    # 直接就是 JSON
    try:
        j = json.loads(text)
        if isinstance(j, dict):
            return j
    except Exception:
        pass

    # 尝试从中间抽取 {...}
    m = _JSON_BLOCK_RE.search(text)
    if m:
        try:
            j = json.loads(m.group(0))
            if isinstance(j, dict):
                return j
        except Exception:
            pass

    # 最后兜底：返回一个结构，避免上层崩
    return {"raw_text": text}


# -----------------------------
# Core call (JSON result)
# -----------------------------
def call_deepseek_json(
    *,
    system: str,
    user: str,
    temperature: float = 0.2,
    timeout_s: int = 60,
) -> Dict[str, Any]:
    """
    直接请求 deepseek-chat，并要求返回 JSON。
    """
    client = _get_client()

    # 没 key 或 client 不可用：返回 mock，保证开发不阻塞
    if not client:
        return {
            "ok": True,
            "mock": True,
            "note": "DEEPSEEK_API_KEY not set or OpenAI client unavailable",
            "system": system[:200],
            "user": user[:200],
        }

    t0 = time.time()
    try:
        resp = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            timeout=timeout_s,
        )
        t1 = time.time()

        content = ""
        try:
            content = resp.choices[0].message.content or ""
        except Exception:
            content = ""

        data = _extract_json(content)

        # 附带一些调试信息（不影响你上层用）
        data.setdefault("ok", True)
        data.setdefault("_meta", {})
        data["_meta"]["latency_ms"] = int((t1 - t0) * 1000)
        data["_meta"]["model"] = DEEPSEEK_MODEL

        # usage（如果有就带上，后面你做 token/cost 统计会用到）
        try:
            u = getattr(resp, "usage", None)
            if u:
                data["_meta"]["usage"] = {
                    "prompt_tokens": getattr(u, "prompt_tokens", None),
                    "completion_tokens": getattr(u, "completion_tokens", None),
                    "total_tokens": getattr(u, "total_tokens", None),
                }
        except Exception:
            pass

        return data

    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
        }


def call_llm_json(*, events_for_llm: Any, window: str = "last_1h") -> Dict[str, Any]:
    """
    给 /api/copilot/briefing 或 /api/copilot/ask 用的“摘要型 JSON”接口。
    你 main.py 里 import 的就是这个名字：call_llm_json ✅
    """
    system = (
        "你是一个运维指挥中心 Copilot。"
        "你会基于输入的事件列表，输出结构化 JSON，总结当前最重要的问题与建议。"
        "务必只输出 JSON 对象，不要输出额外解释文字。"
    )

    payload = {
        "window": window,
        "events": json_safe(events_for_llm),
        "output_schema": {
            "summary": "string",
            "top_risks": [
                {"event_id": "string", "risk": "LOW|MEDIUM|HIGH", "why": "string"}
            ],
            "next_steps": [
                {"priority": 1, "action": "string", "why": "string"}
            ],
        },
    }

    user = json.dumps(payload, ensure_ascii=False)

    return call_deepseek_json(system=system, user=user, temperature=0.2)