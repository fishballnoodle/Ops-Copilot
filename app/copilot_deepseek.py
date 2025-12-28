from __future__ import annotations

import os
import json
from typing import Any, Dict, List

import httpx

from app.models import (
    Event, AnalyzeRequest, Analysis,
    Risk, PossibleCause, ActionSuggestion, EvidenceRef, TimelineItem
)
from app.copilot import mock_analyze


def _event_snapshot(event: Event) -> Dict[str, Any]:
    agg = event.aggregate or {}
    logs = (event.evidence.logs or [])[:6]  # 取前 6 条就够 demo
    log_lines = []
    for lg in logs:
        # EvidenceLog 是 pydantic model，取字段更稳
        log_lines.append({
            "ts": getattr(lg, "ts", None),
            "log_id": getattr(lg, "log_id", None),
            "raw": getattr(lg, "raw", "")[:300],
        })

    return {
        "event_id": event.event_id,
        "ts": event.ts,
        "title": event.title,
        "category": event.category,
        "severity_hint": event.severity_hint,
        "source": {
            "type": event.source.type,
            "vendor": event.source.vendor,
            "name": event.source.name,
            "id": event.source.id,
        },
        "labels": event.labels,
        "entities": [{"type": e.type, "name": e.name} for e in (event.entities or [])],
        "fingerprint": event.fingerprint,
        "aggregate": {
            "count": agg.get("count", 1),
            "first_seen": agg.get("first_seen"),
            "last_seen": agg.get("last_seen"),
        },
        "evidence_logs": log_lines,
    }


def _question_to_instruction(q: str) -> str:
    mapping = {
        "now_status": "给出当前状态：是否仍在发生？频率如何？",
        "what_happened": "用 3-5 句总结发生了什么（可引用证据日志）。",
        "impact": "说明可能影响范围/风险，并给出判断依据。",
        "next_steps": "给出 3-6 条可执行的处置步骤（带命令或检查项更好）。",
        "do_nothing": "说明如果不处理可能的后果 + 可以监控的指标。",
    }
    return mapping.get(q, "对该事件做分析，并给出处置建议。")


def _build_prompt(event: Event, req: AnalyzeRequest) -> str:
    snap = _event_snapshot(event)
    instruction = _question_to_instruction(req.question)

    # 注意：让模型按结构化 JSON 输出，便于直接映射到 pydantic
    return f"""你是资深网络/安全运维 SRE。请基于给定事件与证据，输出严格 JSON（不要 Markdown，不要多余文字）。

【任务】
{instruction}

【事件快照 JSON】
{json.dumps(snap, ensure_ascii=False, indent=2)}

【输出 JSON 结构要求】
{{
  "summary": "一句话总结",
  "risk": {{
    "level": "LOW|MEDIUM|HIGH",
    "confidence": 0.0,
    "impact": "影响描述",
    "spread": "扩散判断"
  }},
  "possible_causes": [
    {{ "rank": 1, "cause": "原因", "confidence": 0.0 }}
  ],
  "actions": [
    {{ "priority": 1, "action": "动作", "why": "原因" }}
  ],
  "evidence_refs": [
    {{ "type": "log", "id": "log_xxx", "ts": "..." }}
  ],
  "narrative_timeline": [
    {{ "ts": "...", "note": "..." }}
  ],
  "should_page_someone": false
}}
"""


def _parse_analysis(obj: Dict[str, Any]) -> Analysis:
    # 把模型输出映射为你的 pydantic Analysis
    risk = obj.get("risk") or None
    risk_model = None
    if isinstance(risk, dict):
        risk_model = Risk(
            level=str(risk.get("level", "LOW")),
            confidence=float(risk.get("confidence", 0.5)),
            impact=str(risk.get("impact", "")),
            spread=str(risk.get("spread", "")),
        )

    pcs = []
    for i in (obj.get("possible_causes") or []):
        if isinstance(i, dict):
            pcs.append(PossibleCause(
                rank=int(i.get("rank", 1)),
                cause=str(i.get("cause", "")),
                confidence=float(i.get("confidence", 0.0)),
            ))

    acts = []
    for a in (obj.get("actions") or []):
        if isinstance(a, dict):
            acts.append(ActionSuggestion(
                priority=int(a.get("priority", 1)),
                action=str(a.get("action", "")),
                why=str(a.get("why", "")),
            ))

    evs = []
    for e in (obj.get("evidence_refs") or []):
        if isinstance(e, dict):
            evs.append(EvidenceRef(
                type=str(e.get("type", "log")),
                id=e.get("id"),
                name=e.get("name"),
                ts=e.get("ts"),
            ))

    tls = []
    for t in (obj.get("narrative_timeline") or []):
        if isinstance(t, dict):
            tls.append(TimelineItem(
                ts=str(t.get("ts", "")),
                note=str(t.get("note", "")),
            ))

    return Analysis(
        summary=str(obj.get("summary", "")),
        risk=risk_model,
        possible_causes=pcs,
        actions=acts,
        evidence_refs=evs,
        narrative_timeline=tls,
        should_page_someone=bool(obj.get("should_page_someone", False)),
    )


def deepseek_analyze(event: Event, req: AnalyzeRequest) -> Analysis:
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1").strip().rstrip("/")
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip()

    # 没配 key：直接走 mock，保证演示稳
    if not api_key:
        return mock_analyze(event, req)

    prompt = _build_prompt(event, req)

    try:
        with httpx.Client(timeout=30) as client:
            r = client.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "你输出必须是严格 JSON。"},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                },
            )
            r.raise_for_status()
            data = r.json()
            content = data["choices"][0]["message"]["content"]

        # 有时模型会在 JSON 外多输出空白/前后文，做一次鲁棒提取
        content = content.strip()
        if content.startswith("```"):
            content = content.strip("`").strip()
        obj = json.loads(content)

        return _parse_analysis(obj)

    except Exception:
        # 真实模型失败时：fallback 到 mock，保证 UI 不挂
        return mock_analyze(event, req)
