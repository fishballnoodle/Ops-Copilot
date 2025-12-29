# app/main.py
from __future__ import annotations

import os
import re
import uuid
import traceback
from datetime import datetime, timezone
from typing import Optional, Any, Dict

from fastapi import FastAPI, HTTPException, Request, Body
from fastapi.middleware.cors import CORSMiddleware

from app.models import (
    Event,
    IngestResponse,
    FocusResponse,
    FocusItem,
    AnalyzeRequest,
    ChatRequest,
    ChatResponse,
)
from app.store import InMemoryStore
from app.scoring import score_event
from app.copilot import detect_intent
from app.ingest.syslog import parse_syslog

from app.llm import call_deepseek_json, json_safe
from app.llm_ledger import ledger_summary, ledger_list


app = FastAPI(title="Ops Copilot API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # demo 阶段放开
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = InMemoryStore()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_parse_dt(ts: Optional[str]) -> datetime:
    if not ts:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _event_sort_key(e: Event) -> datetime:
    agg = getattr(e, "aggregate", None) or {}
    return _safe_parse_dt((agg.get("last_seen") or e.ts))


def _fingerprint_fallback(msg: str) -> str:
    s = (msg or "").strip()
    s = re.sub(
        r"^%[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}:\d{3}\s+\d{4}\s+H3C\s+",
        "H3C ",
        s,
    )
    return s


ANALYZE_SYSTEM_PROMPT = """
You are an on-call network operations copilot for switches/firewalls.

Rules:
- Output MUST be valid JSON and nothing else.
- Do NOT invent facts. Use only the provided event and context.
- Be concise and practical.

Return JSON schema EXACTLY:
{
  "summary": string,
  "risk": {
    "level": "LOW"|"MEDIUM"|"HIGH",
    "confidence": number,
    "impact": string,
    "spread": string
  },
  "possible_causes": [
    {"rank": number, "cause": string, "confidence": number}
  ],
  "actions": [
    {"priority": number, "action": string, "why": string}
  ],
  "evidence_refs": [
    {"type":"log","id":string} | {"type":"metric","name":string,"ts":string}
  ],
  "narrative_timeline": [
    {"ts": string, "note": string}
  ]
}
""".strip()


CHAT_SYSTEM_PROMPT = """
You are an on-call network operations copilot.

Rules:
- Output MUST be valid JSON and nothing else.
- Do NOT invent facts. Use only provided events + context.
- Be concise, action-oriented.

Return JSON schema EXACTLY:
{
  "reply": string,
  "analysis": {
    "summary": string,
    "risk": {"level":"LOW|MEDIUM|HIGH","confidence":number,"impact":string,"spread":string},
    "possible_causes":[{"rank":number,"cause":string,"confidence":number}],
    "actions":[{"priority":number,"action":string,"why":string}],
    "evidence_refs":[{"type":"log","id":string} | {"type":"metric","name":string,"ts":string}],
    "narrative_timeline":[{"ts":string,"note":string}]
  }
}
""".strip()


def _fill_analysis_defaults(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        data = {}

    data.setdefault("summary", "")
    data.setdefault("risk", {})
    if not isinstance(data["risk"], dict):
        data["risk"] = {}
    data["risk"].setdefault("level", "LOW")
    data["risk"].setdefault("confidence", 0.0)
    data["risk"].setdefault("impact", "-")
    data["risk"].setdefault("spread", "-")

    data.setdefault("possible_causes", [])
    data.setdefault("actions", [])
    data.setdefault("evidence_refs", [])
    data.setdefault("narrative_timeline", [])
    return data


# -----------------------------
# Health
# -----------------------------
@app.get("/api/health")
def health():
    llm = "deepseek" if os.getenv("DEEPSEEK_API_KEY") else "mock"
    return {"status": "ok", "llm": llm, "version": app.version}


# -----------------------------
# LLM Ledger APIs
# -----------------------------
@app.get("/api/llm/summary")
def api_llm_summary(window_s: int = 3600):
    return {"ok": True, "generated_at": _now_iso(), "summary": ledger_summary(window_s=window_s)}


@app.get("/api/llm/usage")
def api_llm_usage(window_s: int = 3600, limit: int = 50):
    return {"ok": True, "generated_at": _now_iso(), "window_s": window_s, "items": ledger_list(window_s=window_s, limit=limit)}


# -----------------------------
# Ingest Syslog
# -----------------------------
@app.post("/api/ingest/syslog")
async def ingest_syslog(req: Request):
    payload = await req.json()

    host = payload.get("host") or "unknown"
    program = payload.get("program") or "syslog"
    msg = payload.get("msg") or ""
    ts = payload.get("timestamp") or _now_iso()

    parsed = {}
    try:
        parsed = parse_syslog(msg) or {}
    except Exception:
        parsed = {}

    category = payload.get("category") or parsed.get("category") or "SYSLOG"
    title = payload.get("title") or parsed.get("title") or f"{host} {program}: {msg[:80]}".strip()
    fp = (
        payload.get("fingerprint")
        or parsed.get("fingerprint")
        or f"syslog|{host}|{program}|{_fingerprint_fallback(msg)[:140]}"
    )

    e = Event(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        ts=ts,
        fingerprint=fp,
        category=category,
        title=title,
        source={"name": host, "kind": "syslog", "host": host, "program": program},
        raw={"message": msg, "payload": payload, "parsed": parsed},
    )

    store.upsert_events([e])
    return {"ok": True, "event_id": e.event_id, "fingerprint": fp, "title": title, "category": category}


# -----------------------------
# Events APIs
# -----------------------------
@app.post("/api/events/ingest", response_model=IngestResponse)
def ingest(events: list[Event]):
    ids = store.upsert_events(events)
    return IngestResponse(inserted=len(ids), event_ids=ids)


@app.get("/api/events", response_model=list[Event])
def list_events(limit: int = 20):
    try:
        return store.list_events(limit=limit)
    except TypeError:
        items = store.recent_events(limit=limit) if hasattr(store, "recent_events") else store.list_events(limit=limit)
        items = list(items)
        items.sort(key=_event_sort_key, reverse=True)
        return items


# -----------------------------
# Focus
# -----------------------------
@app.get("/api/focus", response_model=FocusResponse)
def focus(top: int = 3):
    events = store.recent_events(limit=50) if hasattr(store, "recent_events") else store.list_events(limit=50)

    scored = []
    for e in events:
        score, lvl = score_event(e)

        agg = getattr(e, "aggregate", None) or {}
        cnt = int(agg.get("count") or 1)
        fs = agg.get("first_seen")
        ls = agg.get("last_seen")

        cat_u = (e.category or "").upper()
        fp_u = (e.fingerprint or "").upper()
        title_u = (e.title or "").upper()

        if "MAC_FLAPPING" in cat_u or "MAC_FLAPPING" in fp_u or "MAC_FLAPPING" in title_u:
            if lvl == "HIGH":
                one_line = f"高频 MAC 漂移（{cnt}次，{fs}~{ls}），优先排查环路/聚合口，必要时隔离端口。"
            elif lvl == "MEDIUM":
                one_line = f"MAC 漂移（{cnt}次，{fs}~{ls}），建议查 STP/Trunk/上联口一致性。"
            else:
                one_line = f"偶发 MAC 漂移（{cnt}次），可能为迁移或短暂抖动，可观察。"
        else:
            one_line = "当前风险较低，可先观察是否继续出现。" if lvl == "LOW" else "建议尽快确认影响范围与根因。"

        scored.append((float(score), lvl, e, one_line))

    scored.sort(key=lambda x: x[0], reverse=True)

    items = [
        FocusItem(
            event_id=e.event_id,
            title=e.title,
            risk_level=lvl,
            one_line=one_line,
            score=float(score),
        )
        for score, lvl, e, one_line in scored[:top]
    ]
    return FocusResponse(items=items)


# -----------------------------
# Analyze
# -----------------------------
@app.post("/api/copilot/analyze")
def copilot_analyze(req: AnalyzeRequest):
    e = store.get_event(req.event_id)
    if not e:
        raise HTTPException(status_code=404, detail="event not found")

    payload = {
        "question": req.question,
        "event": {
            "event_id": e.event_id,
            "ts": e.ts,
            "title": e.title,
            "category": e.category,
            "fingerprint": e.fingerprint,
            "aggregate": getattr(e, "aggregate", None) or {},
            "raw": e.raw,
        },
        "context": json_safe(getattr(req, "context", None) or {}),
    }

    data = call_deepseek_json(
        system_prompt=ANALYZE_SYSTEM_PROMPT,
        user_payload=payload,
        action="analyze",
        endpoint="/api/copilot/analyze",
        event_id=e.event_id,
        intent=req.question,
        temperature=0.2,
    )
    return _fill_analysis_defaults(data)


@app.get("/api/incidents/{event_id}/timeline")
def incident_timeline(event_id: str):
    e = store.get_event(event_id)
    if not e:
        raise HTTPException(status_code=404, detail="event not found")

    payload = {
        "question": "what_happened",
        "event": {
            "event_id": e.event_id,
            "ts": e.ts,
            "title": e.title,
            "category": e.category,
            "fingerprint": e.fingerprint,
            "aggregate": getattr(e, "aggregate", None) or {},
            "raw": e.raw,
        },
        "context": {},
    }

    data = call_deepseek_json(
        system_prompt=ANALYZE_SYSTEM_PROMPT,
        user_payload=payload,
        action="timeline",
        endpoint="/api/incidents/{event_id}/timeline",
        event_id=e.event_id,
        intent="what_happened",
        temperature=0.2,
    )

    tl = []
    if isinstance(data, dict):
        tl = data.get("narrative_timeline") or []
    return {"event_id": event_id, "timeline": tl}


# -----------------------------
# Chat (统计 token)
# -----------------------------
@app.post("/api/copilot/chat", response_model=ChatResponse)
def copilot_chat(req: ChatRequest):
    msg = (req.message or "").strip()
    if not msg:
        return ChatResponse(reply="你还没输入问题。", focus=[], analysis=None)

    selected = None
    try:
        selected = (req.context or {}).get("selected_event_id")
    except Exception:
        selected = None

    if not selected:
        f = focus(top=1).items
        selected = f[0].event_id if f else None

    e = store.get_event(selected) if selected else None
    intent = detect_intent(msg)

    payload: Dict[str, Any] = {
        "message": msg,
        "intent": intent,
        "selected_event_id": selected,
        "event": None,
    }

    if e:
        payload["event"] = {
            "event_id": e.event_id,
            "ts": e.ts,
            "title": e.title,
            "category": e.category,
            "fingerprint": e.fingerprint,
            "aggregate": getattr(e, "aggregate", None) or {},
            "raw": e.raw,
        }

    data = call_deepseek_json(
        system_prompt=CHAT_SYSTEM_PROMPT,
        user_payload=payload,
        action="chat",
        endpoint="/api/copilot/chat",
        event_id=(e.event_id if e else None),
        intent=intent,
        temperature=0.2,
    )

    reply = ""
    analysis = None
    if isinstance(data, dict):
        reply = str(data.get("reply") or "").strip()
        analysis_raw = data.get("analysis")
        if analysis_raw is not None:
            analysis = _fill_analysis_defaults(analysis_raw)

    if not reply:
        reply = "我收到了你的问题，但没有拿到有效 JSON 回复（请检查 LLM 输出）。"

    f_items = focus(top=3).items
    focus_payload = [{"event_id": i.event_id, "risk_level": i.risk_level, "title": i.title} for i in f_items]

    return ChatResponse(reply=reply, focus=focus_payload, analysis=analysis)