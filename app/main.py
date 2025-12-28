# app/main.py
from __future__ import annotations

import os
import uuid
import traceback
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Body
from fastapi.middleware.cors import CORSMiddleware

import app.store as store_mod
from app.models import (
    Event, IngestResponse, FocusResponse, FocusItem,
    AnalyzeRequest, ChatRequest, ChatResponse, Analysis
)
from app.store import InMemoryStore
from app.scoring import score_event
from app.copilot import detect_intent
from app.copilot_deepseek import deepseek_analyze
from app.llm import call_llm_json, ledger_list, ledger_summary
from app.ingest.syslog import parse_syslog
import re

print("STORE MODULE PATH =", store_mod.__file__)

app = FastAPI(title="Ops Copilot API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # demo 阶段放开
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = InMemoryStore()
print("STORE INSTANCE TYPE =", type(store))
print("STORE HAS ingest_event =", hasattr(store, "ingest_event"))
print("STORE METHODS =", [n for n in dir(store) if n in ("ingest_event", "upsert_events", "list_events", "get_event", "recent_events")])


# -----------------------------
# helpers
# -----------------------------
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
    """
    兜底：尽量去掉类似 H3C 前缀时间戳，避免每条都不一样。
    """
    s = (msg or "").strip()
    s = re.sub(r"^%[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}:\d{3}\s+\d{4}\s+H3C\s+", "H3C ", s)
    s = re.sub(r"^%[A-Za-z]{3}\s+\d{1,2}\s+", "%MON DAY ", s)
    return s


# -----------------------------
# LLM usage APIs (token panel backend)
# -----------------------------
@app.get("/api/llm/usage")
def llm_usage(window_s: int = 3600, limit: int = 200):
    return {
        "ok": True,
        "generated_at": _now_iso(),
        "window_s": window_s,
        "items": ledger_list(window_s=window_s, limit=limit),
    }


@app.get("/api/llm/summary")
def llm_summary(window_s: int = 3600):
    return {
        "ok": True,
        "generated_at": _now_iso(),
        "summary": ledger_summary(window_s=window_s),
    }


# -----------------------------
# Copilot Ask / Briefing
# -----------------------------
@app.post("/api/copilot/ask")
def copilot_ask(payload: dict = Body(...)):
    q = (payload.get("question") or "").strip()
    top = int(payload.get("top") or 3)

    # recent_events 签名容易踩坑：用 limit=top
    if hasattr(store, "recent_events"):
        focus_items = store.recent_events(limit=top)  # type: ignore
    else:
        focus_items = store.list_events(limit=top)

    def to_llm(e: Event) -> dict:
        agg = getattr(e, "aggregate", None) or {}
        return {
            "event_id": e.event_id,
            "title": e.title,
            "category": e.category,
            "fingerprint": e.fingerprint,
            "count": agg.get("count") or 1,
            "first_seen": agg.get("first_seen"),
            "last_seen": agg.get("last_seen"),
            "ts": e.ts,
        }

    events_for_llm = [to_llm(e) for e in focus_items]
    intent = detect_intent(q)

    result = call_llm_json(
        events_for_llm={
            "intent": intent,
            "question": q,
            "events": events_for_llm,
        },
        window="last_1h",
        action="ask",
        endpoint="/api/copilot/ask",
        intent=intent,
        meta={"top": top},
    )

    result["intent"] = intent
    result["ok"] = True
    result["generated_at"] = _now_iso()
    return result


@app.get("/api/copilot/briefing")
def copilot_briefing(top: int = 3, window: str = "last_1h"):
    try:
        if hasattr(store, "recent_events"):
            focus_items = store.recent_events(limit=top)  # type: ignore
        else:
            focus_items = store.list_events(limit=top)

        def to_llm(e: Event) -> dict:
            agg = getattr(e, "aggregate", None) or {}
            return {
                "event_id": getattr(e, "event_id", None),
                "title": getattr(e, "title", None),
                "category": getattr(e, "category", None),
                "ts": getattr(e, "ts", None),
                "fingerprint": getattr(e, "fingerprint", None),
                "count": (agg.get("count") or 1),
                "first_seen": agg.get("first_seen"),
                "last_seen": agg.get("last_seen"),
                "aggregate": agg,
            }

        events_for_llm = [to_llm(e) for e in focus_items]

        briefing = call_llm_json(
            events_for_llm=events_for_llm,
            window=window,
            action="briefing",
            endpoint="/api/copilot/briefing",
            meta={"top": top, "window": window},
        )

        briefing["ok"] = True
        briefing["generated_at"] = _now_iso()
        briefing["window"] = window
        return briefing

    except Exception as e:
        return {
            "ok": False,
            "generated_at": _now_iso(),
            "window": window,
            "error": str(e),
            "trace_tail": traceback.format_exc().splitlines()[-25:],
        }


# -----------------------------
# Ingest Syslog (parse_syslog)
# -----------------------------
@app.post("/api/ingest/syslog")
async def ingest_syslog(req: Request):
    payload = await req.json()

    host = payload.get("host") or "unknown"
    program = payload.get("program") or "syslog"
    msg = payload.get("msg") or ""
    ts = payload.get("timestamp") or datetime.now(timezone.utc).isoformat()

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
        source={
            "name": f"{host}",
            "kind": "syslog",
            "host": host,
            "program": program,
        },
        raw={"message": msg, "payload": payload, "parsed": parsed},
    )

    store.upsert_events([e])
    return {"ok": True, "event_id": e.event_id, "fingerprint": fp, "title": title, "category": category}


# -----------------------------
# Health
# -----------------------------
@app.get("/api/health")
def health():
    llm = "deepseek" if os.getenv("DEEPSEEK_API_KEY") else "mock"
    return {"status": "ok", "llm": llm, "version": app.version}


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
        # 兜底：避免 naive/aware 比较导致 500
        if hasattr(store, "recent_events"):
            items = store.recent_events(limit=limit)  # type: ignore
        else:
            items = store.list_events(limit=limit)

        items = list(items)
        items.sort(key=_event_sort_key, reverse=True)
        return items


# -----------------------------
# Focus (Top N)
# -----------------------------
@app.get("/api/focus", response_model=FocusResponse)
def focus(top: int = 3):
    events = store.recent_events(limit=50)  # type: ignore

    scored = []
    for e in events:
        score, lvl = score_event(e)

        agg = getattr(e, "aggregate", None) or {}
        cnt = int(agg.get("count") or 1)
        fs = agg.get("first_seen")
        ls = agg.get("last_seen")

        one_line = ""
        if "MAC_FLAPPING" in (e.category or "").upper():
            if lvl == "HIGH":
                one_line = (
                    f"高频 MAC 漂移（{cnt} 次，{fs} ~ {ls}），"
                    "高度怀疑二层环路/聚合口异常/转发表震荡，建议立即排查并必要时隔离端口。"
                )
            elif lvl == "MEDIUM":
                one_line = (
                    f"MAC 漂移（{cnt} 次，{fs} ~ {ls}），"
                    "建议检查 STP 状态、聚合口配置一致性及上下联口。"
                )
            else:
                one_line = f"偶发 MAC 漂移（{cnt} 次），可能为主机迁移或短暂抖动，可继续观察。"
        else:
            if lvl == "HIGH":
                one_line = "高风险事件，可能对核心业务产生影响，建议立即确认并处理。"
            elif lvl == "MEDIUM":
                one_line = "存在一定风险，建议尽快确认影响范围与根因。"
            else:
                one_line = "当前风险较低，可先观察是否继续出现。"

        scored.append((score, lvl, e, one_line))

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
# Analyze (DeepSeek)
# -----------------------------
@app.post("/api/copilot/analyze", response_model=Analysis)
def copilot_analyze(req: AnalyzeRequest):
    e = store.get_event(req.event_id)
    if not e:
        raise HTTPException(status_code=404, detail="event not found")
    return deepseek_analyze(e, req)


@app.get("/api/incidents/{event_id}/timeline")
def incident_timeline(event_id: str):
    e = store.get_event(event_id)
    if not e:
        raise HTTPException(status_code=404, detail="event not found")
    analysis = deepseek_analyze(e, AnalyzeRequest(event_id=event_id, question="what_happened"))
    return {"event_id": event_id, "timeline": analysis.narrative_timeline}


# -----------------------------
# Chat (free mode)
# -----------------------------
@app.post("/api/copilot/chat", response_model=ChatResponse)
def copilot_chat(req: ChatRequest):
    msg = (req.message or "").strip()
    if not msg:
        return ChatResponse(reply="你还没输入问题。", focus=[], analysis=None)

    # selected event
    selected = None
    try:
        selected = (req.context or {}).get("selected_event_id")
    except Exception:
        selected = None

    if not selected:
        f = focus(top=1).items
        selected = f[0].event_id if f else None

    intent = detect_intent(msg)

    q = "free_chat"
    if intent in ("now_status", "status"):
        q = "now_status"
    elif intent in ("what_happened", "summary"):
        q = "what_happened"
    elif intent in ("impact", "urgency", "risk"):
        q = "impact"
    elif intent in ("next_steps", "actions"):
        q = "next_steps"
    elif intent in ("do_nothing", "consequence"):
        q = "do_nothing"

    analysis: Optional[Analysis] = None
    if selected:
        e = store.get_event(selected)
        if e:
            areq = AnalyzeRequest(
                event_id=selected,
                question=q,
                context={"intent": intent, "user_message": msg, "session_id": getattr(req, "session_id", None)},
            )
            analysis = deepseek_analyze(e, areq)

    reply = analysis.summary if analysis else "我还没有收到事件数据。你可以先 ingest 一些 syslog。"

    f_items = focus(top=3).items
    focus_payload = [{"event_id": i.event_id, "risk_level": i.risk_level, "title": i.title} for i in f_items]

    return ChatResponse(reply=reply, focus=focus_payload, analysis=analysis)