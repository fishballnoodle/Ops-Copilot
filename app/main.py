from __future__ import annotations

import os
import re
import json
import uuid
import time
import traceback
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Body
from fastapi.middleware.cors import CORSMiddleware

import app.store as store_mod
from app.store import InMemoryStore
from app.models import (
    Event, IngestResponse, FocusResponse, FocusItem,
    AnalyzeRequest, ChatRequest, ChatResponse, Analysis,
)
from tools.desensitizer import Desensitizer, DesensitizeConfig

from app.scoring import score_event
from app.copilot import detect_intent
from app.copilot_deepseek import deepseek_analyze
from app.llm import call_llm_json, json_safe  # 需要你 llm.py 里存在这两个


try:
    from tools.desensitizer import Desensitizer, DesensitizeConfig
except Exception:
    Desensitizer = None  # type: ignore
    DesensitizeConfig = None  # type: ignore

def _build_des():
    enable = os.environ.get("ENABLE_DESENSITIZE", "1").lower() not in ("0", "false", "no")
    if not enable or Desensitizer is None:
        return None
    secret = os.environ.get("OPS_DESENSE_SECRET", "") or "WEAK_DEFAULT_SECRET_CHANGE_ME"
    cfg = DesensitizeConfig(
        secret_key=secret,
        reversible=os.environ.get("DESENSITIZE_REVERSIBLE", "0").lower() in ("1", "true", "yes"),
        mapping_path=os.environ.get("DESENSITIZE_MAP_PATH", "data/desensitize_map.json"),
        keep_private_ranges=os.environ.get("KEEP_PRIVATE_RANGES", "0").lower() in ("1", "true", "yes"),
    )
    return Desensitizer(cfg)

DES = _build_des()

def _mask_text(s: str) -> str:
    if not DES or not s:
        return s
    out, _ = DES.desensitize_line(s + "\n")
    return out.rstrip("\n")

def _mask_obj(obj: Any):
    if DES is None:
        return obj
    if obj is None:
        return None
    if isinstance(obj, str):
        return _mask_text(obj)
    if isinstance(obj, list):
        return [_mask_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _mask_obj(v) for k, v in obj.items()}
    return obj


# syslog parser（如果你项目里有）
try:
    from app.ingest.syslog import parse_syslog
except Exception:
    parse_syslog = None



def _build_des():
    enable = os.environ.get("ENABLE_DESENSITIZE", "1").lower() not in ("0","false","no")
    if not enable:
        return None
    secret = os.environ.get("OPS_DESENSE_SECRET","") or "WEAK_DEFAULT_SECRET_CHANGE_ME"
    cfg = DesensitizeConfig(
        secret_key=secret,
        reversible=os.environ.get("DESENSITIZE_REVERSIBLE","0").lower() in ("1","true","yes"),
        mapping_path=os.environ.get("DESENSITIZE_MAP_PATH","data/desensitize_map.json"),
        keep_private_ranges=os.environ.get("KEEP_PRIVATE_RANGES","0").lower() in ("1","true","yes"),
    )
    return Desensitizer(cfg)

DES = _build_des()

def _mask_text(s: str) -> str:
    if not DES or not s:
        return s
    out, _ = DES.desensitize_line(s + "\n")
    return out.rstrip("\n")

def _mask_obj(obj):
    """递归脱敏 dict/list/str，保证 raw 也不会漏。"""
    if DES is None:
        return obj
    if obj is None:
        return None
    if isinstance(obj, str):
        return _mask_text(obj)
    if isinstance(obj, list):
        return [_mask_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _mask_obj(v) for k, v in obj.items()}
    return obj

# =============================
# LLM Ledger (minimal JSONL)
# =============================
LEDGER_PATH = os.getenv("LLM_LEDGER_JSONL", "./data/llm_usage.jsonl")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_parent(path: str):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


def ledger_record(
    *,
    ts: str,
    ok: bool,
    action: str,
    endpoint: str,
    latency_ms: int,
    total_tokens: int = 0,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    event_id: Optional[str] = None,
    intent: Optional[str] = None,
    error: Optional[str] = None,
):
    """写一条 LLM 使用记录到 JSONL（不影响主流程）。"""
    try:
        _ensure_parent(LEDGER_PATH)
        row = {
            "ts": ts,
            "ok": bool(ok),
            "action": action,
            "endpoint": endpoint,
            "latency_ms": int(latency_ms),
            "total_tokens": int(total_tokens or 0),
            "prompt_tokens": int(prompt_tokens or 0),
            "completion_tokens": int(completion_tokens or 0),
            "event_id": event_id,
            "intent": intent,
            "error": error,
        }
        with open(LEDGER_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _read_ledger_lines(window_s: int) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if not os.path.exists(LEDGER_PATH):
        return items

    cutoff = time.time() - float(window_s)
    try:
        with open(LEDGER_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        for line in reversed(lines[-5000:]):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            ts = row.get("ts")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if dt.timestamp() < cutoff:
                        break
                except Exception:
                    pass
            items.append(row)
    except Exception:
        return []
    return items


def ledger_usage(window_s: int = 3600, limit: int = 50) -> Dict[str, Any]:
    items = _read_ledger_lines(window_s)
    return {
        "ok": True,
        "generated_at": _now_iso(),
        "window_s": int(window_s),
        "items": items[: int(limit)],
    }


def ledger_summary(window_s: int = 3600) -> Dict[str, Any]:
    items = _read_ledger_lines(window_s)

    calls = len(items)
    errors = sum(1 for x in items if not x.get("ok"))
    total_tokens = sum(int(x.get("total_tokens") or 0) for x in items)
    avg_latency = int(sum(int(x.get("latency_ms") or 0) for x in items) / calls) if calls else 0

    by_action: Dict[str, Dict[str, Any]] = {}
    by_endpoint: Dict[str, Dict[str, Any]] = {}

    def acc(m: Dict[str, Dict[str, Any]], key: str, row: Dict[str, Any]):
        if key not in m:
            m[key] = {"calls": 0, "errors": 0, "tokens": 0, "avg_latency_ms": 0}
        m[key]["calls"] += 1
        if not row.get("ok"):
            m[key]["errors"] += 1
        m[key]["tokens"] += int(row.get("total_tokens") or 0)

    for r in items:
        acc(by_action, str(r.get("action") or "-"), r)
        acc(by_endpoint, str(r.get("endpoint") or "-"), r)

    def finalize(m: Dict[str, Dict[str, Any]], key_field: str):
        tmp_lat: Dict[str, int] = {}
        tmp_cnt: Dict[str, int] = {}
        for r in items:
            k = str(r.get(key_field) or "-")
            tmp_lat[k] = tmp_lat.get(k, 0) + int(r.get("latency_ms") or 0)
            tmp_cnt[k] = tmp_cnt.get(k, 0) + 1
        for k, v in m.items():
            c = tmp_cnt.get(k, 0) or 1
            v["avg_latency_ms"] = int(tmp_lat.get(k, 0) / c)

    finalize(by_action, "action")
    finalize(by_endpoint, "endpoint")

    return {
        "ok": True,
        "generated_at": _now_iso(),
        "summary": {
            "window_s": int(window_s),
            "calls": int(calls),
            "errors": int(errors),
            "total_tokens": int(total_tokens),
            "avg_latency_ms": int(avg_latency),
            "by_action": by_action,
            "by_endpoint": by_endpoint,
        },
    }


# =============================
# Evidence Store (Way 3)
# =============================
@dataclass
class EvidenceItem:
    id: str
    ts: str
    source: str
    kind: str
    host: str
    user: Optional[str]
    msg: str
    tags: List[str]
    event_id: Optional[str]
    fingerprint: Optional[str]
    raw: Dict[str, Any]


# 先用内存存，demo 足够；后续你要落盘/ES 再换
EVIDENCE: List[EvidenceItem] = []


def _safe_iso(ts: Optional[str]) -> str:
    if not ts:
        return _now_iso()
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return _now_iso()


def _dt(ts: str) -> datetime:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


# =============================
# App
# =============================
print("STORE MODULE PATH =", store_mod.__file__)

app = FastAPI(title="Ops Copilot API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # demo 放开
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = InMemoryStore()
print("STORE INSTANCE TYPE =", type(store))
print("STORE HAS ingest_event =", hasattr(store, "ingest_event"))


# -----------------------------
# helpers
# -----------------------------
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
    s = re.sub(r"^%[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}:\d{3}\s+\d{4}\s+H3C\s+", "H3C ", s)
    s = re.sub(r"^%[A-Za-z]{3}\s+\d{1,2}\s+", "%MON DAY ", s)
    return s


# =============================
# Health
# =============================
@app.get("/api/health")
def health():
    llm = "deepseek" if os.getenv("DEEPSEEK_API_KEY") else "mock"
    return {"status": "ok", "llm": llm, "version": app.version}


# =============================
# LLM Ledger APIs
# =============================
@app.get("/api/llm/summary")
def api_llm_summary(window_s: int = 3600):
    return ledger_summary(window_s=window_s)


@app.get("/api/llm/usage")
def api_llm_usage(window_s: int = 3600, limit: int = 50):
    return ledger_usage(window_s=window_s, limit=limit)


# =============================
# Evidence APIs  ✅（你缺的就是这个）
# =============================
@app.post("/api/evidence/ingest")
async def evidence_ingest(req: Request):
    """
    Way 3 的入口：FortiGate / 行为管理 / AD / VPN 等日志先作为 evidence 进入系统。

    推荐 payload 字段（不强制）：
    {
      "timestamp": "...ISO...",
      "source": "fortigate|ueba|ad|vpn|proxy|... ",
      "kind": "TRAFFIC|AUTH|ALERT|VPN|UEBA|...",
      "host": "设备名/域控名",
      "user": "用户名(可选)",
      "msg": "一行描述/原始消息",
      "tags": ["blocked","failed_login",...],
      "event_id": "如果你明确知道关联哪个事件就传；否则先不传",
      "fingerprint": "可选，用于 evidence 去重/聚合",
      "raw": {...原始结构...}
    }
    """

    payload = await req.json()

    host = _mask_text(str(payload.get("host") or "unknown"))
    user = _mask_text(str(payload.get("user") or "")) if payload.get("user") else None
    msg = _mask_text(str(payload.get("msg") or payload.get("message") or ""))

    # ✅ raw 一律存脱敏后的
    raw_in = payload.get("raw") or payload
    raw = _mask_obj(dict(raw_in))  # recursive mask

    item = EvidenceItem(
        id=f"evd_{uuid.uuid4().hex[:12]}",
        ts=_safe_iso(payload.get("timestamp")),
        source=str(payload.get("source") or "unknown"),
        kind=str(payload.get("kind") or "evidence"),
        host=host,
        user=user,
        msg=msg,
        tags=list(payload.get("tags") or []),
        event_id=payload.get("event_id"),
        fingerprint=payload.get("fingerprint"),
        raw=raw,
    )
    EVIDENCE.append(item)
    # 控制内存：只保留最后 5000 条
    if len(EVIDENCE) > 5000:
        del EVIDENCE[: len(EVIDENCE) - 5000]

    return {"ok": True, "id": item.id}


@app.get("/api/evidence")
def evidence_list(
    window_s: int = 3600,
    limit: int = 50,
    event_id: Optional[str] = None,
):
    """
    取 evidence：默认最近 1 小时。
    如果传 event_id，则只返回已显式关联的 evidence。
    """
    cutoff = datetime.fromtimestamp(time.time() - float(window_s), tz=timezone.utc)
    items = []
    for it in reversed(EVIDENCE):
        dt = _dt(it.ts)
        if dt < cutoff:
            break
        if event_id and it.event_id != event_id:
            continue
        items.append(asdict(it))
        if len(items) >= int(limit):
            break

    return {"ok": True, "generated_at": _now_iso(), "window_s": int(window_s), "items": items}


# =============================
# Ingest Syslog
# =============================
@app.post("/api/ingest/syslog")
async def ingest_syslog(req: Request):
    payload = await req.json()

    host_raw = payload.get("host") or "unknown"
    program_raw = payload.get("program") or "syslog"
    msg_raw = payload.get("msg") or ""
    ts = payload.get("timestamp") or datetime.now(timezone.utc).isoformat()

    # ✅ 先脱敏基础字段（后续所有派生字段都用脱敏后的）
    host = _mask_text(str(host_raw))
    program = _mask_text(str(program_raw))
    msg = _mask_text(str(msg_raw))

    parsed = {}
    if parse_syslog:
        try:
            # ⚠️ parse_syslog 用脱敏后的 msg（避免 parsed 里再带回明文）
            parsed = parse_syslog(msg) or {}
        except Exception:
            parsed = {}

    category = payload.get("category") or parsed.get("category") or "SYSLOG"

    # ✅ title/fingerprint 也必须脱敏（尤其 fingerprint 你现在会拼 msg）
    title_raw = payload.get("title") or parsed.get("title") or f"{host} {program}: {msg[:80]}".strip()
    title = _mask_text(str(title_raw))

    fp_raw = (
        payload.get("fingerprint")
        or parsed.get("fingerprint")
        or f"syslog|{host}|{program}|{_fingerprint_fallback(msg)[:140]}"
    )
    fp = _mask_text(str(fp_raw))

    # ✅ raw 只能存脱敏后的：message/msg/payload/parsed 全递归脱敏
    #    注意：payload 里原本可能带着明文 msg/host/program，所以要覆盖后再 mask
    payload_safe = dict(payload)
    payload_safe["host"] = host
    payload_safe["program"] = program
    payload_safe["msg"] = msg
    payload_safe["title"] = title
    payload_safe["fingerprint"] = fp
    payload_safe = _mask_obj(payload_safe)

    parsed_safe = _mask_obj(parsed)

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
        raw={
            "message": msg,
            "payload": payload_safe,
            "parsed": parsed_safe,
        },
    )

    store.upsert_events([e])
    return {"ok": True, "event_id": e.event_id, "fingerprint": fp, "title": title, "category": category}

# =============================
# Events APIs
# =============================
@app.post("/api/events/ingest", response_model=IngestResponse)
def ingest(events: list[Event]):
    ids = store.upsert_events(events)
    return IngestResponse(inserted=len(ids), event_ids=ids)


@app.get("/api/events", response_model=list[Event])
def list_events(limit: int = 20):
    try:
        return store.list_events(limit=limit)
    except TypeError:
        if hasattr(store, "recent_events"):
            items = store.recent_events(limit=limit)  # type: ignore
        else:
            items = store.list_events(limit=limit)
        items = list(items)
        items.sort(key=_event_sort_key, reverse=True)
        return items


# =============================
# Focus
# =============================
@app.get("/api/focus", response_model=FocusResponse)
def focus(top: int = 3):
    events = store.recent_events(limit=50)

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
                    "高度怀疑二层环路、聚合口异常或转发表震荡，建议立即排查并必要时隔离端口。"
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


# =============================
# Briefing (LLM JSON)
# =============================
@app.get("/api/copilot/briefing")
def copilot_briefing(top: int = 3, window: str = "last_1h"):
    try:
        if hasattr(store, "recent_events"):
            focus_items = store.recent_events(top)
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
                "aggregate": agg,
            }

        events_for_llm = [to_llm(e) for e in focus_items]
        briefing = call_llm_json(events_for_llm=events_for_llm, window=window)

        ledger_record(
            ts=_now_iso(),
            ok=bool(briefing.get("ok", True)),
            action="briefing",
            endpoint="/api/copilot/briefing",
            latency_ms=int((briefing.get("_meta", {}) or {}).get("latency_ms") or 0),
            total_tokens=int(((briefing.get("_meta", {}) or {}).get("usage") or {}).get("total_tokens") or 0),
            prompt_tokens=int(((briefing.get("_meta", {}) or {}).get("usage") or {}).get("prompt_tokens") or 0),
            completion_tokens=int(((briefing.get("_meta", {}) or {}).get("usage") or {}).get("completion_tokens") or 0),
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


# =============================
# Analyze (DeepSeek)
# =============================
@app.post("/api/copilot/analyze", response_model=Analysis)
def copilot_analyze(req: AnalyzeRequest):
    e = store.get_event(req.event_id)
    if not e:
        raise HTTPException(status_code=404, detail="event not found")

    t0 = time.time()
    try:
        req.context = json_safe(getattr(req, "context", None) or {})
        out = deepseek_analyze(e, req)
        latency_ms = int((time.time() - t0) * 1000)
        ledger_record(
            ts=_now_iso(),
            ok=True,
            action=f"analyze:{req.question}",
            endpoint="/api/copilot/analyze",
            latency_ms=latency_ms,
            event_id=req.event_id,
            intent=(req.context or {}).get("intent"),
        )
        return out
    except Exception as ex:
        latency_ms = int((time.time() - t0) * 1000)
        ledger_record(
            ts=_now_iso(),
            ok=False,
            action=f"analyze:{req.question}",
            endpoint="/api/copilot/analyze",
            latency_ms=latency_ms,
            event_id=req.event_id,
            intent=(getattr(req, "context", None) or {}).get("intent"),
            error=str(ex),
        )
        raise


@app.get("/api/incidents/{event_id}/timeline")
def incident_timeline(event_id: str):
    e = store.get_event(event_id)
    if not e:
        raise HTTPException(status_code=404, detail="event not found")
    analysis = deepseek_analyze(e, AnalyzeRequest(event_id=event_id, question="what_happened"))
    return {"event_id": event_id, "timeline": analysis.narrative_timeline}


# =============================
# Chat (DeepSeek)
# =============================
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
    t0 = time.time()
    try:
        if selected:
            e = store.get_event(selected)
            if e:
                areq = AnalyzeRequest(
                    event_id=selected,
                    question=q,
                    context={"intent": intent, "user_message": msg},
                )
                areq.context = json_safe(areq.context)
                analysis = deepseek_analyze(e, areq)

        latency_ms = int((time.time() - t0) * 1000)
        ledger_record(
            ts=_now_iso(),
            ok=True,
            action=f"chat:{q}",
            endpoint="/api/copilot/chat",
            latency_ms=latency_ms,
            event_id=selected,
            intent=intent,
        )

    except Exception as ex:
        latency_ms = int((time.time() - t0) * 1000)
        ledger_record(
            ts=_now_iso(),
            ok=False,
            action=f"chat:{q}",
            endpoint="/api/copilot/chat",
            latency_ms=latency_ms,
            event_id=selected,
            intent=intent,
            error=str(ex),
        )
        raise HTTPException(status_code=500, detail=str(ex))

    reply = analysis.summary if analysis else "我还没有收到事件数据。你可以先 ingest 一些 syslog/event。"
    f_items = focus(top=3).items
    focus_payload = [{"event_id": i.event_id, "risk_level": i.risk_level, "title": i.title} for i in f_items]
    return ChatResponse(reply=reply, focus=focus_payload, analysis=analysis)