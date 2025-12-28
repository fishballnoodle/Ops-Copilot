from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from app.models import Event, RiskLevel


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    """
    兼容:
      - "2025-12-28T08:03:43.359999+00:00"
      - "2025-12-28T08:03:43.359999Z"
      - "2025-12-28T08:03:43.359999" (naive)
    """
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _severity_weight(sev: Optional[str]) -> float:
    s = (sev or "").upper()
    return {"INFO": 0.2, "WARN": 0.6, "ERROR": 1.0}.get(s, 0.4)


def _safe_len(x: Any) -> int:
    try:
        return len(x)  # type: ignore[arg-type]
    except Exception:
        return 0


def score_event(e: Event) -> Tuple[float, RiskLevel]:
    """
    统一评分入口（务必只保留这一份，不要再出现第二个同名函数！）

    返回:
      (score: float, level: "LOW"|"MEDIUM"|"HIGH")

    规则：
    1) MAC_FLAPPING：基于 aggregate.count + 事件持续时间 duration_s 做分级（可解释、演示友好）
    2) 其他事件：保留一个朴素、可解释的规则（severity/title/labels/evidence）
    """

    # ===== 聚合信息 =====
    agg: Dict[str, Any] = getattr(e, "aggregate", None) or {}
    count = int(agg.get("count") or 1)

    first_seen = _parse_ts(agg.get("first_seen") or getattr(e, "ts", None))
    last_seen = _parse_ts(agg.get("last_seen") or getattr(e, "ts", None))
    duration_s = 0.0
    if first_seen and last_seen:
        duration_s = max(0.0, (last_seen - first_seen).total_seconds())

    # ===== 字段归一化 =====
    cat = (getattr(e, "category", "") or "").upper()
    fp = (getattr(e, "fingerprint", "") or "").upper()
    title = (getattr(e, "title", "") or "").upper()

    # ==========================
    # 1) MAC_FLAPPING 专项评分
    # ==========================
    if "MAC_FLAPPING" in cat or "MAC_FLAPPING" in fp or "MAC_FLAPPING" in title:
        # 分数：次数 + 持续（加上上限，避免爆表）
        score = 10.0 + min(count, 200) * 2.0 + min(duration_s, 1800) * 0.05

        # 分级阈值（演示用清晰可解释）
        # - HIGH：次数很多且持续 >= 60s，倾向环路/聚合配置/接入侧异常
        # - MEDIUM：有明显重复且持续 >= 30s
        # - LOW：偶发/短时抖动
        if count >= 20 and duration_s >= 60:
            return score, "HIGH"
        if count >= 5 and duration_s >= 30:
            return score, "MEDIUM"
        return score, "LOW"

    # =================================
    # 2) 其他事件（朴素、可解释的评分）
    # =================================
    s = 0.0

    # severity_hint 如果不存在就当 INFO-ish
    s += _severity_weight(getattr(e, "severity_hint", None)) * 60

    t = (getattr(e, "title", "") or "").lower()
    if "link down" in t or (" down" in t and "shutdown" not in t):
        s += 25
    if "deny" in t or "attack" in t or "drop" in t or "blocked" in t:
        s += 30

    labels = getattr(e, "labels", None) or []
    labels_s = ",".join(labels).lower() if isinstance(labels, list) else str(labels).lower()
    if "core" in labels_s:
        s += 20

    # evidence 可能不存在（或结构不同），全部做容错
    ev = getattr(e, "evidence", None)
    if ev is not None:
        logs = getattr(ev, "logs", None)
        metrics = getattr(ev, "metrics", None)
        s += min(_safe_len(logs), 5) * 2
        s += min(_safe_len(metrics), 5) * 2

    if s >= 80:
        return s, "HIGH"
    if s >= 50:
        return s, "MEDIUM"
    return s, "LOW"