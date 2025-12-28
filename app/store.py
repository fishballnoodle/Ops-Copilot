from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
import uuid
from app.models import Event


from datetime import datetime, timezone

def _parse_ts(s: str) -> datetime:
    """
    Always return timezone-aware datetime in UTC.
    Accepts ISO8601 with/without timezone.
    """
    if not s:
        return datetime.now(timezone.utc)

    # 允许 "Z"
    s2 = s.strip().replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(s2)
    except Exception:
        # 兜底：不认识就当现在
        return datetime.now(timezone.utc)

    # naive -> assume UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    # normalize to UTC
    return dt.astimezone(timezone.utc)



@dataclass
class _AggRecord:
    event_id: str                 # 当前聚合事件的主 event_id（展示用）
    fingerprint: str
    count: int
    first_seen: str
    last_seen: str


class InMemoryStore:
    def __init__(self) -> None:
        # event_id -> Event（用于 /api/events 原始查看）
        self._events: Dict[str, Event] = {}

        # fingerprint -> _AggRecord（用于聚合）
        self._agg: Dict[str, _AggRecord] = {}

        # fingerprint -> Event（用于 focus/top3 展示：存一份“聚合视图事件”）
        self._agg_event: Dict[str, Event] = {}

    def ingest_event(self, event: dict) -> dict:
        """
        Accepts a raw event and stores it using existing store primitives.
        Returns the stored/normalized event.
        """
        # 1) 补齐 event_id（如果你系统已有 event_id 生成逻辑，可替换）
        event_id = event.get("event_id") or f"evt_{uuid.uuid4().hex[:12]}"
        event["event_id"] = event_id

        # 2) 补齐时间（如果你系统用 first_seen/last_seen 聚合，这里可以先只给 timestamp）
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

        # 3) 调用你 store 里现有的“写入”方法
        # 你需要在下面三行里，把 add/append/put 的真实函数名对齐成你项目已有的那个
        if hasattr(self, "add"):
            self.add(event)
        elif hasattr(self, "append"):
            self.append(event)
        elif hasattr(self, "put_event"):
            self.put_event(event)
        else:
            # 最保守：直接塞进一个列表/字典（按你 store 的字段名改）
            # 假设你有 self.events: dict
            if hasattr(self, "events") and isinstance(self.events, dict):
                self.events[event_id] = event
            else:
                raise AttributeError("No writable method found in InMemoryStore")

        return event

    def upsert_events(self, events: List[Event]) -> List[str]:
        inserted_ids: List[str] = []

        for e in events:
            # 1) 原始事件入库（按 event_id）
            self._events[e.event_id] = e
            inserted_ids.append(e.event_id)

            fp = (e.fingerprint or "").strip()

            # 2) 没 fingerprint：就不做聚合（仍然保留原始事件）
            if not fp:
                continue

            # 3) 聚合：第一次见
            if fp not in self._agg:
                first = e.ts
                last = e.ts
                self._agg[fp] = _AggRecord(
                    event_id=e.event_id,
                    fingerprint=fp,
                    count=1,
                    first_seen=first,
                    last_seen=last,
                )
                # 聚合视图事件：用第一条事件做 base
                agg_e = e.model_copy(deep=True)
                agg_e.aggregate = {"count": 1, "first_seen": first, "last_seen": last}
                agg_e.fingerprint = fp
                self._agg_event[fp] = agg_e
                continue

            # 4) 聚合：更新 count/last_seen，并把展示 event_id 也更新成最新一条
            rec = self._agg[fp]
            rec.count += 1
            # first_seen 保持最早
            if _parse_ts(e.ts) < _parse_ts(rec.first_seen):
                rec.first_seen = e.ts
            # last_seen 更新为最新
            if _parse_ts(e.ts) > _parse_ts(rec.last_seen):
                rec.last_seen = e.ts
                rec.event_id = e.event_id

            # 5) 同步到聚合视图事件（这是 focus/top3 看到的内容）
            agg_e = self._agg_event[fp]
            agg_e.aggregate = {
                "count": rec.count,
                "first_seen": rec.first_seen,
                "last_seen": rec.last_seen,
            }
            agg_e.event_id = rec.event_id  # 展示时指向最新一条 event
            agg_e.ts = rec.last_seen       # ts 也用 last_seen 更直观

        return inserted_ids

    def list_events(self, limit: int = 20) -> List[Event]:
        # 返回“聚合视图事件”为主（你页面更像事件平台）
        items = list(self._agg_event.values())

        # 没 fingerprint 的原始事件，也要展示出来（避免丢数据）
        for e in self._events.values():
            if not (e.fingerprint or "").strip():
                items.append(e)

        items.sort(key=lambda x: _parse_ts((x.aggregate or {}).get("last_seen") or x.ts), reverse=True)
        return items[:limit]

    def recent_events(self, limit: int = 50) -> List[Event]:
        # focus 评分最好用聚合事件（count 高的自然更“值得看”）
        items = list(self._agg_event.values())
        items.sort(key=lambda x: _parse_ts((x.aggregate or {}).get("last_seen") or x.ts), reverse=True)
        return items[:limit]

    def get_event(self, event_id: str) -> Optional[Event]:
        # 先从原始事件里找
        e = self._events.get(event_id)
        if e:
            return e

        # 再从聚合视图里找（如果传进来的是聚合视图 event_id）
        for agg_e in self._agg_event.values():
            if agg_e.event_id == event_id:
                return agg_e
        return None
