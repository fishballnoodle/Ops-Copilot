from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, ConfigDict


# =========================================================
# RiskLevel —— scoring.py 依赖
# =========================================================

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


# =========================================================
# 基础模型（事件/证据）
# =========================================================

class Source(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str = "switch"
    vendor: Optional[str] = None
    name: str
    id: Optional[str] = None


class Entity(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    name: str


class EvidenceLog(BaseModel):
    model_config = ConfigDict(extra="allow")
    log_id: str
    ts: str
    raw: str
    fields: Dict[str, Any] = Field(default_factory=dict)


class EvidenceMetric(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    value: float | int
    unit: Optional[str] = None
    ts: str


class Evidence(BaseModel):
    model_config = ConfigDict(extra="allow")
    logs: List[EvidenceLog] = Field(default_factory=list)
    metrics: List[EvidenceMetric] = Field(default_factory=list)


# =========================================================
# Event（支持 fingerprint / aggregate）
# =========================================================

class Event(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str
    ts: str

    source: Source
    category: str
    title: str
    severity_hint: Literal["INFO", "WARN", "ERROR"] = "INFO"

    entities: List[Entity] = Field(default_factory=list)
    labels: List[str] = Field(default_factory=list)

    evidence: Evidence = Field(default_factory=Evidence)

    fingerprint: Optional[str] = None
    aggregate: Optional[Dict[str, Any]] = None


# =========================================================
# Copilot / 分析模型（必须与 copilot.py 返回对齐）
# =========================================================

class AnalyzeRequest(BaseModel):
    event_id: str
    question: str
    context: Dict[str, Any] = Field(default_factory=dict)


class Risk(BaseModel):
    # copilot.py 里传的是 "LOW/MEDIUM/HIGH" 字符串
    level: str
    confidence: float
    impact: str
    spread: str


class PossibleCause(BaseModel):
    rank: int
    cause: str
    confidence: float = 0.0


class ActionSuggestion(BaseModel):
    priority: int
    action: str
    why: str


# 兼容 import ActionItem（copilot.py 虽然 import 但目前没用）
class ActionItem(ActionSuggestion):
    pass


class EvidenceRef(BaseModel):
    type: Literal["log", "metric"]
    id: Optional[str] = None
    name: Optional[str] = None
    ts: Optional[str] = None


class TimelineItem(BaseModel):
    ts: str
    note: str


# 兼容 TimelineNode 名称（如果其他地方 import）
class TimelineNode(TimelineItem):
    pass


class Analysis(BaseModel):
    summary: str

    risk: Optional[Risk] = None

    # ✅ copilot.py 实际返回的是 List[PossibleCause]
    possible_causes: List[PossibleCause] = Field(default_factory=list)

    # ✅ actions 返回 List[ActionSuggestion]
    actions: List[ActionSuggestion] = Field(default_factory=list)

    # ✅ evidence_refs 返回 List[EvidenceRef]
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)

    # ✅ narrative_timeline 返回 List[TimelineItem]
    narrative_timeline: List[TimelineItem] = Field(default_factory=list)

    should_page_someone: bool = False


# =========================================================
# API 模型（main.py 依赖）
# =========================================================

class IngestResponse(BaseModel):
    inserted: int
    event_ids: List[str] = Field(default_factory=list)


class FocusItem(BaseModel):
    event_id: str
    title: str
    risk_level: RiskLevel | str
    one_line: Optional[str] = None
    score: float = 0.0


class FocusResponse(BaseModel):
    items: List[FocusItem] = Field(default_factory=list)


class ChatRequest(BaseModel):
    # 兼容：有的前端会传 session_id，有的不会
    session_id: Optional[str] = None
    message: str
    context: Dict[str, Any] = Field(default_factory=dict)


class ChatResponse(BaseModel):
    reply: str
    focus: List[Dict[str, Any]] = Field(default_factory=list)
    analysis: Optional[Analysis] = None
