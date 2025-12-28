from __future__ import annotations

from typing import Optional
from app.models import Analysis, AnalyzeRequest, Event, Risk, PossibleCause, ActionItem, EvidenceRef, TimelineItem
from app.scoring import score_event
from app.models import ActionSuggestion, TimelineItem


def mock_analyze(event: Event, req: AnalyzeRequest) -> Analysis:
    score, level = score_event(event)

    # 不同 question 给不同侧重点（但保持结构一致）
    if req.question == "now_status":
        summary = "整体状态：基本稳定。过去几分钟内出现 1 个需要关注的事件。"
    elif req.question == "what_happened":
        summary = f"检测到事件：{event.source.name} 上 {event.title}。这通常代表链路/对端状态发生变化。"
    elif req.question == "impact":
        summary = "当前未见核心链路扩散迹象，但若该接口承载关键终端/业务，可能造成局部不可用。"
    elif req.question == "next_steps":
        summary = "建议先做最快速的确认动作，再决定是否升级处理。"
    else:  # do_nothing
        summary = "短期内大概率不会影响整体，但若持续存在且涉及关键接入，风险会逐步增大。"

    # 证据引用
    evidence_refs = []
    if event.evidence.logs:
        evidence_refs.append(EvidenceRef(type="log", id=event.evidence.logs[0].log_id))
    if event.evidence.metrics:
        m = event.evidence.metrics[0]
        evidence_refs.append(EvidenceRef(type="metric", name=m.name, ts=m.ts))

    # 根因 & 动作（可做成规则+模板，后续再接 LLM）
    causes = [
        PossibleCause(rank=1, cause="对端设备掉电/重启或端口被拔", confidence=0.55),
        PossibleCause(rank=2, cause="线缆/模块/水晶头接触不良", confidence=0.25),
        PossibleCause(rank=3, cause="人为 shutdown 或变更影响", confidence=0.20),
    ]

    actions = [
        ActionSuggestion(
            priority=1,
            action="确认防火墙策略命中情况",
            why="最快缩小问题影响范围",
        ),
        ActionSuggestion(
            priority=2,
            action="核查近期网络或策略变更",
            why="确认是否为计划内变更导致",
        ),
        ActionSuggestion(
            priority=3,
            action="评估是否需要临时放通策略",
            why="降低潜在业务影响",
        ),
    ]

    timeline = [
        TimelineItem(
            ts=event.ts,
            note=f"检测到事件：{event.title}",
        ),
        TimelineItem(
            ts=event.ts,
            note="建议先确认对端设备与变更记录",
        ),
    ]
    if event.evidence.metrics:
        timeline.append(TimelineItem(ts=event.evidence.metrics[0].ts, note="补充证据：指标/状态确认"))
    timeline.append(TimelineItem(ts=event.ts, note="AI：暂未发现扩散，建议先确认对端与变更记录"))

    should_page = (level == "HIGH" and score >= 90)

    return Analysis(
        summary=summary,
        risk=Risk(
            level=level,
            confidence=0.55 if level == "LOW" else (0.72 if level == "MEDIUM" else 0.82),
            impact="局部终端/接入侧可能中断" if level != "LOW" else "轻微或无明显影响",
            spread="未发现扩散迹象",
        ),
        possible_causes=causes,
        actions=actions[:5],
        evidence_refs=evidence_refs,
        narrative_timeline=timeline,
        should_page_someone=should_page,
    )


# 预留：未来接真实 LLM（OpenAI/DeepSeek/本地模型）
# 你只要实现这个函数，然后在 main.py 里切换 use_llm=True
def llm_analyze(event: Event, req: AnalyzeRequest) -> Analysis:
    raise NotImplementedError("LLM analyze not wired yet. Use mock_analyze for now.")

def detect_intent(q: str) -> str:
    s = (q or "").lower()
    if any(k in s for k in ["影响", "紧急", "风险", "严重", "urgency", "impact", "risk"]):
        return "impact_urgency"
    if any(k in s for k in ["下一步", "怎么做", "排查", "处理", "next", "triage", "mitigate"]):
        return "next_steps"
    if any(k in s for k in ["发生", "怎么回事", "原因", "why", "what happened"]):
        return "what_happened"
    if any(k in s for k in ["不处理", "暂时不", "忽略", "会怎样", "if ignore", "do nothing"]):
        return "if_ignore"
    if any(k in s for k in ["现在", "状态", "总体", "health", "status"]):
        return "status_now"
    return "freeform"