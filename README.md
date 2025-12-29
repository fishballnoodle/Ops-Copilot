# Ops Copilot (v1.0)

An AI-first operations copilot for network & infrastructure teams.

This is a **runnable, minimal, end-to-end prototype** that demonstrates:

- Real syslog ingestion & fingerprint aggregation
- Risk scoring with explainable rules
- LLM-powered incident analysis (DeepSeek)
- Token & cost observability (1-hour rolling window)
- A single-page Ops Copilot Console

> ⚠️ This is **not a SaaS product**, but a working engineering prototype.

---

## Features

- Syslog ingestion (`/api/ingest/syslog`)
- Event aggregation by stable fingerprint
- Focus view (Top-N most important events)
- AI analysis: what happened / impact / next steps
- Free-form Copilot chat (LLM-backed)
- LLM usage & cost tracking (by action)

---

## Architecture

```text
Syslog → Ingest → Fingerprint → Aggregate
                     ↓
                 Focus / Score
                     ↓
              LLM Analyze / Chat
                     ↓
          Token & Cost Observability
