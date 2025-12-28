#!/usr/bin/env python3
from __future__ import annotations

import random
import time
import uuid
from datetime import datetime, timezone, timedelta
import requests

API = "http://127.0.0.1:8000/api/events/ingest"

TZ = timezone(timedelta(hours=8))  # Asia/Shanghai/Singapore 都是 +08

DEVICES = [
    {"type": "switch", "vendor": "H3C", "name": "H3C-6520", "id": "of:00017c1e0657624c"},
    {"type": "switch", "vendor": "H3C", "name": "H3C-5130", "id": "h3c:5130-core"},
    {"type": "fw", "vendor": "Generic", "name": "FW-01", "id": "fw:01"},
]

INTERFACES = ["Gi1/0/24", "Gi1/0/1", "Gi1/0/10", "Ten1/0/1", "XGE1/0/49"]
VLANS = ["VLAN11", "VLAN12", "VLAN10"]

TITLES = [
    ("interface", "WARN", lambda: f"{random.choice(INTERFACES)} link down"),
    ("interface", "INFO", lambda: f"{random.choice(INTERFACES)} link up"),
    ("routing", "WARN", lambda: "OSPF neighbor changed"),
    ("security", "ERROR", lambda: "deny policy hit spike"),
    ("system", "INFO", lambda: "CPU usage normal"),
]

def now_iso() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")

def mk_event() -> dict:
    dev = random.choice(DEVICES)
    category, sev, title_fn = random.choice(TITLES)
    title = title_fn()

    event_id = f"evt_{datetime.now(TZ).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    log_id = f"log_{uuid.uuid4().hex[:8]}"

    entities = []
    if "Gi" in title or "Ten" in title or "XGE" in title:
        # 粗暴提取接口名
        intf = title.split()[0]
        entities.append({"type": "interface", "name": intf})
    if random.random() < 0.35:
        entities.append({"type": "vlan", "name": random.choice(VLANS)})

    raw = f"{datetime.now(TZ).strftime('%b %d %H:%M:%S')} {dev['name']} {sev} {category}: {title}"

    # 偶尔给一点“证据指标”，让 AI timeline 更像真的
    metrics = []
    if category == "interface" and ("down" in title or "up" in title) and random.random() < 0.8:
        metrics.append({
            "name": "ifOperStatus",
            "value": 2 if "down" in title else 1,
            "unit": "enum",
            "ts": now_iso(),
        })

    labels = []
    if dev["name"].endswith("6520"):
        labels += ["core"]
    else:
        labels += ["edge", "access"]

    return {
        "event_id": event_id,
        "ts": now_iso(),
        "source": dev,
        "category": category,
        "title": title,
        "severity_hint": sev,
        "entities": entities,
        "labels": labels,
        "evidence": {
            "logs": [{
                "log_id": log_id,
                "ts": now_iso(),
                "raw": raw,
                "fields": {"program": "mock", "facility": "local7"},
            }],
            "metrics": metrics
        }
    }

def post_events(batch: list[dict]) -> None:
    r = requests.post(API, json=batch, timeout=5)
    r.raise_for_status()

def main():
    # 你可以通过环境变量调节频率；保持脚本极简
    interval = float(__import__("os").environ.get("FEED_INTERVAL", "1.0"))  # 秒
    batch_size = int(__import__("os").environ.get("BATCH_SIZE", "1"))

    print(f"[mock_feeder] posting to {API} interval={interval}s batch={batch_size}")
    while True:
        batch = [mk_event() for _ in range(batch_size)]
        try:
            post_events(batch)
        except Exception as e:
            print("[mock_feeder] post failed:", e)
        time.sleep(interval)

if __name__ == "__main__":
    main()

