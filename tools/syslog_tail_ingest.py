#!/usr/bin/env python3
import time
import hashlib
import requests
import traceback
from pathlib import Path
from typing import Iterator


# ✅ 改成你的真实日志文件路径
LOG_FILE = Path("/Users/hongyi.ou01/Downloads/ForwardTrafficLog-memory-2025-12-24T19_18_49.841176.log")

API_URL = "http://127.0.0.1:8000/api/events/ingest"
REPLAY_LAST_LINES = 200          # 启动时回放最后 N 行
POLL_INTERVAL = 0.3              # tail 轮询间隔（秒）


def fingerprint(kv: dict) -> str:
    # 聚合指纹：别包含 action / time，避免“看起来一样但聚合不了”
    parts = [
        kv.get("srcip", "unknown"),
        kv.get("dstip", "unknown"),
        kv.get("dstport", "0"),
        kv.get("policyid", "0"),
    ]
    raw = "|".join(parts)
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def parse_kv(line: str) -> dict:
    kv = {}
    for item in line.strip().split():
        if "=" not in item:
            continue
        k, v = item.split("=", 1)
        kv[k] = v.strip('"')
    return kv


def build_event(line: str) -> dict:
    kv = parse_kv(line)

    # FortiGate 示例：date/time 组合；没有就给个兜底
    date = kv.get("date", "2025-01-01")
    tm = kv.get("time", "00:00:00")
    ts = f"{date}T{tm}"



    fp = fingerprint(kv)

    # event_id 使用 fp + 当前秒，避免重复 id
    event_id = f"fw_{fp}_{int(time.time())}"

    title = (
        f"{kv.get('action')} {kv.get('service')} "
        f"{kv.get('srcip')}:{kv.get('srcport')} → "
        f"{kv.get('dstip')}:{kv.get('dstport')} "
        f"(policy {kv.get('policyid')})"
    )

    event = {
        "event_id": event_id,
        "ts": ts,
        "source": {"type": "firewall", "vendor": "Fortinet", "name": "FW", "id": None},
        "category": "security",
        "title": title,
        "severity_hint": "ERROR" if kv.get("action") == "deny" else "INFO",
        "entities": [
            {"type": "ip", "name": kv.get("srcip", "unknown")},
            {"type": "ip", "name": kv.get("dstip", "unknown")},
            {"type": "service", "name": kv.get("service", "unknown")},
        ],
        "labels": ["fortigate", kv.get("type", "traffic"), kv.get("subtype", "forward")],
        "evidence": {
            "logs": [{
                "log_id": f"log_{fp}",
                "ts": ts,
                "raw": line.strip(),
                "fields": kv,
            }],
            "metrics": [],
        },
        "fingerprint": fp,
        "aggregate": {"count": 1, "first_seen": ts, "last_seen": ts},
    }
    return event


def iter_tail(path: Path, replay_last: int) -> Iterator[str]:
    """
    先回放最后 N 行，再实时 tail 追加内容
    """
    # 1) 回放
    try:
        lines = path.read_text(errors="ignore").splitlines()
        for ln in lines[-replay_last:]:
            if ln.strip():
                yield ln + "\n"
    except Exception:
        pass

    # 2) 实时 tail（从文件末尾开始）
    with path.open(errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL)
                continue
            yield line


def post_events(batch: list[dict]) -> None:
    r = requests.post(API_URL, json=batch, timeout=5)
    print(f"📡 POST {r.status_code} inserted? {r.text[:200]}")
    r.raise_for_status()


def main() -> None:
    print("🔥 SYSLOG TAIL INGEST START")
    print("📄 LOG FILE:", LOG_FILE)
    print("🌐 API:", API_URL)
    print("🔁 REPLAY_LAST_LINES:", REPLAY_LAST_LINES)

    if not LOG_FILE.exists():
        print("❌ LOG FILE NOT FOUND:", LOG_FILE)
        return

    for line in iter_tail(LOG_FILE, REPLAY_LAST_LINES):
        try:
            if not line.strip():
                continue

            event = build_event(line)
            print("📥 RAW:", line.strip()[:160])
            print("📦 EVENT:", event["event_id"], "fp=", event["fingerprint"])

            post_events([event])

        except Exception as e:
            print("❌ INGEST ERROR:", e)
            traceback.print_exc()


if __name__ == "__main__":
    main()
