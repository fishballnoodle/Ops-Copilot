#!/usr/bin/env python3
import os
import time
import json
import re
import requests
from datetime import datetime, timezone

# =========================
# Paths (ABSOLUTE, stable)
# =========================
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

LOG_PATH = "/opt/homebrew/var/log/rsyslog-remote.log"
API_URL = "http://127.0.0.1:8000/api/ingest/syslog"

STATE_PATH = os.path.join(PROJECT_ROOT, "data", "tail_ingest.state")  # ✅ 不再依赖 cwd

# 例：
# Dec 26 19:30:12 2025 YYLLS...:  %%IFNET/5/LINK_UPDOWN: GigabitEthernet1/0/1 link down.
LINE_RE = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<rest>.+)$")

LINK_RE = re.compile(
    r"(?:LINK_UPDOWN).*?(?P<intf>(?:GigabitEthernet|Ten-GigabitEthernet|XGigabitEthernet|Bridge-Aggregation)\S+)\s+link\s+(?P<state>up|down)",
    re.IGNORECASE
)

REBOOT_KW = ("reboot", "restart", "startup", "boot")
PSU_KW = ("power", "psu")
FAN_KW = ("fan",)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_offset() -> int:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return int((f.read().strip() or "0"))
    except Exception:
        return 0


def save_offset(off: int) -> None:
    state_dir = os.path.dirname(STATE_PATH)
    os.makedirs(state_dir, exist_ok=True)

    # ✅ 每个进程用自己的 tmp，避免冲突
    tmp = f"{STATE_PATH}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(str(off))
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp, STATE_PATH)


def post(payload: dict):
    r = requests.post(API_URL, headers={"Content-Type": "application/json"}, data=json.dumps(payload), timeout=2)
    r.raise_for_status()


def classify_h3c(msg: str, host: str):
    # 过滤 CLI 审计噪音
    if "%%10SHELL/" in msg:
        return None

    m = LINK_RE.search(msg)
    if m:
        intf = m.group("intf")
        state = m.group("state").lower()
        category = "SWITCH_LINK"
        title = f"{host} {intf} link {state}"
        fingerprint = f"h3c|{host}|{intf}|link_{state}"
        return category, title, fingerprint

    low = msg.lower()
    if any(k in low for k in REBOOT_KW):
        return "SWITCH_REBOOT", f"{host} reboot/startup", f"h3c|{host}|reboot"

    if any(k in low for k in PSU_KW):
        return "SWITCH_POWER", f"{host} power related", f"h3c|{host}|power"

    if any(k in low for k in FAN_KW):
        return "SWITCH_FAN", f"{host} fan related", f"h3c|{host}|fan"

    # 默认：普通 syslog（建议后续交给后端 parse_syslog 做更稳定聚合）
    category = "SYSLOG"
    title = f"{host} syslog: {msg[:80]}"
    fingerprint = f"syslog|{host}|{msg[:120]}"
    return category, title, fingerprint


def parse_line(line: str):
    line = line.rstrip("\n")
    m = LINE_RE.match(line)
    if not m:
        return ("unknown", "rsyslog", line, utc_now_iso())

    rest = m.group("rest")
    host = "unknown"
    msg = rest

    # "... <HOST>:  <MESSAGE>"
    if ": " in rest:
        left, right = rest.split(": ", 1)
        host = left.split()[-1]
        msg = right.strip()

    return (host, "syslog", msg, utc_now_iso())


def main():
    print(f"[tail_ingest] PROJECT_ROOT = {PROJECT_ROOT}")
    print(f"[tail_ingest] STATE_PATH   = {STATE_PATH}")
    print(f"[tail_ingest] LOG_PATH     = {LOG_PATH}")
    print(f"[tail_ingest] API_URL      = {API_URL}")

    while not os.path.exists(LOG_PATH):
        print(f"[tail_ingest] waiting for {LOG_PATH} ...")
        time.sleep(1)

    offset = load_offset()

    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        # 文件被轮转/截断时，offset 可能超过文件大小
        f.seek(0, os.SEEK_END)
        end = f.tell()
        if offset > end:
            offset = 0

        f.seek(offset, os.SEEK_SET)
        last_save = time.time()

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            host, program, msg, ts = parse_line(line)
            classified = classify_h3c(msg, host)
            if classified is None:
                continue

            category, title, fingerprint = classified
            payload = {
                "timestamp": ts,
                "host": host,
                "program": program,
                "msg": msg,
                "category": category,
                "title": title,
                "fingerprint": fingerprint,
            }

            ok = False
            for i in range(3):
                try:
                    post(payload)
                    ok = True
                    break
                except Exception:
                    time.sleep(0.3 * (i + 1))

            if ok:
                offset = f.tell()
                if time.time() - last_save > 1.0:
                    try:
                        save_offset(offset)
                    except Exception as e:
                        # 不要让 offset 写入失败把 ingest 搞挂
                        print(f"[tail_ingest] WARN save_offset failed: {e}")
                    last_save = time.time()


if __name__ == "__main__":
    main()