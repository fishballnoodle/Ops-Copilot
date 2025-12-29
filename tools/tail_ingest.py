#!/usr/bin/env python3
import os
import time
import json
import re
import requests
from datetime import datetime, timezone

LOG_PATH = "/opt/homebrew/var/log/rsyslog-remote.log"
API_URL = "http://127.0.0.1:8000/api/ingest/syslog"
STATE_PATH = "data/tail_ingest.state"   # 记录读到文件哪个位置，重启不重复灌

# 例：
# Dec 26 19:21:52 2025 YYLLS-C2-3F-CORE-H3C-S6800-01:  %%10SHELL/6/SHELL_CMD: ...
# Dec 26 19:30:12 2025 YYLLS...:  %%IFNET/5/LINK_UPDOWN: GigabitEthernet1/0/1 link down.
LINE_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<rest>.+)$"
)

# 抽 H3C 端口 up/down
LINK_RE = re.compile(
    r"(?:LINK_UPDOWN).*?(?P<intf>(?:GigabitEthernet|Ten-GigabitEthernet|XGigabitEthernet|Bridge-Aggregation)\S+)\s+link\s+(?P<state>up|down)",
    re.IGNORECASE,
)

# 抽 reboot / power / fan 等（先粗匹配，后面你要可以继续加）
REBOOT_KW = ("reboot", "restart", "startup", "boot")
PSU_KW = ("power", "psu")
FAN_KW = ("fan",)

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

def load_offset():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return int(f.read().strip() or "0")
    except Exception:
        return 0

def save_offset(off: int):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(str(off))
    os.replace(tmp, STATE_PATH)

def post(payload: dict):
    r = requests.post(
        API_URL,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload, ensure_ascii=False),
        timeout=2,
    )
    r.raise_for_status()

def classify_h3c(msg: str, host: str):
    """
    返回三元组 (category, title, fingerprint) 或 None
    约定：
      - None 表示：这条日志不由 tail_ingest 定义指纹（交给后端 parse_syslog 生成稳定 fingerprint）
      - 返回三元组 表示：这条日志已经被我们明确识别并定义了“稳定 fingerprint”
    """

    # 过滤 CLI 审计噪音
    if "%%10SHELL/" in msg:
        return None

    # H3C 端口 link up/down
    m = LINK_RE.search(msg)
    if m:
        intf = m.group("intf")
        state = m.group("state").lower()
        category = "SWITCH_LINK"
        title = f"{host} {intf} link {state}"
        fingerprint = f"h3c|{host}|{intf}|link_{state}"
        return category, title, fingerprint

    low = msg.lower()

    # reboot
    if any(k in low for k in REBOOT_KW):
        category = "SWITCH_REBOOT"
        title = f"{host} reboot/startup"
        fingerprint = f"h3c|{host}|reboot"
        return category, title, fingerprint

    # power
    if any(k in low for k in PSU_KW):
        category = "SWITCH_POWER"
        title = f"{host} power related"
        fingerprint = f"h3c|{host}|power"
        return category, title, fingerprint

    # fan
    if any(k in low for k in FAN_KW):
        category = "SWITCH_FAN"
        title = f"{host} fan related"
        fingerprint = f"h3c|{host}|fan"
        return category, title, fingerprint

    # ✅ 关键：默认不再生成 fingerprint/title/category
    # 否则 msg 里带时间戳/毫秒会导致每条 fingerprint 不同，后端无法聚合。
    return None

def parse_line(line: str):
    """
    解析 rsyslog 写入文件的一行，抽 host/program/msg
    ts 暂用当前 UTC（展示够用）；如果你后面要精确还原本地时间，再扩展 month/day/year 解析。
    """
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
    print(f"[tail_ingest] reading {LOG_PATH}")
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

            # 先看能否明确分类（只有明确分类才带 fingerprint）
            classified = classify_h3c(msg, host)

            # ✅ 不论是否 classified，都要发给后端
            payload = {
                "timestamp": ts,
                "host": host,
                "program": program,
                "msg": msg,
            }

            # 只有我们明确识别的事件，才带 category/title/fingerprint
            if classified is not None:
                category, title, fingerprint = classified
                payload.update({
                    "category": category,
                    "title": title,
                    "fingerprint": fingerprint,
                })

            # 尝试发送，失败就简单重试
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
                # 每 1 秒落一次 offset
                if time.time() - last_save > 1.0:
                    save_offset(offset)
                    last_save = time.time()

if __name__ == "__main__":
    main()
