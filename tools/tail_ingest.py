#!/usr/bin/env python3
from __future__ import annotations

import os
import time
import json
import re
import requests
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any

from desensitizer import Desensitizer, DesensitizeConfig

# ============================================================
# Paths (absolute)
# ============================================================
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(ROOT_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

LOG_PATH = os.environ.get("RSYSLOG_REMOTE_LOG", "/opt/homebrew/var/log/rsyslog-remote.log")

EVENT_API_URL = os.environ.get("OPS_EVENT_API", "http://127.0.0.1:8000/api/ingest/syslog")
EVIDENCE_API_URL = os.environ.get("OPS_EVIDENCE_API", "http://127.0.0.1:8000/api/evidence/ingest")

STATE_PATH = os.path.join(DATA_DIR, "tail_ingest.state")  # offset only (compatible)

# ============================================================
# Desensitize config (env)
# ============================================================
ENABLE_DESENSITIZE = os.environ.get("ENABLE_DESENSITIZE", "1").lower() not in ("0", "false", "no")
DESENSE_SECRET = os.environ.get("OPS_DESENSE_SECRET", "")
DESENSE_REVERSIBLE = os.environ.get("DESENSITIZE_REVERSIBLE", "0").lower() in ("1", "true", "yes")
DESENSE_MAP_PATH = os.environ.get("DESENSITIZE_MAP_PATH", os.path.join(DATA_DIR, "desensitize_map.json"))

# Optional: if you want to keep RFC1918 IPs (NOT recommended), set KEEP_PRIVATE_RANGES=1
KEEP_PRIVATE_RANGES = os.environ.get("KEEP_PRIVATE_RANGES", "0").lower() in ("1", "true", "yes")

# ============================================================
# Regex
# ============================================================

# Example lines:
# Dec 26 19:30:12 2025 YYLLS...:  %%IFNET/5/LINK_UPDOWN: GigabitEthernet1/0/1 link down.
LINE_RE = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<rest>.+)$")

# H3C link up/down
LINK_RE = re.compile(
    r"(?:LINK_UPDOWN).*?(?P<intf>(?:GigabitEthernet|Ten-GigabitEthernet|XGigabitEthernet|Bridge-Aggregation)\S+)\s+link\s+(?P<state>up|down)",
    re.IGNORECASE
)

# MAC flapping
MAC_FLAP_RE = re.compile(
    r"MAC[_\s]?FLAPPING.*?MAC address\s+(?P<mac>[0-9a-fA-F\-\.]+)\s+has been moving between port\s+(?P<p1>\S+)\s+and\s+port\s+(?P<p2>\S+)",
    re.IGNORECASE
)

# quick “source” detector for evidence
FORTI_HINT = ("fortigate", "fg-", "utm", "traffic", "appid", "policyid", "vd=")
AD_HINT = ("kerberos", "ntlm", "eventid", "4624", "4625", "4768", "4771", "ldap")
VPN_HINT = ("vpn", "ssl vpn", "ipsec", "ike", "tunnel", "login", "logout")
UEBA_HINT = ("ueba", "risk", "behavior", "anomaly", "impossible travel")


# ============================================================
# Helpers
# ============================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_offset() -> int:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return int((f.read().strip() or "0"))
    except Exception:
        return 0


def save_offset(off: int) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(str(off))
        os.replace(tmp, STATE_PATH)
    except Exception as e:
        print(f"[tail_ingest] WARN save_offset failed: {e}")


def post_json(url: str, payload: dict, timeout: float = 3.0) -> None:
    r = requests.post(
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload, ensure_ascii=False),
        timeout=timeout
    )
    r.raise_for_status()


def detect_source(host: str, msg: str) -> str:
    h = (host or "").lower()
    m = (msg or "").lower()

    if any(x in h for x in ("forti", "fg", "fortigate")) or any(x in m for x in FORTI_HINT):
        return "fortigate"
    if any(x in h for x in ("ad", "dc", "domain")) or any(x in m for x in AD_HINT):
        return "ad"
    if any(x in h for x in ("vpn", "ssl", "ipsec")) or any(x in m for x in VPN_HINT):
        return "vpn"
    if any(x in h for x in ("ueba", "behavior")) or any(x in m for x in UEBA_HINT):
        return "ueba"
    return "syslog"


def parse_line(line: str) -> Tuple[str, str, str, str]:
    """
    返回 (host, program, msg, ts_iso_utc)
    说明：你这里 ts 先用 ingest 时间（utc_now_iso），保持你原逻辑。
    如果你后面想解析 syslog 原始时间戳，也可以扩展。
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


def classify_as_event(msg: str, host: str) -> Optional[Tuple[str, str, str]]:
    """
    返回 (category, title, fingerprint) 表示：这条值得当 Event
    返回 None 表示：不当 Event，应当进 Evidence
    注意：本函数应该使用“已经脱敏后的 msg/host”，确保 fingerprint/title 不含敏感信息。
    """
    # filter CLI audit noise (你原逻辑：SHELL_CMD 走 evidence)
    if "%%10SHELL/" in msg:
        return None

    m = MAC_FLAP_RE.search(msg)
    if m:
        mac = m.group("mac")
        p1 = m.group("p1")
        p2 = m.group("p2")
        category = "L2/MAC_FLAPPING"
        title = f"MAC_FLAPPING {mac} {p1}<->{p2}"
        fingerprint = f"syslog|MAC_FLAPPING|{mac}|{p1}|{p2}"
        return category, title, fingerprint

    m = LINK_RE.search(msg)
    if m:
        intf = m.group("intf")
        state = m.group("state").lower()
        category = "SWITCH_LINK"
        title = f"{host} {intf} link {state}"
        fingerprint = f"h3c|{host}|{intf}|link_{state}"
        return category, title, fingerprint

    return None


# ============================================================
# Desensitizer init
# ============================================================

def build_desensitizer() -> Optional[Desensitizer]:
    if not ENABLE_DESENSITIZE:
        print("[tail_ingest] desensitize disabled (ENABLE_DESENSITIZE=0)")
        return None

    if not DESENSE_SECRET or len(DESENSE_SECRET) < 12:
        print("[tail_ingest] WARN desensitize enabled but OPS_DESENSE_SECRET is missing/too short.")
        print("[tail_ingest]      Set OPS_DESENSE_SECRET to a long random secret. (Otherwise mapping unstable/weak)")
        # 仍然允许运行，但强烈建议你设置 secret
        # 这里给一个最低限度 fallback：用固定弱 key（不推荐）
        secret = (DESENSE_SECRET or "WEAK_DEFAULT_SECRET_CHANGE_ME")
    else:
        secret = DESENSE_SECRET

    cfg = DesensitizeConfig(
        secret_key=secret,
        reversible=DESENSE_REVERSIBLE,
        mapping_path=DESENSE_MAP_PATH,
        keep_private_ranges=KEEP_PRIVATE_RANGES,
    )
    print(f"[tail_ingest] desensitize enabled reversible={DESENSE_REVERSIBLE} map={DESENSE_MAP_PATH}")
    return Desensitizer(cfg)


# ============================================================
# Main loop
# ============================================================

def main() -> None:
    print(f"[tail_ingest] ROOT={ROOT_DIR}")
    print(f"[tail_ingest] reading {LOG_PATH}")
    print(f"[tail_ingest] state={STATE_PATH}")
    print(f"[tail_ingest] event_api={EVENT_API_URL}")
    print(f"[tail_ingest] evidence_api={EVIDENCE_API_URL}")

    des = build_desensitizer()

    while not os.path.exists(LOG_PATH):
        print(f"[tail_ingest] waiting for {LOG_PATH} ...")
        time.sleep(1)

    offset = load_offset()

    # 失败退避（防止 API 挂了时疯狂刷）
    fail_sleep = 0.0  # seconds

    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        # 你原版是从 EOF 开始；保持一致
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

            if fail_sleep > 0:
                time.sleep(fail_sleep)
                fail_sleep = 0.0

            host_raw, program_raw, msg_raw, ts = parse_line(line)

            # ---------------------------
            # Desensitize (host + msg)
            # ---------------------------
            host = host_raw
            program = program_raw
            msg = msg_raw
            mask_stats: Dict[str, int] = {}

            if des:
                # desensitize_line 需要“完整 syslog 行”才能识别 header hostname；
                # 但我们这里已经拆出来 host/msg，所以采用“拼回去”的方式做统一脱敏：
                fake_line = f"Dec 01 00:00:00 {host_raw}: {msg_raw}\n"
                masked_line, st = des.desensitize_line(fake_line)
                mask_stats = st or {}

                # 再拆回来
                # masked_line 形如: "Dec 01 00:00:00 DEV_xxxx: <masked_msg>"
                try:
                    _, _, _, rest = masked_line.split(" ", 3)   # rest = "DEV_xxxx: <masked_msg>\n"
                    left, right = rest.split(": ", 1)
                    host = left.strip()
                    msg = right.strip()
                except Exception:
                    # fallback：至少对 msg 做 replace
                    msg = masked_line.strip()

            # ---------------------------
            # classify
            # ---------------------------
            ev = classify_as_event(msg, host)

            ok = False
            if ev is not None:
                category, title, fingerprint = ev
                payload = {
                    "timestamp": ts,
                    "host": host,
                    "program": program,
                    "msg": msg,
                    "category": category,
                    "title": title,
                    "fingerprint": fingerprint,
                    "meta": {
                        "masked": bool(des),
                        "mask_stats": mask_stats,
                        "raw_host_present": False,  # 明示：不会把 raw host 写进去
                    }
                }
                for i in range(3):
                    try:
                        post_json(EVENT_API_URL, payload)
                        ok = True
                        break
                    except Exception as e:
                        time.sleep(0.3 * (i + 1))
            else:
                source = detect_source(host, msg)
                payload = {
                    "timestamp": ts,
                    "host": host,
                    "source": source,
                    "message": msg,
                    "fields": {
                        "program": program,
                        "masked": bool(des),
                        "mask_stats": mask_stats,
                    },
                }
                for i in range(3):
                    try:
                        post_json(EVIDENCE_API_URL, payload)
                        ok = True
                        break
                    except Exception as e:
                        time.sleep(0.3 * (i + 1))

            # ---------------------------
            # offset & state
            # ---------------------------
            if ok:
                offset = f.tell()
                if time.time() - last_save > 1.0:
                    save_offset(offset)
                    last_save = time.time()
            else:
                # 发送失败：不前移 offset，避免丢数据。
                # 但为了防止死循环刷 API：小退避
                fail_sleep = 0.5


if __name__ == "__main__":
    main()