#!/usr/bin/env python3
from __future__ import annotations

import os
import time
import json
import re
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any

import requests
from tools.desensitizer import Desensitizer, DesensitizeConfig

# ============================================================
# Paths (absolute)
# ============================================================
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(ROOT_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

LOG_PATH = os.environ.get("RSYSLOG_REMOTE_LOG", "/opt/homebrew/var/log/rsyslog-remote.log")

EVENT_API_URL = os.environ.get("OPS_EVENT_API", "http://127.0.0.1:8000/api/ingest/syslog")
EVIDENCE_API_URL = os.environ.get("OPS_EVIDENCE_API", "http://127.0.0.1:8000/api/evidence/ingest")

STATE_PATH = os.environ.get("TAIL_STATE_PATH", os.path.join(DATA_DIR, "tail_ingest.state.json"))

# 可选：将“原始明文”仅落本机文件（不进 API/DB）
RAW_TAP_ENABLE = os.environ.get("RAW_TAP_ENABLE", "0").lower() in ("1", "true", "yes")
RAW_TAP_PATH = os.environ.get("RAW_TAP_PATH", os.path.join(DATA_DIR, "raw_tap.log"))  # 强烈建议只本机可读

# ============================================================
# Desensitize config (env)
# ============================================================
ENABLE_DESENSITIZE = os.environ.get("ENABLE_DESENSITIZE", "1").lower() not in ("0", "false", "no")
DESENSE_SECRET = os.environ.get("OPS_DESENSE_SECRET", "")
DESENSE_REVERSIBLE = os.environ.get("DESENSITIZE_REVERSIBLE", "0").lower() in ("1", "true", "yes")
DESENSE_MAP_PATH = os.environ.get("DESENSITIZE_MAP_PATH", os.path.join(DATA_DIR, "desensitize_map.json"))
KEEP_PRIVATE_RANGES = os.environ.get("KEEP_PRIVATE_RANGES", "0").lower() in ("1", "true", "yes")

# ============================================================
# Networking (requests)
# ============================================================
HTTP_TIMEOUT = float(os.environ.get("INGEST_HTTP_TIMEOUT", "3"))
RETRY_MAX = int(os.environ.get("INGEST_RETRY_MAX", "3"))
RETRY_BACKOFF = float(os.environ.get("INGEST_RETRY_BACKOFF", "0.3"))

# ============================================================
# Regex
# ============================================================

# Example:
# Dec 26 19:30:12 2025 YYLLS...:  %%IFNET/5/LINK_UPDOWN: GigabitEthernet1/0/1 link down.
LINE_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<rest>.+)$"
)

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
FORTI_HINT = ("fortigate", "fg-", "utm", "traffic", "appid", "policyid", "vd=", "srcip=", "dstip=")
AD_HINT = ("kerberos", "ntlm", "eventid", "4624", "4625", "4768", "4771", "ldap")
VPN_HINT = ("vpn", "ssl vpn", "ipsec", "ike", "tunnel", "login", "logout")
UEBA_HINT = ("ueba", "risk", "behavior", "anomaly", "impossible travel")

# ============================================================
# State (inode + offset)
# ============================================================

@dataclass
class TailState:
    path: str
    inode: int
    offset: int
    updated_at: str

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _safe_mkdir(p: str) -> None:
    os.makedirs(p, exist_ok=True)

def _file_inode(path: str) -> int:
    return os.stat(path).st_ino

def _file_size(path: str) -> int:
    return os.stat(path).st_size

def load_state() -> TailState:
    """
    兼容：
    - 新版 JSON state: {"path":..., "inode":..., "offset":...}
    - 旧版纯 offset 文件：内容是整数
    """
    if not os.path.exists(STATE_PATH):
        return TailState(path=LOG_PATH, inode=0, offset=0, updated_at=utc_now_iso())

    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            txt = f.read().strip()
        # 旧版：纯 offset
        if txt and txt[0].isdigit():
            off = int(txt)
            return TailState(path=LOG_PATH, inode=0, offset=off, updated_at=utc_now_iso())

        data = json.loads(txt)
        return TailState(
            path=data.get("path", LOG_PATH),
            inode=int(data.get("inode", 0)),
            offset=int(data.get("offset", 0)),
            updated_at=data.get("updated_at", utc_now_iso()),
        )
    except Exception:
        return TailState(path=LOG_PATH, inode=0, offset=0, updated_at=utc_now_iso())

def save_state(st: TailState) -> None:
    _safe_mkdir(os.path.dirname(STATE_PATH) or ".")
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st.__dict__, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_PATH)

# ============================================================
# Desensitizer
# ============================================================

def build_desensitizer() -> Optional[Desensitizer]:
    if not ENABLE_DESENSITIZE:
        print("[tail_ingest] desensitize disabled (ENABLE_DESENSITIZE=0)")
        return None

    if not DESENSE_SECRET or len(DESENSE_SECRET) < 12:
        print("[tail_ingest] WARN desensitize enabled but OPS_DESENSE_SECRET missing/too short.")
        print("[tail_ingest]      Please export OPS_DESENSE_SECRET to a long random secret for stable mapping.")
        secret = DESENSE_SECRET or "WEAK_DEFAULT_SECRET_CHANGE_ME"
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
# Parsing / masking helpers
# ============================================================

def parse_syslog_line(line: str) -> Tuple[str, str, str]:
    """
    从 rsyslog 落盘行里尽可能提取：
      - host（可能是设备名）
      - program（固定 syslog/rsyslog）
      - msg（正文）
    注意：时间戳我们不解析，统一使用 ingest 时间 utc_now_iso（保持你现有行为）。
    """
    line = line.rstrip("\n")
    m = LINE_RE.match(line)
    if not m:
        return "unknown", "rsyslog", line

    rest = m.group("rest")
    host = "unknown"
    msg = rest

    # "... HOST:  MESSAGE"
    if ": " in rest:
        left, right = rest.split(": ", 1)
        host = left.split()[-1]
        msg = right.strip()

    return host, "syslog", msg

def mask_text(des: Optional[Desensitizer], text: str) -> Tuple[str, Dict[str, int]]:
    """
    对任意文本脱敏（不依赖 syslog header 结构）
    注意：desensitizer.desensitize_line 期望一行，所以补 '\n'
    """
    if not des:
        return text, {}
    masked, stats = des.desensitize_line(text + "\n")
    return masked.rstrip("\n"), (stats or {})

def stable_fingerprint(s: str) -> str:
    # 指纹使用脱敏后的字符串生成（避免原始敏感信息“可逆推测”）
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:16]

# ============================================================
# Classify (always feed masked msg/host)
# ============================================================

def detect_source(host_masked: str, msg_masked: str) -> str:
    h = (host_masked or "").lower()
    m = (msg_masked or "").lower()

    if any(x in h for x in ("forti", "fg", "fortigate")) or any(x in m for x in FORTI_HINT):
        return "fortigate"
    if any(x in h for x in ("ad", "dc", "domain")) or any(x in m for x in AD_HINT):
        return "ad"
    if any(x in h for x in ("vpn", "ssl", "ipsec")) or any(x in m for x in VPN_HINT):
        return "vpn"
    if any(x in h for x in ("ueba", "behavior")) or any(x in m for x in UEBA_HINT):
        return "ueba"
    return "syslog"

def classify_as_event(msg_masked: str, host_masked: str) -> Optional[Tuple[str, str, str]]:
    # SHELL_CMD 类：仍然不当 Event，但也要走脱敏后的 Evidence
    if "%%10SHELL/" in msg_masked:
        return None

    m = MAC_FLAP_RE.search(msg_masked)
    if m:
        mac = m.group("mac")
        p1 = m.group("p1")
        p2 = m.group("p2")
        category = "L2/MAC_FLAPPING"
        title = f"MAC_FLAPPING {mac} {p1}<->{p2}"
        fingerprint = stable_fingerprint(f"MAC_FLAPPING|{mac}|{p1}|{p2}")
        return category, title, fingerprint

    m = LINK_RE.search(msg_masked)
    if m:
        intf = m.group("intf")
        state = m.group("state").lower()
        category = "SWITCH_LINK"
        title = f"{host_masked} {intf} link {state}"
        fingerprint = stable_fingerprint(f"LINK|{host_masked}|{intf}|{state}")
        return category, title, fingerprint

    return None

# ============================================================
# HTTP
# ============================================================

def post_json(url: str, payload: Dict[str, Any]) -> None:
    r = requests.post(
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload, ensure_ascii=False),
        timeout=HTTP_TIMEOUT,
    )
    r.raise_for_status()

def post_with_retry(url: str, payload: Dict[str, Any]) -> bool:
    for i in range(RETRY_MAX):
        try:
            post_json(url, payload)
            return True
        except Exception:
            time.sleep(RETRY_BACKOFF * (i + 1))
    return False

# ============================================================
# RAW tap (optional, local-only)
# ============================================================

def raw_tap_write(line: str) -> None:
    if not RAW_TAP_ENABLE:
        return
    _safe_mkdir(os.path.dirname(RAW_TAP_PATH) or ".")
    # best-effort; do not crash ingestion
    try:
        # 0600 best effort (works on unix)
        if not os.path.exists(RAW_TAP_PATH):
            with open(RAW_TAP_PATH, "w", encoding="utf-8") as _:
                pass
            try:
                os.chmod(RAW_TAP_PATH, 0o600)
            except Exception:
                pass
        with open(RAW_TAP_PATH, "a", encoding="utf-8") as f:
            f.write(line if line.endswith("\n") else (line + "\n"))
    except Exception:
        pass

# ============================================================
# Main
# ============================================================
print("[tail_ingest] IMPORT OK: tools.desensitizer loaded")
print("[tail_ingest] ENABLE_DESENSITIZE =", os.getenv("ENABLE_DESENSITIZE"))
print("[tail_ingest] OPS_DESENSE_SECRET len =", len(os.getenv("OPS_DESENSE_SECRET","")))

def main() -> None:
    print(f"[tail_ingest] ROOT={ROOT_DIR}")
    print(f"[tail_ingest] reading {LOG_PATH}")
    print(f"[tail_ingest] state={STATE_PATH}")
    print(f"[tail_ingest] event_api={EVENT_API_URL}")
    print(f"[tail_ingest] evidence_api={EVIDENCE_API_URL}")
    print(f"[tail_ingest] raw_tap_enable={RAW_TAP_ENABLE} raw_tap_path={RAW_TAP_PATH}")

    des = build_desensitizer()

    while not os.path.exists(LOG_PATH):
        print(f"[tail_ingest] waiting for {LOG_PATH} ...")
        time.sleep(1)

    st = load_state()

    # open file and resolve inode
    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        cur_inode = _file_inode(LOG_PATH)
        st.path = LOG_PATH

        # inode 不一致 => 说明可能 logrotate 或 state 旧，按“从末尾开始”更安全
        if st.inode != 0 and st.inode != cur_inode:
            print("[tail_ingest] inode changed (logrotate). Reset offset=0")
            st.offset = 0

        st.inode = cur_inode

        # offset 合法性
        end = f.seek(0, os.SEEK_END)
        if st.offset > end:
            st.offset = 0

        # 默认行为：从 state offset 续读；若 state 是 0 则从末尾开始（避免灌历史）
        if st.offset == 0:
            # 你如果想首次从头灌，把这里改成 f.seek(0, os.SEEK_SET)
            f.seek(0, os.SEEK_END)
            st.offset = f.tell()
            save_state(st)
            print(f"[tail_ingest] start at EOF offset={st.offset}")
        else:
            f.seek(st.offset, os.SEEK_SET)
            print(f"[tail_ingest] resume offset={st.offset}")

        last_save = time.time()
        fail_sleep = 0.0

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            if fail_sleep > 0:
                time.sleep(fail_sleep)
                fail_sleep = 0.0

            # 仅本机可选留一份明文（不会进 API）
            raw_tap_write(line)

            host_raw, program_raw, msg_raw = parse_syslog_line(line)

            # ============
            # 关键：入口即脱敏
            # ============
            host_masked, host_stats = mask_text(des, host_raw)
            msg_masked, msg_stats = mask_text(des, msg_raw)

            # 合并统计
            mask_stats: Dict[str, int] = {}
            for d in (host_stats, msg_stats):
                for k, v in d.items():
                    mask_stats[k] = mask_stats.get(k, 0) + int(v)

            ts = utc_now_iso()

            ev = classify_as_event(msg_masked, host_masked)

            ok = False
            if ev is not None:
                category, title, fingerprint = ev
                payload = {
                    "timestamp": ts,
                    "host": host_masked,
                    "program": program_raw,  # program 一般不敏感，但你也可以 mask_text
                    "msg": msg_masked,
                    "category": category,
                    "title": title,
                    "fingerprint": fingerprint,
                    "meta": {
                        "masked": bool(des),
                        "mask_stats": mask_stats,
                        "ingest": "tail_ingest",
                    },
                }
                ok = post_with_retry(EVENT_API_URL, payload)
            else:
                source = detect_source(host_masked, msg_masked)
                payload = {
                    "timestamp": ts,
                    "host": host_masked,
                    "source": source,
                    "message": msg_masked,
                    "fields": {
                        "program": program_raw,
                        "masked": bool(des),
                        "mask_stats": mask_stats,
                        "fingerprint": stable_fingerprint(f"{host_masked}|{source}|{msg_masked[:200]}"),
                    },
                }
                ok = post_with_retry(EVIDENCE_API_URL, payload)

            if ok:
                st.offset = f.tell()
                st.updated_at = utc_now_iso()
                if time.time() - last_save > 1.0:
                    save_state(st)
                    last_save = time.time()
            else:
                # 不前移 offset，避免丢；稍微退避
                fail_sleep = 0.5


if __name__ == "__main__":
    main()