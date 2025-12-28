import re
from typing import Dict, Any, Optional, Tuple

# 例子：
# %Aug 18 14:25:29:336 2025 H3C L2MGNT/5/MAC_FLAPPING: MAC address 5489-98b3-2111 has been moving between port GigabitEthernet1/0/48 and port GigabitEthernet2/0/48.

_H3C_HDR = re.compile(
    r"""^%
    (?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+
    (?P<hms>\d{2}:\d{2}:\d{2}):(?P<ms>\d{3})\s+
    (?P<year>\d{4})\s+
    (?P<vendor>H3C)\s+
    (?P<module>[^:]+):\s+
    (?P<body>.*)$
    """,
    re.X,
)

# module: L2MGNT/5/MAC_FLAPPING
# body:   MAC address 5489-98b3-2111 has been moving between port Gi... and port Gi...
_MAC_FLAP = re.compile(
    r"""MAC\s+address\s+(?P<mac>[0-9a-fA-F\-\.]+)\s+has\s+been\s+moving\s+between\s+port\s+
    (?P<p1>[\w/]+)\s+and\s+port\s+(?P<p2>[\w/]+)\.?$
    """,
    re.X,
)

def _norm_mac(mac: str) -> str:
    # 兼容 5489-98b3-2111 / 5489.98b3.2111 / 54:89:98:b3:21:11
    m = mac.strip().lower().replace(".", "").replace("-", "").replace(":", "")
    if len(m) == 12:
        return f"{m[0:4]}-{m[4:8]}-{m[8:12]}"
    return mac.strip().lower()

def _sort_ports(a: str, b: str) -> Tuple[str, str]:
    a = a.strip()
    b = b.strip()
    return (a, b) if a <= b else (b, a)

def parse_syslog(msg: str) -> Dict[str, Any]:
    """
    返回字段约定：
      - category: 用于 UI 分类
      - title:    用于事件标题（尽量短）
      - fingerprint: 聚合关键（必须稳定，不能包含时间戳）
      - fields/raw: 可选
    """
    s = (msg or "").strip()
    if not s:
        return {}

    m = _H3C_HDR.match(s)
    if not m:
        # 没命中 H3C 的“%Aug ... H3C ...:”格式
        return {}

    module = (m.group("module") or "").strip()     # e.g. L2MGNT/5/MAC_FLAPPING
    body = (m.group("body") or "").strip()

    # --- MAC FLAPPING 特判：做稳定 fingerprint ---
    mf = _MAC_FLAP.match(body)
    if mf:
        mac = _norm_mac(mf.group("mac"))
        p1, p2 = _sort_ports(mf.group("p1"), mf.group("p2"))

        category = "L2/MAC_FLAPPING"
        title = f"MAC_FLAPPING {mac} {p1}<->{p2}"

        # ✅ 关键：fingerprint 不含任何时间戳/毫秒/日期
        fingerprint = f"syslog|MAC_FLAPPING|{mac}|{p1}|{p2}"

        return {
            "category": category,
            "title": title,
            "fingerprint": fingerprint,
            "fields": {
                "vendor": "H3C",
                "module": module,
                "mac": mac,
                "port_a": p1,
                "port_b": p2,
                "body": body,
            },
        }

    # --- 其他 H3C 模块：给一个“去时间戳”的通用 fingerprint ---
    # module 里通常已经含 “子系统/级别/事件名”，比 raw msg 稳定
    # body 仍可能含动态数字，但也比带时间戳强
    safe_body = body[:140]
    category = f"H3C/{module.split('/')[0] or 'SYSLOG'}"
    title = f"{module} syslog: {safe_body[:80]}".strip()

    fingerprint = f"syslog|{module}|{safe_body}"

    return {
        "category": category,
        "title": title,
        "fingerprint": fingerprint,
        "fields": {"vendor": "H3C", "module": module, "body": body},
    }