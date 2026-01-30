# tools/desensitizer.py
from __future__ import annotations

import os
import re
import json
import hmac
import hashlib
from dataclasses import dataclass
from typing import Tuple, Dict


@dataclass
class DesensitizeConfig:
    secret_key: str
    reversible: bool = False
    mapping_path: str = "data/desensitize_map.json"
    keep_private_ranges: bool = False


class Desensitizer:
    def __init__(self, cfg: DesensitizeConfig):
        self.cfg = cfg
        self._map: Dict[str, str] = {}
        self._rev: Dict[str, str] = {}
        self._load_map()

    # -------------------------
    # public
    # -------------------------
    def desensitize_line(self, line: str) -> Tuple[str, Dict]:
        meta = {}

        s = line
        s = self._mask_ip(s)
        s = self._mask_mac(s)
        s = self._mask_secret(s)

        return s, meta

    # -------------------------
    # internals
    # -------------------------
    def _h(self, s: str) -> str:
        return hmac.new(
            self.cfg.secret_key.encode(),
            s.encode(),
            hashlib.sha256
        ).hexdigest()[:10]

    def _map_value(self, raw: str, prefix: str) -> str:
        if raw in self._map:
            return self._map[raw]

        token = f"<{prefix}:{self._h(raw)}>"
        self._map[raw] = token
        if self.cfg.reversible:
            self._rev[token] = raw
        self._save_map()
        return token

    def _mask_ip(self, s: str) -> str:
        def repl(m):
            ip = m.group(0)
            if self.cfg.keep_private_ranges and self._is_private_ip(ip):
                return ip
            return self._map_value(ip, "IP")

        return re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", repl, s)

    def _mask_mac(self, s: str) -> str:
        return re.sub(
            r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            lambda m: self._map_value(m.group(0), "MAC"),
            s,
        )

    def _mask_secret(self, s: str) -> str:
        patterns = [
            r"(password\s*=\s*)(\S+)",
            r"(token\s*=\s*)(\S+)",
            r"(secret\s*=\s*)(\S+)",
        ]
        for p in patterns:
            s = re.sub(
                p,
                lambda m: m.group(1) + self._map_value(m.group(2), "SECRET"),
                s,
                flags=re.IGNORECASE,
            )
        return s

    def _is_private_ip(self, ip: str) -> bool:
        return (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("172.")
        )

    # -------------------------
    # mapping persistence
    # -------------------------
    def _load_map(self):
        if os.path.exists(self.cfg.mapping_path):
            try:
                with open(self.cfg.mapping_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._map = data.get("map", {})
                    self._rev = data.get("rev", {})
            except Exception:
                pass

    def _save_map(self):
        os.makedirs(os.path.dirname(self.cfg.mapping_path), exist_ok=True)
        try:
            with open(self.cfg.mapping_path, "w", encoding="utf-8") as f:
                json.dump(
                    {"map": self._map, "rev": self._rev},
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
        except Exception:
            pass