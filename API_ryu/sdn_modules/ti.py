# -*- coding: utf-8 -*-
"""
ti.py — Threat Intelligence fetcher and TI APIs.

Split from unified_sdn.py for improved maintainability.
"""

import os
import json
import time
import ipaddress
import requests
from typing import Set, Tuple, List, Optional, Dict

from .constants import (
    TI_FILE, COOKIE_TI, TBL, PRIO_TI_DROP,
    TI_SOURCES, TI_CONNECT_TIMEOUT, TI_READ_TIMEOUT,
    TI_RETRIES_PER_SRC, TI_BACKOFF_BASE_S, TI_BACKOFF_MAX_S,
    TI_MUTE_AFTER_FAIL, TI_MUTE_SECONDS, FETCH_INTERVAL_S, MAX_NEW_PER_FETCH
)


class TIMixin:
    """
    Mixin providing Threat Intelligence functionality.
    
    Requires the following attributes on the host class:
    - datapaths: Dict[int, Any]
    - l3_dpid: Optional[int]
    - ti_set: Set[Tuple[str, str]]
    - _ti_fail_count: Dict[str, int]
    - _ti_muted_until: Dict[str, float]
    - logger: logging.Logger
    
    Requires the following methods from other mixins:
    - _add_flow()
    - _del_by_cookie()
    """

    # ===== TI (table 1) =====
    @staticmethod
    def _parse_ti_token(token: str) -> Optional[Tuple[str, str]]:
        try:
            if '/' in token:
                n = ipaddress.ip_network(token, strict=False)
                if isinstance(n, ipaddress.IPv4Network):
                    return (str(n.network_address), str(n.netmask))
            else:
                ip = ipaddress.ip_address(token)
                if isinstance(ip, ipaddress.IPv4Address):
                    return (str(ip), "255.255.255.255")
        except:
            return None
        return None

    def _install_ti_entry(self, dp, entry: Tuple[str, str]):
        addr, mask = entry
        p = dp.ofproto_parser
        m1 = p.OFPMatch(eth_type=0x0800, ipv4_src=(addr, mask))
        m2 = p.OFPMatch(eth_type=0x0800, ipv4_dst=(addr, mask))
        self._add_flow(dp, TBL["TI"], PRIO_TI_DROP, m1, actions=[], cookie=COOKIE_TI)
        self._add_flow(dp, TBL["TI"], PRIO_TI_DROP, m2, actions=[], cookie=COOKIE_TI)

    def _apply_ti_on_l3(self, entries: List[Tuple[str, str]]):
        if not (self.l3_dpid and self.l3_dpid in self.datapaths): return
        dp = self.datapaths[self.l3_dpid]
        for e in entries: self._install_ti_entry(dp, e)

    def _load_ti_file(self):
        if not os.path.exists(TI_FILE): return
        cnt = 0
        with open(TI_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                s = line.strip()
                if not s: continue
                try: obj = json.loads(s)
                except: obj = s
                if isinstance(obj, str):
                    ent = self._parse_ti_token(obj)
                elif isinstance(obj, dict) and obj.get('cidr'):
                    ent = self._parse_ti_token(obj['cidr'])
                elif isinstance(obj, dict) and obj.get('ip'):
                    ent = self._parse_ti_token(obj['ip'])
                else: ent = None
                if ent: self.ti_set.add(ent); cnt += 1
        self.logger.info(f"[TI] loaded {cnt} entries from {TI_FILE}")

    def _append_ti_file(self, entries: List[Tuple[str, str]]):
        if not entries: return
        with open(TI_FILE, 'a', encoding='utf-8') as f:
            for a, m in entries:
                net = ipaddress.IPv4Network((a, m), strict=False)
                f.write(json.dumps({"cidr": str(net), "ts": int(time.time())}, ensure_ascii=False) + "\n")

    def _write_ti_file_full(self):
        with open(TI_FILE, 'w', encoding='utf-8') as f:
            for a, m in sorted(self.ti_set):
                net = ipaddress.IPv4Network((a, m), strict=False)
                f.write(json.dumps({"cidr": str(net), "ts": int(time.time())}, ensure_ascii=False) + "\n")

    def _ti_fetch_once(self) -> List[str]:
        out: List[str] = []
        headers = {"User-Agent": "UnifiedSDN/1.0 (+ryu-unified)"}
        timeout = (TI_CONNECT_TIMEOUT, TI_READ_TIMEOUT)
        now = time.time()
        for url in TI_SOURCES:
            if now < self._ti_muted_until.get(url, 0.0):
                self.logger.debug("[TI] muted source: %s (remain %.0fs)", url, self._ti_muted_until[url] - now)
                continue
            ok = False
            for attempt in range(1, TI_RETRIES_PER_SRC + 1):
                try:
                    r = requests.get(url, headers=headers, timeout=timeout)
                    if r.status_code != 200:
                        self.logger.warning("[TI] %s -> HTTP %s (try %d/%d)", url, r.status_code, attempt, TI_RETRIES_PER_SRC)
                        time.sleep(min(TI_BACKOFF_MAX_S, TI_BACKOFF_BASE_S * attempt))
                        continue
                    for line in r.text.splitlines():
                        s = (line or "").strip()
                        if not s or s.startswith("#"): continue
                        token = s.split()[0]
                        try:
                            if "/" in token:
                                net = ipaddress.ip_network(token, strict=False)
                                if net.version == 4: out.append(str(net))
                            else:
                                ip = ipaddress.ip_address(token)
                                if ip.version == 4: out.append(str(ip))
                        except: pass
                    ok = True
                    self._ti_fail_count[url] = 0
                    break
                except requests.exceptions.RequestException as e:
                    msg = str(e).split("\n")[0]
                    self.logger.warning("[TI] fetch %s error: %s (try %d/%d)", url, msg, attempt, TI_RETRIES_PER_SRC)
                    time.sleep(min(TI_BACKOFF_MAX_S, TI_BACKOFF_BASE_S * attempt))
            if not ok:
                self._ti_fail_count[url] = self._ti_fail_count.get(url, 0) + 1
                fails = self._ti_fail_count[url]
                if fails >= TI_MUTE_AFTER_FAIL:
                    self._ti_muted_until[url] = time.time() + TI_MUTE_SECONDS
                    self.logger.warning("[TI] give up & mute %s for %ds (fails=%d)", url, TI_MUTE_SECONDS, fails)
                else:
                    self.logger.warning("[TI] give up source: %s (fails=%d)", url, fails)

        seen = set()
        uniq = []
        for s in out:
            if s not in seen:
                seen.add(s)
                uniq.append(s)
        return uniq

    def _ti_fetch_loop(self):
        while True:
            try:
                new = self._ti_fetch_once()
                if new:
                    added = []
                    for ipstr in new[:MAX_NEW_PER_FETCH]:
                        ent = self._parse_ti_token(ipstr)
                        if ent and ent not in self.ti_set:
                            self.ti_set.add(ent)
                            added.append(ent)
                    if added:
                        self._apply_ti_on_l3(added)
                        self._append_ti_file(added)
                        self.logger.info("[TI] auto-added %d (total=%d)", len(added), len(self.ti_set))
            except Exception as e:
                self.logger.warning("[TI] updater error: %s", e)
            time.sleep(FETCH_INTERVAL_S)

    # public TI
    def ti_list(self, offset: int = 0, limit: int = 500):
        items = [{"type": "cidr", "value": str(ipaddress.IPv4Network((a, m), strict=False))}
                 for (a, m) in sorted(self.ti_set)]
        total = len(items)
        off = max(0, int(offset))
        lim = max(1, min(int(limit), 2000))
        return {"total": total, "offset": off, "limit": lim, "items": items[off: off + lim]}

    def ti_add(self, raw_items: List[str]):
        added = []
        for s in (raw_items or []):
            ent = self._parse_ti_token(str(s).strip())
            if ent and ent not in self.ti_set:
                self.ti_set.add(ent)
                added.append(ent)
        self._apply_ti_on_l3(added)
        self._append_ti_file(added)
        return {"added": [str(ipaddress.IPv4Network((a, m), strict=False)) for a, m in added]}

    def ti_del(self, raw_items: List[str]):
        rm = []
        for s in (raw_items or []):
            ent = self._parse_ti_token(str(s).strip())
            if ent and ent in self.ti_set: rm.append(ent)
        for e in rm: self.ti_set.discard(e)
        if self.l3_dpid and self.l3_dpid in self.datapaths:
            self._del_by_cookie(self.datapaths[self.l3_dpid], COOKIE_TI)
            self._apply_ti_on_l3(sorted(self.ti_set))
        self._write_ti_file_full()
        return {"removed": [str(ipaddress.IPv4Network((a, m), strict=False)) for a, m in rm]}
