# -*- coding: utf-8 -*-
"""
ids.py — EVE tailer, IDS auto-block, Suricata local.rules management.

Split from unified_sdn.py for improved maintainability.
"""

import os
import json
import time
import re
import subprocess
from collections import defaultdict
from typing import Dict, Tuple, List, Optional

from .constants import (
    SURICATA_LOCAL_RULES, SURICATA_LOCAL_RULES_BAK, EVE_JSON_PATH,
    SURICATA_RELOAD_CMD, COOKIE_IDS, TBL,
    BLOCK_MODE, BLOCK_PRIORITY, HARD_TIMEOUT, REBLOCK_GRACE,
    SEVERITY_MIN, TARGET_DPID, WHITELIST_IPS, WHITELIST_SIDS
)


class IDSMixin:
    """
    Mixin providing IDS auto-block and Suricata rules management functionality.
    
    Requires the following attributes on the host class:
    - datapaths: Dict[int, Any]
    - l3_dpid: Optional[int]
    - ids_last_block_ts: defaultdict(float)
    - ids_active_until: Dict[Tuple[int, Tuple], float]
    - ids_cookie_key: Dict[Tuple[int, int], Tuple]
    - logger: logging.Logger
    
    Requires the following methods from other mixins:
    - _add_flow()
    """

    # ===== IDS AUTO-BLOCK (table 3) =====
    def _ids_key_from_event(self, ev: dict) -> Optional[Tuple]:
        if (ev.get('event_type') or '').lower() != 'alert':
            return None
        al = ev.get('alert') or {}
        sid = al.get('signature_id') or al.get('sid')
        try: sid = int(sid) if sid is not None else None
        except: sid = None
        if sid and sid in WHITELIST_SIDS: return None

        sev = al.get('severity')
        try: sev = int(sev) if sev is not None else None
        except: sev = None
        if sev is not None and sev > SEVERITY_MIN:
            return None

        sip = ev.get('src_ip')
        dip = ev.get('dest_ip') or ev.get('dst_ip')
        proto = (ev.get('proto') or '').upper()
        sp = ev.get('src_port')
        dpn = ev.get('dest_port') or ev.get('dst_port')

        if sip in WHITELIST_IPS or dip in WHITELIST_IPS:
            return None

        if BLOCK_MODE == "src_ip" and sip:
            return ("src_ip", sip, sid)
        elif BLOCK_MODE == "src_ip_proto" and sip and proto:
            return ("src_ip_proto", sip, proto, sid)
        elif BLOCK_MODE == "5tuple" and sip and dip and proto:
            sp_i = int(sp) if sp not in (None, "", 0) else None
            dp_i = int(dpn) if dpn not in (None, "", 0) else None
            return ("5t", proto, sip, sp_i, dip, dp_i, sid)
        elif BLOCK_MODE == "dst_ip" and dip:
            return ("dst_ip", dip, sid)
        elif sip:
            return ("src_ip", sip, sid)
        return None

    def _ids_is_active(self, dpid: int, key: Tuple, now: float) -> bool:
        exp = self.ids_active_until.get((dpid, key))
        return (exp is not None) and (now < exp)

    def _ids_mark_active(self, dpid: int, key: Tuple, now: float):
        self.ids_active_until[(dpid, key)] = now + (HARD_TIMEOUT - 1 if HARD_TIMEOUT > 0 else 600)

    def _ids_install_drop(self, dp, key: Tuple):
        ofp, p = dp.ofproto, dp.ofproto_parser
        # cookie: ghép thêm sid nếu có
        sid = key[-1] if isinstance(key[-1], int) or (isinstance(key[-1], type(None))) else None
        sid_val = (sid & 0xFFFF) if isinstance(sid, int) else 0
        cookie = COOKIE_IDS | sid_val
        flags = ofp.OFPFF_SEND_FLOW_REM

        k0 = key[0]
        def _send(match_kwargs):
            self._add_flow(dp, TBL["IDS"], BLOCK_PRIORITY,
                           p.OFPMatch(**match_kwargs), actions=[],
                           cookie=cookie, hard_timeout=HARD_TIMEOUT, idle_timeout=0, flags=flags)

        if k0 == "src_ip":
            _, sip, _sid = key
            _send(dict(eth_type=0x0800, ipv4_src=sip))
        elif k0 == "src_ip_proto":
            _, sip, proto, _sid = key
            mk = dict(eth_type=0x0800, ipv4_src=sip)
            if proto == "TCP": mk["ip_proto"] = 6
            elif proto == "UDP": mk["ip_proto"] = 17
            elif proto == "ICMP": mk["ip_proto"] = 1
            _send(mk)
        elif k0 == "dst_ip":
            _, dip, _sid = key
            _send(dict(eth_type=0x0800, ipv4_dst=dip))
        elif k0 == "5t":
            _, proto, sip, sp, dip, dpn, _sid = key
            mk = dict(eth_type=0x0800, ipv4_src=sip, ipv4_dst=dip)
            if proto == "TCP":
                mk["ip_proto"] = 6
                if sp  is not None: mk["tcp_src"] = int(sp)
                if dpn is not None: mk["tcp_dst"] = int(dpn)
            elif proto == "UDP":
                mk["ip_proto"] = 17
                if sp  is not None: mk["udp_src"] = int(sp)
                if dpn is not None: mk["udp_dst"] = int(dpn)
            elif proto == "ICMP":
                mk["ip_proto"] = 1
            _send(mk)
        else:
            return

        # lưu map cookie->key để dọn đúng lúc
        self.ids_cookie_key[(dp.id, cookie)] = key

    def _ids_apply_on_dpid(self, dpid: int, key: Tuple, now: float) -> bool:
        dp = self.datapaths.get(dpid)
        if not dp: return False
        if self._ids_is_active(dpid, key, now): return False
        self._ids_install_drop(dp, key)
        self._ids_mark_active(dpid, key, now)
        return True

    def _ids_apply(self, key: Tuple):
        now = time.time()
        # throttle theo key
        if now - self.ids_last_block_ts[key] < REBLOCK_GRACE:
            return
        installed = 0
        # phạm vi áp: nếu TARGET_DPID != 0 → chỉ dpid đó; ngược lại ưu tiên sL3
        dpids = []
        if TARGET_DPID:
            if TARGET_DPID in self.datapaths: dpids = [TARGET_DPID]
        else:
            if self.l3_dpid in self.datapaths: dpids = [self.l3_dpid]
        # nếu chưa xác định được sL3 thì có thể bỏ qua (đợi vòng sau)
        for dpid in dpids:
            try:
                if self._ids_apply_on_dpid(dpid, key, now):
                    installed += 1
            except Exception as e:
                self.logger.error("IDS install_drop failed dpid=%s key=%s err=%s", dpid, key, e)
        self.ids_last_block_ts[key] = now
        if installed > 0:
            self.logger.warning("IDS BLOCK(installed=%d) mode=%s key=%s", installed, BLOCK_MODE, key)

    def _ids_handle_eve_line(self, line: str):
        if not line: return
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return
        key = self._ids_key_from_event(ev)
        if key is not None:
            self._ids_apply(key)

    def _ids_open_tail(self, path):
        while True:
            try:
                fp = open(path, "r", buffering=1)
                fp.seek(0, os.SEEK_END)
                self.logger.info("IDS tailing EVE: %s", path)
                return fp, os.fstat(fp.fileno()).st_ino
            except FileNotFoundError:
                self.logger.warning("IDS waiting for EVE file %s ...", path)
                time.sleep(1.0)

    def _ids_eve_tail_loop(self):
        path = EVE_JSON_PATH
        fp = None
        ino = None
        while True:
            try:
                if fp is None:
                    fp, ino = self._ids_open_tail(path)
                line = fp.readline()
                if not line:
                    try:
                        if os.stat(path).st_ino != ino:
                            fp.close()
                            fp = None
                            continue
                    except FileNotFoundError:
                        fp.close()
                        fp = None
                        continue
                    time.sleep(0.1)
                    continue
                self._ids_handle_eve_line(line.strip())
            except Exception as e:
                self.logger.error("IDS EVE reader error: %s", e)
                time.sleep(1.0)
                try:
                    if fp: fp.close()
                except Exception:
                    pass
                fp = None

    # ===== IDS RULES (CRUD local.rules) =====
    def ids_rules_list(self):
        rules = []
        try:
            with open(SURICATA_LOCAL_RULES, 'r', encoding='utf-8', errors='ignore') as f:
                for ln in f:
                    line = ln.strip()
                    if not line or line.startswith('#'): continue
                    msg = None
                    sid = None
                    m = re.search(r'msg\s*:\s*"(.*?)"', line)
                    if m: msg = m.group(1)
                    m = re.search(r'\bsid\s*:\s*(\d+)', line)
                    if m: sid = int(m.group(1))
                    rules.append({"raw": line, "msg": msg, "sid": sid})
            return {"file": SURICATA_LOCAL_RULES, "total": len(rules), "items": rules}
        except PermissionError as e:
            return {"error": f"Permission denied reading {SURICATA_LOCAL_RULES}. Run ryu as root OR grant group access.", "details": str(e), "items": []}
        except FileNotFoundError as e:
            return {"error": f"File not found: {SURICATA_LOCAL_RULES}", "details": str(e), "items": []}
        except Exception as e:
            return {"error": str(e), "file": SURICATA_LOCAL_RULES, "items": []}

    def _reload_suricata(self):
        if not SURICATA_RELOAD_CMD: return {"reloaded": False, "cmd": None, "rc": None}
        try:
            rc = subprocess.call(SURICATA_RELOAD_CMD, shell=True)
            return {"reloaded": rc == 0, "cmd": SURICATA_RELOAD_CMD, "rc": rc}
        except Exception as e:
            return {"reloaded": False, "cmd": SURICATA_RELOAD_CMD, "error": str(e)}

    def ids_rule_add(self, raw_rule: str, replace_sid: bool = True, do_reload: bool = True):
        raw_rule = (raw_rule or '').strip()
        if not raw_rule: raise ValueError("empty rule")
        m = re.search(r'\bsid\s*:\s*(\d+)', raw_rule)
        sid = int(m.group(1)) if m else None

        # backup
        try:
            if os.path.exists(SURICATA_LOCAL_RULES):
                with open(SURICATA_LOCAL_RULES, 'rb') as s, open(SURICATA_LOCAL_RULES_BAK, 'wb') as d:
                    d.write(s.read())
        except Exception as e:
            self.logger.warning("[IDS] backup failed: %s", e)

        # read old
        lines = []
        try:
            if os.path.exists(SURICATA_LOCAL_RULES):
                with open(SURICATA_LOCAL_RULES, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [ln.rstrip('\n') for ln in f.readlines()]
        except PermissionError as e:
            raise PermissionError(f"Permission denied reading {SURICATA_LOCAL_RULES}: {e}")

        # write new
        wrote = False
        try:
            with open(SURICATA_LOCAL_RULES, 'w', encoding='utf-8') as f:
                replaced = False
                for ln in lines:
                    if replace_sid and sid is not None and re.search(rf'\bsid\s*:\s*{sid}\b', ln):
                        if not replaced:
                            f.write(raw_rule + '\n')
                            replaced = True
                            wrote = True
                    else:
                        f.write(ln + '\n')
                if not replaced:
                    f.write(raw_rule + '\n')
                    wrote = True
        except PermissionError as e:
            raise PermissionError(f"Permission denied writing {SURICATA_LOCAL_RULES}: {e}")

        reload_info = self._reload_suricata() if (wrote and do_reload) else {"reloaded": False}
        return {"sid": sid, "wrote": wrote, "reloaded": reload_info}

    def ids_rule_delete(self, sid: int, do_reload: bool = True):
        sid = int(sid)
        # backup
        try:
            if os.path.exists(SURICATA_LOCAL_RULES):
                with open(SURICATA_LOCAL_RULES, 'rb') as s, open(SURICATA_LOCAL_RULES_BAK, 'wb') as d:
                    d.write(s.read())
        except Exception as e:
            self.logger.warning("[IDS] backup failed: %s", e)

        if not os.path.exists(SURICATA_LOCAL_RULES):
            return {"deleted": 0, "reloaded": False}

        try:
            with open(SURICATA_LOCAL_RULES, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [ln.rstrip('\n') for ln in f.readlines()]
        except PermissionError as e:
            raise PermissionError(f"Permission denied reading {SURICATA_LOCAL_RULES}: {e}")

        kept = []
        deleted = 0
        for ln in lines:
            if re.search(rf'\bsid\s*:\s*{sid}\b', ln): deleted += 1
            else: kept.append(ln)

        try:
            with open(SURICATA_LOCAL_RULES, 'w', encoding='utf-8') as f:
                for ln in kept: f.write(ln + '\n')
        except PermissionError as e:
            raise PermissionError(f"Permission denied writing {SURICATA_LOCAL_RULES}: {e}")

        reload_info = self._reload_suricata() if (deleted > 0 and do_reload) else {"reloaded": False}
        return {"deleted": deleted, "reloaded": reload_info}

    # ===== IDS ALERTS (tail/tac/grep -m LIMIT) =====
    def ids_alerts_list(self, limit: int = 10, types: List[str] = None, since_ts: float = None):
        path = EVE_JSON_PATH
        limit = max(1, min(int(limit or 10), 2000))
        picked = [t.strip().lower() for t in (types or ['alert']) if t.strip()]
        picked_set = set(picked) if picked else {'alert'}

        try:
            st = os.stat(path)
        except FileNotFoundError as e:
            return {"error": f"File not found: {path}", "details": str(e), "items": []}
        except PermissionError as e:
            return {"error": f"Permission denied reading {path}", "details": str(e), "items": []}
        except Exception as e:
            return {"error": str(e), "file": path, "items": []}

        def _parse_one(ev: dict) -> dict:
            et = (ev.get('event_type') or '').lower()
            base = {
                "ts": ev.get('timestamp'),
                "type": et,
                "src_ip": ev.get('src_ip'), "src_port": ev.get('src_port'),
                "dst_ip": ev.get('dest_ip') or ev.get('dst_ip'),
                "dst_port": ev.get('dest_port') or ev.get('dst_port'),
                "proto": (ev.get('proto') or '').upper() if ev.get('proto') else None,
            }
            if et == 'alert':
                al = ev.get('alert', {}) or {}
                base.update({
                    "signature": al.get('signature'),
                    "sid": al.get('signature_id') or al.get('sid'),
                    "severity": al.get('severity'),
                    "category": al.get('category'),
                })
            return base

        if picked_set == {"alert"}:
            TAIL_INITIAL = 10000
            TAIL_MAX     = 800000
            tail_lines   = TAIL_INITIAL
            while tail_lines <= TAIL_MAX:
                try:
                    cmd = (
                        f"tail -n {tail_lines} {path} | "
                        f"tac | "
                        f"grep -m {limit} '\"event_type\"\\s*:\\s*\"alert\"'"
                    )
                    res = subprocess.run(
                        ["/bin/sh", "-c", cmd],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, check=False, env={**os.environ, "LC_ALL": "C"}
                    )
                    if res.returncode not in (0, 1):
                        break
                    items = []
                    for line in res.stdout.splitlines():
                        line = line.strip()
                        if not line: continue
                        try: ev = json.loads(line)
                        except Exception: continue
                        if (ev.get('event_type') or '').lower() != 'alert': continue
                        items.append(_parse_one(ev))
                        if len(items) >= limit: break
                    if items:
                        return {"file": path, "total": len(items), "items": items}
                    tail_lines = min(tail_lines * 2, TAIL_MAX)
                except Exception:
                    break
        # tổng quát
        def parse_lines(text: str, need: int):
            out = []
            for s in reversed(text.splitlines()):
                if len(out) >= need: break
                s = s.strip()
                if not s: continue
                try: ev = json.loads(s)
                except: continue
                et = (ev.get('event_type') or '').lower()
                if picked_set and et not in picked_set: continue
                out.append(_parse_one(ev))
            return out

        TAIL_INITIAL = 2000
        TAIL_MAX     = 500_000
        tail_lines   = TAIL_INITIAL
        items: List[dict] = []
        try:
            while tail_lines <= TAIL_MAX and len(items) < limit:
                res = subprocess.run(
                    ["tail", "-n", str(tail_lines), path],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, check=False, env={**os.environ, "LC_ALL": "C"}
                )
                if res.returncode not in (0, 1):
                    break
                items = parse_lines(res.stdout, limit)
                if len(items) >= limit: break
                tail_lines = min(tail_lines * 2, TAIL_MAX)
        except Exception as e:
            return {"error": str(e), "file": path, "items": []}

        # fallback đọc ngược theo khối
        if len(items) < limit:
            CHUNK = 256 * 1024
            MAX_SCAN = 16 * 1024 * 1024
            to_read = min(MAX_SCAN, st.st_size)
            pos = st.st_size
            buf = b""
            raw = []
            try:
                with open(path, 'rb', buffering=0) as f:
                    while pos > 0 and len(raw) < (limit * 6):
                        step = CHUNK if pos >= CHUNK else pos
                        pos -= step
                        f.seek(pos)
                        chunk = f.read(step)
                        buf = chunk + buf
                        parts = buf.split(b'\n')
                        buf = parts[0]
                        for ln in parts[-1:0:-1]:
                            if ln:
                                try:
                                    s = ln.decode('utf-8', errors='ignore').strip()
                                except Exception:
                                    continue
                                if s:
                                    raw.append(s)
                        if (st.st_size - pos) >= to_read:
                            break
                    try:
                        s = buf.decode('utf-8', errors='ignore').strip()
                        if s:
                            raw.append(s)
                    except Exception:
                        pass
            except PermissionError as e:
                return {"error": f"Permission denied reading {path}", "details": str(e), "items": []}
            except Exception as e:
                return {"error": str(e), "file": path, "items": []}

            for s in raw:
                if len(items) >= limit: break
                try: ev = json.loads(s)
                except: continue
                et = (ev.get('event_type') or '').lower()
                if picked_set and et not in picked_set: continue
                items.append(_parse_one(ev))

        return {"file": path, "total": len(items), "items": items}
