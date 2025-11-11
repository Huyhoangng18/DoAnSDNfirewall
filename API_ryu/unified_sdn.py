#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
unified_sdn.py — SDN (Ryu) với 3 nhóm chức năng hợp nhất:
- RULES (table 0): CRUD drop/allow TCP, lưu /tmp/rules.json, áp trên sL3 (mặc định) hoặc all.
- TI (table 1): tự cập nhật IP/CIDR chỉ trên sL3, lưu /tmp/ti_blacklist.jsonl, REST paging.
- IDS (table 3): auto-block theo Suricata EVE (eve.json) với BLOCK_MODE, de-dup, FLOW_REMOVED; CRUD /etc/suricata/rules/local.rules; đọc alerts nhanh.

Chạy (cần quyền đọc/ghi Suricata paths):
  sudo env SURICATA_RELOAD_CMD="systemctl reload suricata" ryu-manager --observe-links unified_sdn.py
"""

import os, json, time, ipaddress, hashlib, threading, re, requests, subprocess
from collections import defaultdict
from typing import Dict, Any, Set, Tuple, List, Optional

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event as topo_event
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from webob import Response

# ---------- file paths ----------
RULES_FILE = '/tmp/rules.json'
TI_FILE    = '/tmp/ti_blacklist.jsonl'

# IDS (root paths)
SURICATA_LOCAL_RULES     = '/etc/suricata/rules/local.rules'
SURICATA_LOCAL_RULES_BAK = '/etc/suricata/rules/local.rules.bak'
EVE_JSON_PATH            = os.getenv("EVE_JSON_PATH", "/var/log/suricata/eve.json")
SURICATA_RELOAD_CMD      = os.getenv('SURICATA_RELOAD_CMD', '').strip()

# ---------- cookies ----------
COOKIE_BASELINE = (0xA1 << 56)
COOKIE_RULES    = (0xA2 << 56)
COOKIE_TI       = (0xA3 << 56)
COOKIE_IDS      = (0xA4 << 56)   # + (sid & 0xFFFF)

# ---------- tables & priority ----------
TBL = {"T0":0,"TI":1,"IDS":3,"CT":4,"L3":5,"L2":6,"SVC":7,"QOS":8,"TLM":9,"EGRESS":10}
PRIO_TI_DROP = 35000

# ---------- sL3 detect ----------
FORCE_L3_BRIDGE_NAME = "sL3"
VLAN_NAME_HINT       = "-vlan"
GRACE_PICK_S         = 5.0  # chờ vài giây nhận đủ PortDesc/Link trước khi chốt sL3

# ---------- TI auto update (ENV tunable) ----------
TI_SOURCES = [s.strip() for s in os.getenv(
    "TI_SOURCES",
    "https://lists.blocklist.de/lists/all.txt,"
    "https://iplists.firehol.org/files/firehol_level1.netset"
).split(",") if s.strip()]
TI_CONNECT_TIMEOUT = float(os.getenv("TI_CONNECT_TIMEOUT", "5"))
TI_READ_TIMEOUT    = float(os.getenv("TI_READ_TIMEOUT", "20"))
TI_RETRIES_PER_SRC = int(os.getenv("TI_RETRIES_PER_SRC", "2"))
TI_BACKOFF_BASE_S  = float(os.getenv("TI_BACKOFF_BASE_S", "1.5"))
TI_BACKOFF_MAX_S   = float(os.getenv("TI_BACKOFF_MAX_S", "6.0"))
TI_MUTE_AFTER_FAIL = int(os.getenv("TI_MUTE_AFTER_FAIL", "3"))
TI_MUTE_SECONDS    = int(os.getenv("TI_MUTE_SECONDS", "900"))
FETCH_INTERVAL_S   = int(os.getenv("FETCH_INTERVAL_S", "300"))
MAX_NEW_PER_FETCH  = int(os.getenv("MAX_NEW_PER_FETCH", "2000"))

# ---------- IDS (ENV tunable) ----------
BLOCK_MODE      = os.getenv("BLOCK_MODE", "src_ip").lower()  # src_ip | src_ip_proto | 5tuple | dst_ip
BLOCK_PRIORITY  = int(os.getenv("BLOCK_PRIORITY", "60000"))
HARD_TIMEOUT    = int(os.getenv("HARD_TIMEOUT", "300"))      # giây; 0 = vĩnh viễn (không khuyến nghị)
REBLOCK_GRACE   = float(os.getenv("REBLOCK_GRACE", "5.0"))   # giây, chống spam
SEVERITY_MIN    = int(os.getenv("SEVERITY_MIN", "2"))        # chỉ block khi severity <= 2
TARGET_DPID     = int(os.getenv("TARGET_DPID", "0"))         # 0 = theo sL3; !=0 chỉ áp lên dpid cụ thể
WHITELIST_IPS   = set(ip.strip() for ip in os.getenv("WHITELIST_IPS", "127.0.0.1").split(",") if ip.strip())
WHITELIST_SIDS  = set(int(x) for x in os.getenv("WHITELIST_SIDS", "").split(",") if x.strip().isdigit())

# ---------- REST base ----------
APP_NAME = 'unified_sdn'
REST_BASE_RYU = '/ryu'
REST_BASE_IDS = '/ids'


class UnifiedSDN(app_manager.RyuApp):
    _CONTEXTS = {'wsgi': WSGIApplication}
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        self.wsgi: WSGIApplication = kwargs['wsgi']
        super().__init__(*args, **kwargs)

        # topo & roles
        self.datapaths: Dict[int, Any] = {}
        self.dp_ports: Dict[int, List[str]] = {}
        self.neighbors: Dict[int, Set[int]] = {}
        self.l3_dpid: Optional[int] = None
        self.applied_role: Dict[int, str] = {}
        self.start_ts = time.time()
        self.lock = threading.RLock()

        # RULES state
        self.rules: Dict[str, dict] = {}
        self._load_rules_file()

        # TI state
        self.ti_set: Set[Tuple[str,str]] = set()
        self._load_ti_file()
        # TI health
        self._ti_fail_count: Dict[str, int] = {u: 0 for u in TI_SOURCES}
        self._ti_muted_until: Dict[str, float] = {u: 0.0 for u in TI_SOURCES}

        # IDS state (auto-block)
        self.ids_last_block_ts = defaultdict(float)      # key -> last ts (throttle)
        self.ids_active_until: Dict[Tuple[int, Tuple], float] = {}   # (dpid,key) -> expire_ts
        self.ids_cookie_key: Dict[Tuple[int, int], Tuple] = {}       # (dpid,cookie) -> key

        # REST
        self.wsgi.registory[UnifiedRest.__name__] = {APP_NAME: self}
        self.wsgi.register(UnifiedRest, {APP_NAME: self})

        # background: TI updater
        threading.Thread(target=self._ti_fetch_loop, daemon=True).start()
        # background: IDS EVE tailer
        threading.Thread(target=self._ids_eve_tail_loop, daemon=True).start()

        self.logger.info("UnifiedSDN ready: RULES@0, TI@1, IDS(auto-block@3 + rules+alerts view)")

    # ===== OF helpers =====
    def _add_flow(self, dp, table, prio, match, actions=None, inst=None, cookie=0,
                  hard_timeout=0, idle_timeout=0, flags=0):
        p, ofp = dp.ofproto_parser, dp.ofproto
        if inst is None:
            inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions or [])]
        mod = p.OFPFlowMod(datapath=dp, table_id=table, priority=prio, match=match,
                           instructions=inst, cookie=cookie,
                           hard_timeout=hard_timeout, idle_timeout=idle_timeout,
                           flags=flags)
        dp.send_msg(mod)

    def _del_by_cookie(self, dp, cookie):
        p, ofp = dp.ofproto_parser, dp.ofproto
        mod = p.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE, table_id=ofp.OFPTT_ALL,
                           out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                           cookie=cookie, cookie_mask=0xFFFFFFFFFFFFFFFF, match=p.OFPMatch())
        dp.send_msg(mod)

    # ===== pipeline =====
    def _install_pipeline(self, dp):
        ofp, p = dp.ofproto, dp.ofproto_parser
        act_norm = [p.OFPActionOutput(ofp.OFPP_NORMAL)]
        GOTO = lambda dst: [p.OFPInstructionGotoTable(dst)]

        # 0 -> T0 -> TI -> IDS -> CT -> L3 -> L2 -> SVC -> QOS -> TLM -> EGRESS
        self._add_flow(dp, 0, 0, p.OFPMatch(), inst=GOTO(TBL["T0"]))
        self._add_flow(dp, TBL["T0"], 0, p.OFPMatch(), inst=GOTO(TBL["TI"]), cookie=COOKIE_BASELINE)
        self._add_flow(dp, TBL["TI"], 0, p.OFPMatch(), inst=GOTO(TBL["IDS"]), cookie=COOKIE_BASELINE)
        self._add_flow(dp, TBL["IDS"], 0, p.OFPMatch(), inst=GOTO(TBL["CT"]),  cookie=COOKIE_BASELINE)
        self._add_flow(dp, TBL["CT"],  0, p.OFPMatch(), inst=GOTO(TBL["L3"]),  cookie=COOKIE_BASELINE)
        self._add_flow(dp, TBL["L3"],  0, p.OFPMatch(), inst=GOTO(TBL["L2"]),  cookie=COOKIE_BASELINE)
        self._add_flow(dp, TBL["L2"],  0, p.OFPMatch(), inst=GOTO(TBL["SVC"]), cookie=COOKIE_BASELINE)
        self._add_flow(dp, TBL["SVC"], 0, p.OFPMatch(), inst=GOTO(TBL["QOS"]), cookie=COOKIE_BASELINE)
        self._add_flow(dp, TBL["QOS"], 0, p.OFPMatch(), inst=GOTO(TBL["TLM"]), cookie=COOKIE_BASELINE)
        self._add_flow(dp, TBL["TLM"], 0, p.OFPMatch(), inst=GOTO(TBL["EGRESS"]), cookie=COOKIE_BASELINE)
        # EGRESS (ARP fast-path + NORMAL)
        self._add_flow(dp, TBL["EGRESS"], 40000, p.OFPMatch(eth_type=0x0806), actions=act_norm, cookie=COOKIE_BASELINE)
        self._add_flow(dp, TBL["EGRESS"], 0, p.OFPMatch(), actions=act_norm, cookie=COOKIE_BASELINE)

    # ===== sL3 pick =====
    def _score(self, dpid:int)->int:
        names = self.dp_ports.get(dpid, [])
        deg   = len(self.neighbors.get(dpid, set()))
        s = 0
        if any((n or '').startswith(FORCE_L3_BRIDGE_NAME) for n in names): s += 10000
        if any(VLAN_NAME_HINT in (n or '').lower() for n in names):       s += 3000
        s += 100*deg + len(names)
        return s

    def _pick_best_l3(self)->Optional[int]:
        if not self.datapaths: return None
        ranked = sorted(((self._score(d), d) for d in self.datapaths.keys()), reverse=True)
        if not ranked: return None
        best = ranked[0][1]
        # đợi một nhịp để có đủ tín hiệu trước khi chốt
        if time.time() - self.start_ts < GRACE_PICK_S: return None
        return best

    def _reselect_l3(self):
        best = self._pick_best_l3()
        if best is None: return
        if self.l3_dpid != best:
            old = self.l3_dpid
            self.l3_dpid = best
            if old is None:
                self.logger.info(f"[PIPE] Select sL3 dpid=0x{best:x}")
            else:
                self.logger.warning(f"[PIPE] Reselect sL3 0x{old:x} → 0x{best:x}")
            self.applied_role.clear()
            self._apply_roles_all()

    def _apply_roles_all(self):
        for dp in list(self.datapaths.values()):
            self._apply_role(dp)

    def _apply_role(self, dp):
        want = 'L3' if self.l3_dpid == dp.id else 'L2'
        if self.applied_role.get(dp.id) == want: return
        self._install_pipeline(dp)
        self.applied_role[dp.id] = want
        self.logger.info(f"[PIPE] set role {want} on dp=0x{dp.id:x}")
        if want == 'L3':
            self._apply_all_rules_to_dp(dp)
            for e in sorted(self.ti_set): self._install_ti_entry(dp, e)

    # ===== OF events =====
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        # yêu cầu PortDesc
        req = dp.ofproto_parser.OFPPortDescStatsRequest(dp, 0)
        dp.send_msg(req)
        threading.Timer(0.2, self._reselect_l3).start()

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def on_portdesc(self, ev):
        dp = ev.msg.datapath
        names=[]
        for p in ev.msg.body:
            try: nm = p.name.decode('utf-8') if isinstance(p.name, bytes) else p.name
            except: nm = str(getattr(p,'port_no','unknown'))
            names.append(nm)
        with self.lock: self.dp_ports[dp.id] = names
        self._reselect_l3()

    @set_ev_cls(topo_event.EventLinkAdd)
    def on_link_add(self, ev):
        s, d = ev.link.src.dpid, ev.link.dst.dpid
        self.neighbors.setdefault(s,set()).add(d)
        self.neighbors.setdefault(d,set()).add(s)
        self._reselect_l3()

    @set_ev_cls(topo_event.EventLinkDelete)
    def on_link_del(self, ev):
        s, d = ev.link.src.dpid, ev.link.dst.dpid
        if s in self.neighbors: self.neighbors[s].discard(d)
        if d in self.neighbors: self.neighbors[d].discard(s)
        self._reselect_l3()

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self._install_pipeline(dp)
            self._apply_role(dp)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    # ===== FLOW_REMOVED cho IDS =====
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def on_flow_removed(self, ev):
        dp = ev.msg.datapath
        cookie = ev.msg.cookie
        key = self.ids_cookie_key.pop((dp.id, cookie), None)
        if key is not None:
            self.ids_active_until.pop((dp.id, key), None)
            self.logger.info("IDS FLOW_REMOVED dpid=%s key=%s reason=%s", dp.id, key, ev.msg.reason)

    # ===== RULES (table 0) =====
    def _rule_cookie(self, rid:str)->int:
        h = hashlib.sha256(rid.encode('utf-8')).digest()
        return COOKIE_RULES | (int.from_bytes(h[:5],'big') & 0xFFFFFFFFFF)

    def _rule_match(self, dp, m:dict):
        p = dp.ofproto_parser
        kw={'eth_type':0x0800, 'ip_proto':6}
        if m.get('ipv4_src'): kw['ipv4_src']=m['ipv4_src']
        if m.get('ipv4_dst'): kw['ipv4_dst']=m['ipv4_dst']
        if m.get('tcp_dst'):  kw['tcp_dst']=int(m['tcp_dst'])
        return p.OFPMatch(**kw)

    def _rules_scope_dpids(self, scope):
        if scope == 'all': return list(self.datapaths.keys())
        # mặc định: áp trên sL3
        return [self.l3_dpid] if (self.l3_dpid in self.datapaths) else []

    def _install_rule_on_dp(self, dp, rule:dict):
        p, ofp = dp.ofproto_parser, dp.ofproto
        actions = [] if rule['action']=='drop' else [p.OFPActionOutput(ofp.OFPP_NORMAL)]
        match = self._rule_match(dp, rule['match'])
        self._add_flow(dp, TBL["T0"], int(rule['priority']), match, actions=actions, cookie=self._rule_cookie(rule['rule_id']))

    def _delete_rule_on_all_dp(self, rid:str):
        ck = self._rule_cookie(rid)
        for dp in list(self.datapaths.values()):
            self._del_by_cookie(dp, ck)

    def _apply_all_rules_to_dp(self, dp):
        for r in self.rules.values():
            if dp.id in self._rules_scope_dpids(r.get('scope','l3')):
                self._install_rule_on_dp(dp, r)

    def _load_rules_file(self):
        if not os.path.exists(RULES_FILE): self.rules={}; return
        try:
            with open(RULES_FILE,'r',encoding='utf-8') as f:
                self.rules=json.load(f)
                if not isinstance(self.rules, dict): self.rules={}
            self.logger.info(f"[RULES] loaded {len(self.rules)} from {RULES_FILE}")
        except Exception as e:
            self.logger.error(f"[RULES] load error: {e}"); self.rules={}

    def _save_rules_file(self):
        try:
            with open(RULES_FILE,'w',encoding='utf-8') as f:
                json.dump(self.rules,f,ensure_ascii=False,indent=2)
        except Exception as e:
            self.logger.error(f"[RULES] write error: {e}")

    # public rules
    def rules_list(self):
        return {"count": len(self.rules), "items": list(self.rules.values())}

    def rules_upsert(self, rule:dict):
        for k in ['rule_id','priority','action','match']:
            if k not in rule: raise ValueError(f"missing {k}")
        if rule['action'] not in ('drop','allow'):
            raise ValueError('action must be drop/allow')
        rid = rule['rule_id']
        old = self.rules.get(rid)
        if old and old == rule: return rule
        if old and old != rule:
            self._delete_rule_on_all_dp(rid)
        for dpid in self._rules_scope_dpids(rule.get('scope','l3')):
            dp = self.datapaths.get(dpid)
            if dp: self._install_rule_on_dp(dp, rule)
        self.rules[rid]=rule; self._save_rules_file(); return rule

    def rules_delete(self, rid:str)->bool:
        if rid not in self.rules: return False
        self._delete_rule_on_all_dp(rid)
        self.rules.pop(rid); self._save_rules_file(); return True

    # ===== TI (table 1) =====
    @staticmethod
    def _parse_ti_token(token:str)->Optional[Tuple[str,str]]:
        try:
            if '/' in token:
                n = ipaddress.ip_network(token, strict=False)
                if isinstance(n, ipaddress.IPv4Network):
                    return (str(n.network_address), str(n.netmask))
            else:
                ip = ipaddress.ip_address(token)
                if isinstance(ip, ipaddress.IPv4Address):
                    return (str(ip), "255.255.255.255")
        except: return None
        return None

    def _install_ti_entry(self, dp, entry:Tuple[str,str]):
        addr, mask = entry
        p = dp.ofproto_parser
        m1 = p.OFPMatch(eth_type=0x0800, ipv4_src=(addr, mask))
        m2 = p.OFPMatch(eth_type=0x0800, ipv4_dst=(addr, mask))
        self._add_flow(dp, TBL["TI"], PRIO_TI_DROP, m1, actions=[], cookie=COOKIE_TI)
        self._add_flow(dp, TBL["TI"], PRIO_TI_DROP, m2, actions=[], cookie=COOKIE_TI)

    def _apply_ti_on_l3(self, entries:List[Tuple[str,str]]):
        if not (self.l3_dpid and self.l3_dpid in self.datapaths): return
        dp = self.datapaths[self.l3_dpid]
        for e in entries: self._install_ti_entry(dp, e)

    def _load_ti_file(self):
        if not os.path.exists(TI_FILE): return
        cnt=0
        with open(TI_FILE,'r',encoding='utf-8') as f:
            for line in f:
                s=line.strip()
                if not s: continue
                try: obj=json.loads(s)
                except: obj=s
                if isinstance(obj,str):
                    ent=self._parse_ti_token(obj)
                elif isinstance(obj,dict) and obj.get('cidr'):
                    ent=self._parse_ti_token(obj['cidr'])
                elif isinstance(obj,dict) and obj.get('ip'):
                    ent=self._parse_ti_token(obj['ip'])
                else: ent=None
                if ent: self.ti_set.add(ent); cnt+=1
        self.logger.info(f"[TI] loaded {cnt} entries from {TI_FILE}")

    def _append_ti_file(self, entries:List[Tuple[str,str]]):
        if not entries: return
        with open(TI_FILE,'a',encoding='utf-8') as f:
            for a,m in entries:
                net = ipaddress.IPv4Network((a,m), strict=False)
                f.write(json.dumps({"cidr":str(net),"ts":int(time.time())},ensure_ascii=False)+"\n")

    def _write_ti_file_full(self):
        with open(TI_FILE,'w',encoding='utf-8') as f:
            for a,m in sorted(self.ti_set):
                net = ipaddress.IPv4Network((a,m), strict=False)
                f.write(json.dumps({"cidr":str(net),"ts":int(time.time())},ensure_ascii=False)+"\n")

    def _ti_fetch_once(self) -> List[str]:
        out: List[str] = []
        headers = {"User-Agent": "UnifiedSDN/1.0 (+ryu-unified)"}
        timeout = (TI_CONNECT_TIMEOUT, TI_READ_TIMEOUT)
        now = time.time()
        for url in TI_SOURCES:
            if now < self._ti_muted_until.get(url, 0.0):
                self.logger.debug("[TI] muted source: %s (remain %.0fs)", url, self._ti_muted_until[url]-now)
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

        seen=set(); uniq=[]
        for s in out:
            if s not in seen:
                seen.add(s); uniq.append(s)
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
                            self.ti_set.add(ent); added.append(ent)
                    if added:
                        self._apply_ti_on_l3(added)
                        self._append_ti_file(added)
                        self.logger.info("[TI] auto-added %d (total=%d)", len(added), len(self.ti_set))
            except Exception as e:
                self.logger.warning("[TI] updater error: %s", e)
            time.sleep(FETCH_INTERVAL_S)

    # public TI
    def ti_list(self, offset:int=0, limit:int=500):
        items = [{"type":"cidr", "value": str(ipaddress.IPv4Network((a,m), strict=False))}
                 for (a,m) in sorted(self.ti_set)]
        total = len(items)
        off = max(0, int(offset)); lim = max(1, min(int(limit), 2000))
        return {"total": total, "offset": off, "limit": lim, "items": items[off: off+lim]}

    def ti_add(self, raw_items:List[str]):
        added=[]
        for s in (raw_items or []):
            ent = self._parse_ti_token(str(s).strip())
            if ent and ent not in self.ti_set:
                self.ti_set.add(ent); added.append(ent)
        self._apply_ti_on_l3(added)
        self._append_ti_file(added)
        return {"added":[str(ipaddress.IPv4Network((a,m), strict=False)) for a,m in added]}

    def ti_del(self, raw_items:List[str]):
        rm=[]
        for s in (raw_items or []):
            ent=self._parse_ti_token(str(s).strip())
            if ent and ent in self.ti_set: rm.append(ent)
        for e in rm: self.ti_set.discard(e)
        if self.l3_dpid and self.l3_dpid in self.datapaths:
            self._del_by_cookie(self.datapaths[self.l3_dpid], COOKIE_TI)
            self._apply_ti_on_l3(sorted(self.ti_set))
        self._write_ti_file_full()
        return {"removed":[str(ipaddress.IPv4Network((a,m), strict=False)) for a,m in rm]}

    # ===== IDS AUTO-BLOCK (table 3) =====
    def _ids_key_from_event(self, ev:dict) -> Optional[Tuple]:
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
        sp = ev.get('src_port'); dpn = ev.get('dest_port') or ev.get('dst_port')

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

    def _ids_is_active(self, dpid:int, key:Tuple, now:float)->bool:
        exp = self.ids_active_until.get((dpid, key))
        return (exp is not None) and (now < exp)

    def _ids_mark_active(self, dpid:int, key:Tuple, now:float):
        self.ids_active_until[(dpid, key)] = now + (HARD_TIMEOUT - 1 if HARD_TIMEOUT > 0 else 600)

    def _ids_install_drop(self, dp, key:Tuple):
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

    def _ids_apply_on_dpid(self, dpid:int, key:Tuple, now:float)->bool:
        dp = self.datapaths.get(dpid)
        if not dp: return False
        if self._ids_is_active(dpid, key, now): return False
        self._ids_install_drop(dp, key)
        self._ids_mark_active(dpid, key, now)
        return True

    def _ids_apply(self, key:Tuple):
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

    def _ids_handle_eve_line(self, line:str):
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
        fp = None; ino = None
        while True:
            try:
                if fp is None:
                    fp, ino = self._ids_open_tail(path)
                line = fp.readline()
                if not line:
                    try:
                        if os.stat(path).st_ino != ino:
                            fp.close(); fp=None; continue
                    except FileNotFoundError:
                        fp.close(); fp=None; continue
                    time.sleep(0.1); continue
                self._ids_handle_eve_line(line.strip())
            except Exception as e:
                self.logger.error("IDS EVE reader error: %s", e)
                time.sleep(1.0)
                try:
                    if fp: fp.close()
                except Exception:
                    pass
                fp=None

    # ===== IDS RULES (CRUD local.rules) =====
    def ids_rules_list(self):
        rules=[]
        try:
            with open(SURICATA_LOCAL_RULES,'r',encoding='utf-8', errors='ignore') as f:
                for ln in f:
                    line=ln.strip()
                    if not line or line.startswith('#'): continue
                    msg = None; sid=None
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
            return {"reloaded": rc==0, "cmd": SURICATA_RELOAD_CMD, "rc": rc}
        except Exception as e:
            return {"reloaded": False, "cmd": SURICATA_RELOAD_CMD, "error": str(e)}

    def ids_rule_add(self, raw_rule:str, replace_sid:bool=True, do_reload:bool=True):
        raw_rule = (raw_rule or '').strip()
        if not raw_rule: raise ValueError("empty rule")
        m = re.search(r'\bsid\s*:\s*(\d+)', raw_rule)
        sid = int(m.group(1)) if m else None

        # backup
        try:
            if os.path.exists(SURICATA_LOCAL_RULES):
                with open(SURICATA_LOCAL_RULES,'rb') as s, open(SURICATA_LOCAL_RULES_BAK,'wb') as d:
                    d.write(s.read())
        except Exception as e:
            self.logger.warning("[IDS] backup failed: %s", e)

        # read old
        lines=[]
        try:
            if os.path.exists(SURICATA_LOCAL_RULES):
                with open(SURICATA_LOCAL_RULES,'r',encoding='utf-8',errors='ignore') as f:
                    lines = [ln.rstrip('\n') for ln in f.readlines()]
        except PermissionError as e:
            raise PermissionError(f"Permission denied reading {SURICATA_LOCAL_RULES}: {e}")

        # write new
        wrote=False
        try:
            with open(SURICATA_LOCAL_RULES,'w',encoding='utf-8') as f:
                replaced=False
                for ln in lines:
                    if replace_sid and sid is not None and re.search(rf'\bsid\s*:\s*{sid}\b', ln):
                        if not replaced:
                            f.write(raw_rule+'\n'); replaced=True; wrote=True
                    else:
                        f.write(ln+'\n')
                if not replaced:
                    f.write(raw_rule+'\n'); wrote=True
        except PermissionError as e:
            raise PermissionError(f"Permission denied writing {SURICATA_LOCAL_RULES}: {e}")

        reload_info = self._reload_suricata() if (wrote and do_reload) else {"reloaded": False}
        return {"sid": sid, "wrote": wrote, "reloaded": reload_info}

    def ids_rule_delete(self, sid:int, do_reload:bool=True):
        sid=int(sid)
        # backup
        try:
            if os.path.exists(SURICATA_LOCAL_RULES):
                with open(SURICATA_LOCAL_RULES,'rb') as s, open(SURICATA_LOCAL_RULES_BAK,'wb') as d:
                    d.write(s.read())
        except Exception as e:
            self.logger.warning("[IDS] backup failed: %s", e)

        if not os.path.exists(SURICATA_LOCAL_RULES):
            return {"deleted": 0, "reloaded": False}

        try:
            with open(SURICATA_LOCAL_RULES,'r',encoding='utf-8',errors='ignore') as f:
                lines = [ln.rstrip('\n') for ln in f.readlines()]
        except PermissionError as e:
            raise PermissionError(f"Permission denied reading {SURICATA_LOCAL_RULES}: {e}")

        kept=[]; deleted=0
        for ln in lines:
            if re.search(rf'\bsid\s*:\s*{sid}\b', ln): deleted+=1
            else: kept.append(ln)

        try:
            with open(SURICATA_LOCAL_RULES,'w',encoding='utf-8') as f:
                for ln in kept: f.write(ln+'\n')
        except PermissionError as e:
            raise PermissionError(f"Permission denied writing {SURICATA_LOCAL_RULES}: {e}")

        reload_info = self._reload_suricata() if (deleted>0 and do_reload) else {"reloaded": False}
        return {"deleted": deleted, "reloaded": reload_info}

    # ===== IDS ALERTS (tail/tac/grep -m LIMIT) =====
    def ids_alerts_list(self, limit:int=10, types:List[str]=None, since_ts:float=None):
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
        def parse_lines(text: str, need:int):
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


# ===== REST Controller =====
class UnifiedRest(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app: UnifiedSDN = data[APP_NAME]

    # ---- RULES ----
    @route('rules_list', REST_BASE_RYU + '/rules', methods=['GET'])
    def rules_list(self, req, **kwargs):
        return Response(body=json.dumps(self.app.rules_list(), ensure_ascii=False).encode('utf-8'),
                        content_type='application/json; charset=utf-8')

    @route('rules_add', REST_BASE_RYU + '/rules', methods=['POST'])
    def rules_add(self, req, **kwargs):
        try:
            rule = json.loads(req.body) if req.body else {}
            saved = self.app.rules_upsert(rule)
            return Response(body=json.dumps(saved, ensure_ascii=False).encode('utf-8'),
                            content_type='application/json; charset=utf-8')
        except Exception as e:
            return Response(body=json.dumps({"error": str(e)}, ensure_ascii=False).encode('utf-8'),
                            status=400, content_type='application/json; charset=utf-8')

    @route('rules_del', REST_BASE_RYU + '/rules/{rid}', methods=['DELETE'])
    def rules_del(self, req, rid, **kwargs):
        ok = self.app.rules_delete(rid)
        payload = {"deleted": rid} if ok else {"error": "not found"}
        return Response(body=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
                        status=200 if ok else 404, content_type='application/json; charset=utf-8')

    # ---- TI (paging) ----
    @route('ti_list', REST_BASE_RYU + '/ti', methods=['GET'])
    def ti_list(self, req, **kwargs):
        q = req.GET
        off = int(q.get('offset', '0'))
        lim = int(q.get('limit', '500'))
        data = self.app.ti_list(off, lim)
        return Response(body=json.dumps(data, ensure_ascii=False).encode('utf-8'),
                        content_type='application/json; charset=utf-8')

    @route('ti_add', REST_BASE_RYU + '/ti', methods=['POST'])
    def ti_add(self, req, **kwargs):
        try:
            body = json.loads(req.body) if req.body else {}
            out = self.app.ti_add(body.get('items', []))
            return Response(body=json.dumps(out, ensure_ascii=False).encode('utf-8'),
                            content_type='application/json; charset=utf-8')
        except Exception as e:
            return Response(body=json.dumps({"error": str(e)}, ensure_ascii=False).encode('utf-8'),
                            status=400, content_type='application/json; charset=utf-8')

    @route('ti_del', REST_BASE_RYU + '/ti', methods=['DELETE'])
    def ti_del(self, req, **kwargs):
        try:
            body = json.loads(req.body) if req.body else {}
            out = self.app.ti_del(body.get('items', []))
            return Response(body=json.dumps(out, ensure_ascii=False).encode('utf-8'),
                            content_type='application/json; charset=utf-8')
        except Exception as e:
            return Response(body=json.dumps({"error": str(e)}, ensure_ascii=False).encode('utf-8'),
                            status=400, content_type='application/json; charset=utf-8')

    # ---- IDS RULES (CRUD) ----
    @route('ids_rules_get', REST_BASE_IDS + '/rules', methods=['GET'])
    def ids_rules_get(self, req, **kwargs):
        data = self.app.ids_rules_list()
        return Response(body=json.dumps(data, ensure_ascii=False).encode('utf-8'),
                        content_type='application/json; charset=utf-8')

    @route('ids_rules_post', REST_BASE_IDS + '/rules', methods=['POST'])
    def ids_rules_post(self, req, **kwargs):
        try:
            body = json.loads(req.body) if req.body else {}
            raw = body.get('raw')
            replace = bool(body.get('replace_sid', True))
            reload_ = bool(body.get('reload', True))
            out = self.app.ids_rule_add(raw, replace_sid=replace, do_reload=reload_)
            return Response(body=json.dumps(out, ensure_ascii=False).encode('utf-8'),
                            content_type='application/json; charset=utf-8')
        except Exception as e:
            return Response(body=json.dumps({"error": str(e)}, ensure_ascii=False).encode('utf-8'),
                            status=400, content_type='application/json; charset=utf-8')

    @route('ids_rules_del_sid', REST_BASE_IDS + '/rules/{sid}', methods=['DELETE'])
    def ids_rules_del_sid(self, req, sid, **kwargs):
        try:
            reload_ = bool((req.GET or {}).get('reload', 'true').lower()!='false')
            out = self.app.ids_rule_delete(int(sid), do_reload=reload_)
            return Response(body=json.dumps(out, ensure_ascii=False).encode('utf-8'),
                            content_type='application/json; charset=utf-8')
        except Exception as e:
            return Response(body=json.dumps({"error": str(e)}, ensure_ascii=False).encode('utf-8'),
                            status=400, content_type='application/json; charset=utf-8')

    # ---- IDS ALERTS ----
    @route('ids_alerts', REST_BASE_IDS + '/alerts', methods=['GET'])
    def ids_alerts(self, req, **kwargs):
        q = req.GET
        lim = int(q.get('limit','200'))
        types = (q.get('types','alert') or 'alert').split(',')
        data = self.app.ids_alerts_list(limit=lim, types=types)
        return Response(body=json.dumps(data, ensure_ascii=False).encode('utf-8'),
                        content_type='application/json; charset=utf-8')

