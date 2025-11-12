#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ti_force_sL3_table1.py
----------------------------------
Ryu TI – CHỈ áp TI trên sL3 (Table 1), có tuỳ chọn ép nạp ngay vào sL3.

Tính năng chính:
- Pipeline tối giản:
    * L2 (không phải sL3): Table 0 -> NORMAL
    * sL3: Table 0 -> GOTO 1; Table 1: DROP theo ipv4_src/dst ∈ blacklist, default NORMAL
- ÉP CHỌN sL3 qua ENV:
    * FORCE_L3_DPID=3 (ưu tiên theo DPID)
    * FORCE_L3_NAME=sL3 (match prefix tên port, ví dụ sL3-vlan101, sL3-eth1)
- Debounce re-apply (gom sự kiện PortDesc/Topology), cài flow theo delta (không spam)
- Cookie tách bạch: BASE vs TI
- Tải TI từ các nguồn công khai định kỳ, lưu/persist vào file JSONL

Chạy:
    FORCE_L3_DPID=3 ryu-manager --observe-links ti_sdn.py
hoặc:
    FORCE_L3_NAME=sL3 ryu-manager --observe-links ti_sdn.py
"""

import ipaddress
import threading
import time
import json
import os
import requests
from typing import Set, List, Tuple, Optional, Dict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event as topo_event

# ===================== CẤU HÌNH =====================
# Giữ ý định sử dụng TABLE 1 cho TI
TABLE_TI: int = 1
PRIO_TI_DROP: int = 35000
PRIO_TI_DEFAULT: int = 0

# Cookie tách bạch
COOKIE_TI:   int = 0xAA11   # Chỉ cho TI (table 1)
COOKIE_BASE: int = 0xAA10   # Baseline (table 0 NORMAL/GOTO)

# Debounce re-apply
REAPPLY_DEBOUNCE_S: float = 0.5

# Lưu/persist TI
LOCAL_STATE_FILE: str = "/tmp/ti_blacklist.jsonl"

# Nguồn TI (có thể thay đổi)
TI_SOURCES: List[str] = [
    "https://lists.blocklist.de/lists/all.txt",
    "https://iplists.firehol.org/files/firehol_level1.netset",
]

FETCH_INTERVAL_S: int = 300
REQUEST_TIMEOUT_S: int = 15
ACCEPT_MIN_PREFIX: int = 24      # /24 trở lên
MAX_NEW_PER_CYCLE: int = 10000     # giới hạn cài mới mỗi chu kỳ

# FORCE chọn sL3
FORCE_L3_DPID: Optional[int] = None   # Ưu tiên nếu set
FORCE_L3_NAME: Optional[str] = "sL3"  # Prefix tên port

# Đọc ENV (nếu có)
try:
    v = os.getenv("FORCE_L3_DPID")
    if v:
        FORCE_L3_DPID = int(v, 0)  # hỗ trợ "3" hoặc "0x3"
    n = os.getenv("FORCE_L3_NAME")
    if n:
        FORCE_L3_NAME = n
except Exception:
    pass

TIEntry = Tuple[str, str]  # (addr_str, netmask_str)


class TITableRyu(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lock = threading.RLock()

        # TI state
        self.blacklist: Set[TIEntry] = set()
        self.pending: Set[TIEntry] = set()
        self.installed_ti: Dict[int, Set[TIEntry]] = {}  # dpid -> entries đã cài theo delta

        # Datapaths & topo
        self.datapaths: Dict[int, object] = {}          # dpid -> dp
        self.dp_ports: Dict[int, List[str]] = {}        # dpid -> [port names]
        self.neighbors: Dict[int, Set[int]] = {}        # dpid -> set(dpid neighbors)
        self.l3_dpid: Optional[int] = None              # DPID sL3
        self.applied_role: Dict[int, str] = {}          # dpid -> 'L3' | 'L2'

        # Debounce timer
        self._debounce_timer: Optional[threading.Timer] = None

        # Tải local state (persist)
        self._load_local_state()

        # Thread tải TI nền
        t = threading.Thread(target=self._ti_fetch_loop, daemon=True)
        t.start()

    # ===================== Helpers: Flow ops =====================
    def _add_flow(self, dp, table_id: int, priority: int, match, actions=None, inst=None,
                  hard_timeout: int = 0, idle_timeout: int = 0, cookie: int = COOKIE_TI):
        ofp, p = dp.ofproto, dp.ofproto_parser
        if inst is None:
            if actions is None:
                inst = []
            else:
                inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = p.OFPFlowMod(
            datapath=dp, table_id=table_id, priority=priority,
            match=match, instructions=inst, cookie=cookie,
            hard_timeout=hard_timeout, idle_timeout=idle_timeout
        )
        dp.send_msg(mod)

    def _del_flows_by_cookie(self, dp, table_id: Optional[int] = None, cookie: int = COOKIE_TI):
        ofp, p = dp.ofproto, dp.ofproto_parser
        match = p.OFPMatch()
        if table_id is None:
            mod = p.OFPFlowMod(datapath=dp,
                               command=ofp.OFPFC_DELETE,
                               out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                               cookie=cookie, cookie_mask=0xffffffffffffffff,
                               match=match)
        else:
            mod = p.OFPFlowMod(datapath=dp, table_id=table_id,
                               command=ofp.OFPFC_DELETE,
                               out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                               cookie=cookie, cookie_mask=0xffffffffffffffff,
                               match=match)
        dp.send_msg(mod)

    # ===================== Helpers: Baseline & TI tables =====================
    def _ensure_table0_normal(self, dp) -> None:
        ofp, p = dp.ofproto, dp.ofproto_parser
        actions = [p.OFPActionOutput(ofp.OFPP_NORMAL)]
        self._add_flow(dp, 0, 0, p.OFPMatch(), actions=actions, cookie=COOKIE_BASE)
        self.logger.info(f"[BASE] dp 0x{dp.id:x}: T0 -> NORMAL")

    def _ensure_table0_goto_ti(self, dp) -> None:
        p = dp.ofproto_parser
        inst = [p.OFPInstructionGotoTable(TABLE_TI)]
        self._add_flow(dp, 0, 0, p.OFPMatch(), inst=inst, cookie=COOKIE_BASE)
        self.logger.info(f"[BASE] dp 0x{dp.id:x}: T0 -> GOTO {TABLE_TI}")

    def _ensure_ti_default_normal(self, dp) -> None:
        ofp, p = dp.ofproto, dp.ofproto_parser
        actions = [p.OFPActionOutput(ofp.OFPP_NORMAL)]
        self._add_flow(dp, TABLE_TI, PRIO_TI_DEFAULT, p.OFPMatch(), actions=actions, cookie=COOKIE_TI)
        self.logger.info(f"[TI]   dp 0x{dp.id:x}: T{TABLE_TI} default -> NORMAL")

    # ===================== Helpers: TI entries (delta install) =====================
    def _install_drop_entry(self, dp, entry: TIEntry) -> None:
        addr, mask = entry
        p = dp.ofproto_parser
        m_src = p.OFPMatch(eth_type=0x0800, ipv4_src=(addr, mask))
        m_dst = p.OFPMatch(eth_type=0x0800, ipv4_dst=(addr, mask))
        self._add_flow(dp, TABLE_TI, PRIO_TI_DROP, m_src, actions=[], cookie=COOKIE_TI)
        self._add_flow(dp, TABLE_TI, PRIO_TI_DROP, m_dst, actions=[], cookie=COOKIE_TI)

    def _apply_entries_delta(self, dp, want: Set[TIEntry]):
        current = self.installed_ti.setdefault(dp.id, set())
        add_set = want - current
        if add_set:
            for e in sorted(add_set):
                self._install_drop_entry(dp, e)
            current |= add_set
            self.logger.info(f"[TI]   dp 0x{dp.id:x}: +{len(add_set)} entries (total {len(current)})")

    def _apply_ti_on_l3(self, dp):
        # Baseline trên sL3: GOTO table 1
        self._ensure_table0_goto_ti(dp)
        # Default NORMAL ở table 1
        self._ensure_ti_default_normal(dp)
        # Gom entries (blacklist ∪ pending) rồi cài theo delta
        want = set(self.blacklist) | set(self.pending)
        if self.pending:
            for e in self.pending:
                if e not in self.blacklist:
                    self.blacklist.add(e)
                    self._append_local_state(e)
            self.pending.clear()
        self._apply_entries_delta(dp, want)

    # ===================== FORCE pick sL3 =====================
    def _force_pick_l3_if_match(self, dp) -> bool:
        # Ưu tiên theo DPID
        if FORCE_L3_DPID is not None and dp.id == FORCE_L3_DPID:
            self.l3_dpid = dp.id
            self.logger.warning(f"[TI] FORCE L3 by DPID -> 0x{dp.id:x}")
            self._apply_role_for_all_dp()
            return True

        # Hoặc theo prefix tên port (cần PortDesc đã đến)
        if FORCE_L3_NAME:
            names = self.dp_ports.get(dp.id, [])
            has_prefix = any((n or "").startswith(FORCE_L3_NAME) for n in names)
            if has_prefix and self.l3_dpid is None:
                self.l3_dpid = dp.id
                self.logger.warning(f"[TI] FORCE L3 by NAME -> 0x{dp.id:x} ({FORCE_L3_NAME})")
                self._apply_role_for_all_dp()
                return True
        return False

    # ===================== Debounce scheduler =====================
    def _schedule_recompute(self):
        if self._debounce_timer and self._debounce_timer.is_alive():
            self._debounce_timer.cancel()
        self._debounce_timer = threading.Timer(REAPPLY_DEBOUNCE_S, self._recompute_roles_once)
        self._debounce_timer.start()

    def _recompute_roles_once(self):
        with self.lock:
            # Khi đã FORCE, bỏ auto-reselect để không giật
            if FORCE_L3_DPID is None and not FORCE_L3_NAME:
                self._reconsider_l3()
            self._apply_role_for_all_dp()

    # ===================== L3 selection (auto – dùng khi không FORCE) =====================
    def _l3_score(self, dpid: int) -> int:
        names = self.dp_ports.get(dpid, [])
        deg   = len(self.neighbors.get(dpid, set()))
        ports = len([n for n in names if n])
        score = 0
        # hint: port prefix 'sL3-'
        if any((n or "").startswith("sL3-") for n in names):
            score += 10000
        # hint: '-vlan' (cổng nội bộ)
        if any("-vlan" in (n or "").lower() for n in names):
            score += 5000
        score += 100 * deg
        score += ports
        return score

    def _pick_best_l3(self) -> Optional[int]:
        if not self.datapaths:
            return None
        scored = [(self._l3_score(d), d) for d in self.datapaths.keys()]
        if not scored:
            return None
        scored.sort(reverse=True)
        return scored[0][1]

    def _reconsider_l3(self) -> None:
        best = self._pick_best_l3()
        if best is None:
            return
        if self.l3_dpid is None:
            self.l3_dpid = best
            self.logger.info(f"[TI] Select L3 dpid=0x{best:x}")
            return
        if best != self.l3_dpid:
            old = self.l3_dpid
            self.l3_dpid = best
            self._migrate_l3(old, best)

    def _migrate_l3(self, old_dpid: int, new_dpid: int):
        old_dp = self.datapaths.get(old_dpid)
        new_dp = self.datapaths.get(new_dpid)
        self.logger.warning(f"[TI] Re-select L3: 0x{old_dpid:x} -> 0x{new_dpid:x}")

        # 1) Gỡ TI ở old L3, giữ baseline NORMAL
        if old_dp:
            self._del_flows_by_cookie(old_dp, None, COOKIE_TI)
            self.installed_ti[old_dp.id] = set()
            self._ensure_table0_normal(old_dp)
            self.applied_role[old_dp.id] = 'L2'
            self.logger.info(f"[TI]   Clear TI on old L3 0x{old_dpid:x}")

        # 2) Áp TI ở new L3
        if new_dp:
            self._apply_ti_on_l3(new_dp)
            self.applied_role[new_dp.id] = 'L3'
            self.logger.info(f"[TI]   Applied TI on new L3 0x{new_dpid:x}")

    # ===================== Apply roles idempotent =====================
    def _apply_role_for_dp(self, dp) -> None:
        if self.l3_dpid is None:
            return
        want = 'L3' if dp.id == self.l3_dpid else 'L2'
        cur  = self.applied_role.get(dp.id)
        if cur == want:
            return

        # luôn dọn TI trước khi đổi vai
        self._del_flows_by_cookie(dp, None, COOKIE_TI)
        self.installed_ti[dp.id] = set()

        if want == 'L3':
            self._apply_ti_on_l3(dp)
        else:
            self._ensure_table0_normal(dp)

        self.applied_role[dp.id] = want

    def _apply_role_for_all_dp(self) -> None:
        for dp in list(self.datapaths.values()):
            self._apply_role_for_dp(dp)

    # ===================== OpenFlow Handlers =====================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp

        # baseline tạm NORMAL cho tất cả dp
        self._ensure_table0_normal(dp)

        # yêu cầu PortDesc để lấy tên port
        req = dp.ofproto_parser.OFPPortDescStatsRequest(dp, 0)
        dp.send_msg(req)

        # FORCE ngay nếu khớp DPID (không cần đợi PortDesc)
        if self._force_pick_l3_if_match(dp):
            return

        # debounce recompute
        self._schedule_recompute()

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def on_port_desc(self, ev):
        dp = ev.msg.datapath
        names = []
        for p in ev.msg.body:
            try:
                nm = p.name.decode('utf-8') if isinstance(p.name, bytes) else p.name
            except Exception:
                nm = str(getattr(p, 'port_no', 'unknown'))
            names.append(nm)

        with self.lock:
            self.dp_ports[dp.id] = names
            # FORCE lần nữa sau khi đã có tên port
            if self.l3_dpid is None and self._force_pick_l3_if_match(dp):
                return
            self._schedule_recompute()

    @set_ev_cls(topo_event.EventLinkAdd)
    def _on_link_add(self, ev):
        src = ev.link.src.dpid
        dst = ev.link.dst.dpid
        self.neighbors.setdefault(src, set()).add(dst)
        self.neighbors.setdefault(dst, set()).add(src)
        with self.lock:
            self._schedule_recompute()

    @set_ev_cls(topo_event.EventLinkDelete)
    def _on_link_del(self, ev):
        src = ev.link.src.dpid
        dst = ev.link.dst.dpid
        if src in self.neighbors:
            self.neighbors[src].discard(dst)
        if dst in self.neighbors:
            self.neighbors[dst].discard(src)
        with self.lock:
            self._schedule_recompute()

    # ===================== TI background fetch =====================
    def _ti_fetch_loop(self):
        while True:
            try:
                fetched = self._fetch_ti_all_sources()
                if fetched:
                    with self.lock:
                        delta = [e for e in fetched if e not in self.blacklist]
                        if MAX_NEW_PER_CYCLE > 0 and len(delta) > MAX_NEW_PER_CYCLE:
                            delta = delta[:MAX_NEW_PER_CYCLE]
                        if delta:
                            self.logger.info(f"[TI] New entries: {len(delta)}")
                            # Nếu đã có sL3, áp ngay theo delta; chưa có thì cho pending
                            if self.l3_dpid and self.l3_dpid in self.datapaths:
                                dp = self.datapaths[self.l3_dpid]
                                # thêm vào blacklist + persist trước
                                for e in delta:
                                    self.blacklist.add(e)
                                    self._append_local_state(e)
                                # cài delta
                                self._apply_entries_delta(dp, set(delta))
                            else:
                                for e in delta:
                                    self.pending.add(e)
                        else:
                            self.logger.debug("[TI] No new entries")
                else:
                    self.logger.debug("[TI] No entries fetched")
            except Exception as e:
                self.logger.error(f"[TI] Fetch loop error: {e}")

            time.sleep(FETCH_INTERVAL_S)

    def _fetch_ti_all_sources(self) -> List[TIEntry]:
        out: Set[TIEntry] = set()
        for url in TI_SOURCES:
            try:
                r = requests.get(url, timeout=REQUEST_TIMEOUT_S)
                if r.status_code != 200:
                    self.logger.warning(f"[TI] {url} -> HTTP {r.status_code}")
                    continue
                for line in r.text.splitlines():
                    s = line.strip()
                    if not s or s.startswith('#'):
                        continue
                    entry = self._parse_ipv4_or_cidr(s)
                    if entry:
                        out.add(entry)
            except Exception as e:
                self.logger.warning(f"[TI] source error {url}: {e}")
        return sorted(out)

    def _parse_ipv4_or_cidr(self, token: str) -> Optional[TIEntry]:
        try:
            if '/' in token:
                net = ipaddress.ip_network(token, strict=False)
                if isinstance(net, ipaddress.IPv4Network) and net.prefixlen >= ACCEPT_MIN_PREFIX:
                    return (str(net.network_address), str(net.netmask))
                return None
            ip = ipaddress.ip_address(token)
            if isinstance(ip, ipaddress.IPv4Address):
                return (str(ip), "255.255.255.255")
            return None
        except Exception:
            return None

    # ===================== Local state =====================
    def _load_local_state(self) -> None:
        if not os.path.exists(LOCAL_STATE_FILE):
            self.logger.info("[TI] No local state file. Will create when needed.")
            return
        cnt = 0
        try:
            with open(LOCAL_STATE_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        cidr = obj.get('cidr')
                        if not cidr:
                            ip_legacy = obj.get('ip') or obj.get('addr')
                            mask_legacy = obj.get('mask') or "255.255.255.255"
                            if ip_legacy:
                                self.blacklist.add((str(ip_legacy), str(mask_legacy)))
                                cnt += 1
                            continue
                        net = ipaddress.ip_network(cidr, strict=False)
                        if isinstance(net, ipaddress.IPv4Network) and net.prefixlen >= ACCEPT_MIN_PREFIX:
                            self.blacklist.add((str(net.network_address), str(net.netmask)))
                            cnt += 1
                    except Exception:
                        continue
            self.logger.info(f"[TI] Loaded {cnt} entries from {LOCAL_STATE_FILE}")
        except Exception as e:
            self.logger.error(f"[TI] load state error: {e}")

    def _append_local_state(self, entry: TIEntry) -> None:
        addr, mask = entry
        try:
            net = ipaddress.IPv4Network((addr, mask), strict=False)
            rec = {"cidr": str(net), "ts": int(time.time())}
        except Exception:
            rec = {"addr": addr, "mask": mask, "ts": int(time.time())}
        try:
            with open(LOCAL_STATE_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.error(f"[TI] write state error: {e}")
