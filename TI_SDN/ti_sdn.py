#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ryu TI Table20 – CHỈ áp TI trên sL3 (ổn định, tái chọn động nếu chọn nhầm ban đầu)

Mục tiêu:
- Mặc định thông tất cả host (NORMAL) trên mọi switch.
- Chỉ switch L3 (sL3) mới nhận rule TI ở Table 20 (DROP theo ipv4_src/dst ∈ blacklist).
- Tránh áp nhầm s1/s2: cơ chế chấm điểm + tái đánh giá động khi có thêm dữ liệu.

Cách nhận diện sL3 (ưu tiên giảm dần):
1) Tên port bắt đầu bằng 'sL3-' (FORCE_L3_BRIDGE_NAME '-') → chắc kèo nhất cho topo của bạn.
2) Port name chứa '-vlan' (có internal VLAN).
3) Bậc topo (--observe-links): số láng giềng switch lớn nhất (>=2).
4) Fallback 'nhiều port nhất' — chỉ sau GRACE_PICK_S để tránh pick sớm nhầm.

An toàn cấu hình:
- Xóa flow cũ theo COOKIE_TI trước khi áp role mới (tránh trùng/nhảy bảng).
- Lưu role đã áp để không reconfigure thừa.
- Trong lúc chờ nhận diện, table 0 đặt NORMAL để mạng thông suốt.

Chạy:
    ryu-manager --observe-links ti_sdn2_final.py
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
TABLE_TI: int = 1
PRIO_TI_DROP: int = 35000
PRIO_TI_DEFAULT: int = 0
COOKIE_TI: int = 0xAA11
LOCAL_STATE_FILE: str = "/tmp/ti_blacklist.jsonl"
FETCH_INTERVAL_S: int = 300
REQUEST_TIMEOUT_S: int = 15
ACCEPT_MIN_PREFIX: int = 24
MAX_NEW_PER_CYCLE: int = 500

# Nhận diện sL3
FORCE_L3_BRIDGE_NAME = "sL3"          # nếu port bắt đầu bằng "sL3-" → cộng điểm cực mạnh
BRIDGE_NAME_HINT     = FORCE_L3_BRIDGE_NAME + "-"
VLAN_NAME_HINT       = "-vlan"        # port có internal VLAN
GRACE_PICK_S         = 5.0            # chỉ fallback sau khoảng thời gian này (tránh pick sớm)

TI_SOURCES: List[str] = [
    "https://lists.blocklist.de/lists/all.txt",
    "https://iplists.firehol.org/files/firehol_level1.netset",
]

TIEntry = Tuple[str, str]    # (addr_str, mask_str)


class TITableRyu(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lock = threading.RLock()

        self.blacklist: Set[TIEntry] = set()
        self.pending: Set[TIEntry] = set()

        self.datapaths: Dict[int, object] = {}          # dpid -> dp
        self.dp_ports: Dict[int, List[str]] = {}        # dpid -> [port names]
        self.neighbors: Dict[int, Set[int]] = {}        # dpid -> set(dpid neighbors)
        self.l3_dpid: Optional[int] = None              # dpid L3 đã chọn
        self.applied_role: Dict[int, str] = {}          # dpid -> 'L3' | 'L2'
        self.start_ts = time.time()

        self._load_local_state()

        # Thread nền cập nhật TI
        t = threading.Thread(target=self._ti_fetch_loop, daemon=True)
        t.start()

    # ===================== OpenFlow helpers =====================
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

    def _ensure_table0_goto_ti(self, dp) -> None:
        p = dp.ofproto_parser
        inst = [p.OFPInstructionGotoTable(TABLE_TI)]
        self._add_flow(dp, 0, 0, p.OFPMatch(), inst=inst, cookie=COOKIE_TI)
        self.logger.info(f"[TI] dp {dp.id}: table 0 default -> GOTO {TABLE_TI}")

    def _ensure_table0_normal(self, dp) -> None:
        ofp, p = dp.ofproto, dp.ofproto_parser
        actions = [p.OFPActionOutput(ofp.OFPP_NORMAL)]
        self._add_flow(dp, 0, 0, p.OFPMatch(), actions=actions, cookie=COOKIE_TI)
        self.logger.info(f"[TI] dp {dp.id}: table 0 default -> NORMAL")

    def _ensure_table20_default_normal(self, dp) -> None:
        ofp, p = dp.ofproto, dp.ofproto_parser
        actions = [p.OFPActionOutput(ofp.OFPP_NORMAL)]
        self._add_flow(dp, TABLE_TI, PRIO_TI_DEFAULT, p.OFPMatch(), actions=actions, cookie=COOKIE_TI)
        self.logger.info(f"[TI] dp {dp.id}: table {TABLE_TI} default -> NORMAL")

    def _install_drop_entry(self, dp, entry: TIEntry) -> None:
        addr, mask = entry
        p = dp.ofproto_parser
        m_src = p.OFPMatch(eth_type=0x0800, ipv4_src=(addr, mask))
        self._add_flow(dp, TABLE_TI, PRIO_TI_DROP, m_src, actions=[], cookie=COOKIE_TI)
        m_dst = p.OFPMatch(eth_type=0x0800, ipv4_dst=(addr, mask))
        self._add_flow(dp, TABLE_TI, PRIO_TI_DROP, m_dst, actions=[], cookie=COOKIE_TI)

    def _apply_entries_to_dp(self, dp, entries: List[TIEntry]) -> None:
        for e in entries:
            self._install_drop_entry(dp, e)

    def _apply_entries_to_l3(self, entries: List[TIEntry]) -> None:
        if self.l3_dpid is None:
            return
        dp = self.datapaths.get(self.l3_dpid)
        if not dp:
            return
        self._apply_entries_to_dp(dp, entries)

    # ===================== Scoring & re-selection =====================
    def _l3_score(self, dpid: int) -> int:
        """
        Tính điểm cho mỗi switch để chọn sL3. Điểm cao hơn => ưu tiên hơn.
        """
        names = self.dp_ports.get(dpid, [])
        deg   = len(self.neighbors.get(dpid, set()))
        ports = len([n for n in names if n])

        score = 0
        # Ưu tiên cực mạnh: port bắt đầu bằng "sL3-"
        if any((n or "").startswith(BRIDGE_NAME_HINT) for n in names):
            score += 10000
        # Ưu tiên mạnh: có internal vlan
        if any(VLAN_NAME_HINT in (n or "").lower() for n in names):
            score += 5000
        # Ưu tiên topo: độ bậc cao (thường sL3 nối >=2 switch)
        score += 100 * deg
        # Tie-break: nhiều port hơn thì + điểm nhẹ
        score += ports
        return score

    def _pick_best_l3(self) -> Optional[int]:
        """
        Trả về dpid có điểm cao nhất. Trước GRACE_PICK_S sẽ tránh fallback kiểu
        'nhiều port nhất' nếu chưa có tín hiệu vlan/topo/bridge name.
        """
        if not self.datapaths:
            return None

        scored = []
        for dpid in self.datapaths.keys():
            scored.append((self._l3_score(dpid), dpid))
        if not scored:
            return None
        scored.sort(reverse=True)
        best_score, best_dpid = scored[0]

        # Nếu chưa qua GRACE mà best chỉ hơn nhờ ports (không có hint/topo), thì… đợi thêm
        now = time.time()
        if now - self.start_ts < GRACE_PICK_S:
            names = self.dp_ports.get(best_dpid, [])
            has_bridge = any((n or "").startswith(BRIDGE_NAME_HINT) for n in names)
            has_vlan   = any(VLAN_NAME_HINT in (n or "").lower() for n in names)
            deg        = len(self.neighbors.get(best_dpid, set()))
            if not (has_bridge or has_vlan or deg >= 2):
                return None

        return best_dpid

    def _reconsider_l3(self) -> None:
        """
        Gọi mỗi khi có dữ liệu mới (PortDesc/LinkAdd/LinkDel). Nếu best khác hiện tại,
        di chuyển role: gỡ TI khỏi dp cũ, áp vào dp mới.
        """
        best = self._pick_best_l3()
        if best is None:
            return

        # Nếu chưa có L3 hiện tại -> áp luôn
        if self.l3_dpid is None:
            self.l3_dpid = best
            self.logger.info(f"[TI] Select L3 dpid=0x{best:x}")
            self._apply_role_for_all_dp()
            return

        # Nếu đã chọn mà best đổi -> migrate
        if best != self.l3_dpid:
            old = self.l3_dpid
            self.l3_dpid = best
            self.logger.warning(f"[TI] Re-select L3: 0x{old:x} -> 0x{best:x}")
            old_dp = self.datapaths.get(old)
            new_dp = self.datapaths.get(best)
            if old_dp:
                self._del_flows_by_cookie(old_dp, None, COOKIE_TI)
                self.applied_role.pop(old, None)
                self._apply_role_for_dp(old_dp)   # sẽ đặt NORMAL (L2)
            if new_dp:
                self._del_flows_by_cookie(new_dp, None, COOKIE_TI)
                self.applied_role.pop(best, None)
                self._apply_role_for_dp(new_dp)   # sẽ đặt GOTO20 + TI (L3)

    # ===================== Apply roles =====================
    def _apply_role_for_dp(self, dp) -> None:
        if self.l3_dpid is None:
            return
        want_role = 'L3' if dp.id == self.l3_dpid else 'L2'
        cur_role = self.applied_role.get(dp.id)
        if cur_role == want_role:
            return

        # Xóa sạch flow TI trước khi set lại
        self._del_flows_by_cookie(dp, None, COOKIE_TI)

        if want_role == 'L3':
            # L3: Table0->TI, Table20 default NORMAL, cài entries
            self._ensure_table0_goto_ti(dp)
            self._ensure_table20_default_normal(dp)
            if self.blacklist:
                self._apply_entries_to_dp(dp, sorted(self.blacklist))
            if self.pending:
                for e in sorted(self.pending):
                    self._install_drop_entry(dp, e)
                    if e not in self.blacklist:
                        self.blacklist.add(e)
                        self._append_local_state(e)
                self.pending.clear()
            self.logger.info(f"[TI] Applied TI on L3 dp=0x{dp.id:x}")
        else:
            # L2: Table0 -> NORMAL
            self._ensure_table0_normal(dp)
            self.logger.info(f"[TI] Set NORMAL on L2 dp=0x{dp.id:x} (no TI)")

        self.applied_role[dp.id] = want_role

    def _apply_role_for_all_dp(self) -> None:
        for dp in list(self.datapaths.values()):
            self._apply_role_for_dp(dp)

    # ===================== OF Handlers =====================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp

        # Tạm NORMAL để thông trong lúc chờ nhận diện
        self._ensure_table0_normal(dp)

        # Yêu cầu PortDesc để thu tên port
        req = dp.ofproto_parser.OFPPortDescStatsRequest(dp, 0)
        dp.send_msg(req)

        # Sau 5s, refresh PortDesc một lần (để chắc đã thấy sL3-vlan*)
        def _refresh_portdesc():
            try:
                req2 = dp.ofproto_parser.OFPPortDescStatsRequest(dp, 0)
                dp.send_msg(req2)
            except Exception:
                pass
        threading.Timer(5.0, _refresh_portdesc).start()

        # Thử tái chọn sau một nhịp ngắn
        threading.Timer(0.2, lambda: self._reconsider_l3()).start()

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
            self._reconsider_l3()
            self._apply_role_for_all_dp()

    # Topology events (cần ryu-manager --observe-links)
    @set_ev_cls(topo_event.EventLinkAdd)
    def _on_link_add(self, ev):
        src = ev.link.src.dpid
        dst = ev.link.dst.dpid
        self.neighbors.setdefault(src, set()).add(dst)
        self.neighbors.setdefault(dst, set()).add(src)
        with self.lock:
            self._reconsider_l3()
            self._apply_role_for_all_dp()

    @set_ev_cls(topo_event.EventLinkDelete)
    def _on_link_del(self, ev):
        src = ev.link.src.dpid
        dst = ev.link.dst.dpid
        if src in self.neighbors:
            self.neighbors[src].discard(dst)
        if dst in self.neighbors:
            self.neighbors[dst].discard(src)
        with self.lock:
            self._reconsider_l3()
            self._apply_role_for_all_dp()

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
                            if self.l3_dpid and self.l3_dpid in self.datapaths:
                                self._apply_entries_to_l3(delta)
                                for e in delta:
                                    self.blacklist.add(e)
                                    self._append_local_state(e)
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
                            ip_legacy = obj.get('ip')
                            if ip_legacy:
                                self.blacklist.add((str(ip_legacy), "255.255.255.255"))
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

