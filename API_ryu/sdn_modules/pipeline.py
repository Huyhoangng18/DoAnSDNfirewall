# -*- coding: utf-8 -*-
"""
pipeline.py — Datapath, pipeline install, sL3 pick, and flow helpers.

Split from unified_sdn.py for improved maintainability.
"""

import time
from typing import Dict, Any, Set, List, Optional

from .constants import (
    TBL, COOKIE_BASELINE, FORCE_L3_BRIDGE_NAME, VLAN_NAME_HINT, GRACE_PICK_S
)


class PipelineMixin:
    """
    Mixin providing OpenFlow pipeline and sL3 selection functionality.
    
    Requires the following attributes on the host class:
    - datapaths: Dict[int, Any]
    - dp_ports: Dict[int, List[str]]
    - neighbors: Dict[int, Set[int]]
    - l3_dpid: Optional[int]
    - applied_role: Dict[int, str]
    - start_ts: float
    - lock: threading.RLock
    - logger: logging.Logger
    """

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
    def _score(self, dpid: int) -> int:
        names = self.dp_ports.get(dpid, [])
        deg   = len(self.neighbors.get(dpid, set()))
        s = 0
        if any((n or '').startswith(FORCE_L3_BRIDGE_NAME) for n in names): s += 10000
        if any(VLAN_NAME_HINT in (n or '').lower() for n in names):       s += 3000
        s += 100*deg + len(names)
        return s

    def _pick_best_l3(self) -> Optional[int]:
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
