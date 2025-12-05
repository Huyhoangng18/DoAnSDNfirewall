#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
unified_sdn.py — SDN (Ryu) với 3 nhóm chức năng hợp nhất:
- RULES (table 0): CRUD drop/allow TCP, lưu /tmp/rules.json, áp trên sL3 (mặc định) hoặc all.
- TI (table 1): tự cập nhật IP/CIDR chỉ trên sL3, lưu /tmp/ti_blacklist.jsonl, REST paging.
- IDS (table 3): auto-block theo Suricata EVE (eve.json) với BLOCK_MODE, de-dup, FLOW_REMOVED; CRUD /etc/suricata/rules/local.rules; đọc alerts nhanh.

Chạy (cần quyền đọc/ghi Suricata paths):
  sudo env SURICATA_RELOAD_CMD="systemctl reload suricata" ryu-manager --observe-links unified_sdn.py

This module has been refactored into separate sub-modules for improved maintainability.
See sdn_modules/ for the individual components:
- constants.py: File paths, cookies, tables, environment variables
- pipeline.py: Datapath, pipeline install, sL3 pick, flow helpers
- rules.py: RULES logic (table 0), CRUD, file handling
- ti.py: Threat Intelligence fetcher and TI APIs
- ids.py: EVE tailer, IDS auto-block, Suricata local.rules management
- rest.py: UnifiedRest controller with WSGI routes
"""

import time
import threading
from collections import defaultdict
from typing import Dict, Any, Set, Tuple, List, Optional

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event as topo_event
from ryu.app.wsgi import WSGIApplication

# Import from modular components
from sdn_modules.constants import APP_NAME, TI_SOURCES
from sdn_modules.pipeline import PipelineMixin
from sdn_modules.rules import RulesMixin
from sdn_modules.ti import TIMixin
from sdn_modules.ids import IDSMixin
from sdn_modules.rest import UnifiedRest


class UnifiedSDN(app_manager.RyuApp, PipelineMixin, RulesMixin, TIMixin, IDSMixin):
    """
    Unified SDN application combining RULES, TI, and IDS functionality.
    
    Inherits from mixins that provide modular functionality:
    - PipelineMixin: OpenFlow pipeline and sL3 selection
    - RulesMixin: RULES management (table 0)
    - TIMixin: Threat Intelligence (table 1)
    - IDSMixin: IDS auto-block and Suricata rules (table 3)
    """
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
        self.ti_set: Set[Tuple[str, str]] = set()
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
        names = []
        for p in ev.msg.body:
            try:
                nm = p.name.decode('utf-8') if isinstance(p.name, bytes) else p.name
            except:
                nm = str(getattr(p, 'port_no', 'unknown'))
            names.append(nm)
        with self.lock:
            self.dp_ports[dp.id] = names
        self._reselect_l3()

    @set_ev_cls(topo_event.EventLinkAdd)
    def on_link_add(self, ev):
        s, d = ev.link.src.dpid, ev.link.dst.dpid
        self.neighbors.setdefault(s, set()).add(d)
        self.neighbors.setdefault(d, set()).add(s)
        self._reselect_l3()

    @set_ev_cls(topo_event.EventLinkDelete)
    def on_link_del(self, ev):
        s, d = ev.link.src.dpid, ev.link.dst.dpid
        if s in self.neighbors:
            self.neighbors[s].discard(d)
        if d in self.neighbors:
            self.neighbors[d].discard(s)
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


# Re-export UnifiedRest for backwards compatibility
__all__ = ['UnifiedSDN', 'UnifiedRest']
