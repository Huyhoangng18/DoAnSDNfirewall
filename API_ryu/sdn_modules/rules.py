# -*- coding: utf-8 -*-
"""
rules.py — RULES logic (table 0): CRUD drop/allow TCP, file persistence.

Split from unified_sdn.py for improved maintainability.
"""

import os
import json
import hashlib
from typing import Dict

from .constants import RULES_FILE, COOKIE_RULES, TBL


class RulesMixin:
    """
    Mixin providing RULES management functionality.
    
    Requires the following attributes on the host class:
    - datapaths: Dict[int, Any]
    - l3_dpid: Optional[int]
    - rules: Dict[str, dict]
    - logger: logging.Logger
    
    Requires the following methods from other mixins:
    - _add_flow()
    - _del_by_cookie()
    """

    # ===== RULES (table 0) =====
    def _rule_cookie(self, rid: str) -> int:
        h = hashlib.sha256(rid.encode('utf-8')).digest()
        return COOKIE_RULES | (int.from_bytes(h[:5], 'big') & 0xFFFFFFFFFF)

    def _rule_match(self, dp, m: dict):
        p = dp.ofproto_parser
        kw = {'eth_type': 0x0800, 'ip_proto': 6}
        if m.get('ipv4_src'): kw['ipv4_src'] = m['ipv4_src']
        if m.get('ipv4_dst'): kw['ipv4_dst'] = m['ipv4_dst']
        if m.get('tcp_dst'):  kw['tcp_dst'] = int(m['tcp_dst'])
        return p.OFPMatch(**kw)

    def _rules_scope_dpids(self, scope):
        if scope == 'all': return list(self.datapaths.keys())
        # mặc định: áp trên sL3
        return [self.l3_dpid] if (self.l3_dpid in self.datapaths) else []

    def _install_rule_on_dp(self, dp, rule: dict):
        p, ofp = dp.ofproto_parser, dp.ofproto
        actions = [] if rule['action'] == 'drop' else [p.OFPActionOutput(ofp.OFPP_NORMAL)]
        match = self._rule_match(dp, rule['match'])
        self._add_flow(dp, TBL["T0"], int(rule['priority']), match, actions=actions, cookie=self._rule_cookie(rule['rule_id']))

    def _delete_rule_on_all_dp(self, rid: str):
        ck = self._rule_cookie(rid)
        for dp in list(self.datapaths.values()):
            self._del_by_cookie(dp, ck)

    def _apply_all_rules_to_dp(self, dp):
        for r in self.rules.values():
            if dp.id in self._rules_scope_dpids(r.get('scope', 'l3')):
                self._install_rule_on_dp(dp, r)

    def _load_rules_file(self):
        if not os.path.exists(RULES_FILE): 
            self.rules = {}
            return
        try:
            with open(RULES_FILE, 'r', encoding='utf-8') as f:
                self.rules = json.load(f)
                if not isinstance(self.rules, dict): self.rules = {}
            self.logger.info(f"[RULES] loaded {len(self.rules)} from {RULES_FILE}")
        except Exception as e:
            self.logger.error(f"[RULES] load error: {e}")
            self.rules = {}

    def _save_rules_file(self):
        try:
            with open(RULES_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.rules, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.logger.error(f"[RULES] write error: {e}")

    # public rules
    def rules_list(self):
        return {"count": len(self.rules), "items": list(self.rules.values())}

    def rules_upsert(self, rule: dict):
        for k in ['rule_id', 'priority', 'action', 'match']:
            if k not in rule: raise ValueError(f"missing {k}")
        if rule['action'] not in ('drop', 'allow'):
            raise ValueError('action must be drop/allow')
        rid = rule['rule_id']
        old = self.rules.get(rid)
        if old and old == rule: return rule
        if old and old != rule:
            self._delete_rule_on_all_dp(rid)
        for dpid in self._rules_scope_dpids(rule.get('scope', 'l3')):
            dp = self.datapaths.get(dpid)
            if dp: self._install_rule_on_dp(dp, rule)
        self.rules[rid] = rule
        self._save_rules_file()
        return rule

    def rules_delete(self, rid: str) -> bool:
        if rid not in self.rules: return False
        self._delete_rule_on_all_dp(rid)
        self.rules.pop(rid)
        self._save_rules_file()
        return True
