#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ids_pipeline.py (src-ip blocking, de-dup install, clean pipeline)

- Pipeline OpenFlow 0..10:
  T0 -> INGRESS -> ACL -> IDS -> CT -> L3 -> L2 -> SVC -> QOS -> TLM -> EGRESS(NORMAL)

- Đọc Suricata EVE (eve.json). Khi event_type=="alert":
  * Mặc định: CHẶN THEO NGUỒN (ipv4_src=src_ip) -> không bị ảnh hưởng khi attacker đổi source port
  * Tuỳ chọn: "src_ip_proto" / "5tuple" / "dst_ip"

- Tránh re-install:
  * Cache (dpid,key) -> expire_ts, không cài lại nếu flow còn hạn
  * Nhận FLOW_REMOVED để xoá cache đúng lúc
  * Throttle REBLOCK_GRACE để giảm log khi alert dồn dập

Env gợi ý:
  BLOCK_MODE=src_ip
  HARD_TIMEOUT=1800
  REBLOCK_GRACE=10
  TARGET_DPID=<dpid sL3>   # 0 = đẩy lên tất cả DP (mặc định)
"""

import json
import os
import time
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

# ===================== CẤU HÌNH =====================

EVE_JSON_PATH   = os.getenv("EVE_JSON_PATH", "/var/log/suricata/eve.json")

# Chế độ chặn:
#  - "src_ip"       : chặn toàn bộ lưu lượng từ src_ip  ✅ (khuyến nghị)
#  - "src_ip_proto" : chặn theo src_ip + ip_proto (TCP/UDP/ICMP)
#  - "5tuple"       : chặn đúng luồng
#  - "dst_ip"       : chặn toàn bộ về đích
BLOCK_MODE      = os.getenv("BLOCK_MODE", "src_ip").lower()

IDS_TABLE       = int(os.getenv("IDS_TABLE", "3"))
BLOCK_PRIORITY  = int(os.getenv("BLOCK_PRIORITY", "60000"))

# Thời gian & chống spam
HARD_TIMEOUT    = int(os.getenv("HARD_TIMEOUT", "300"))     # giây
REBLOCK_GRACE   = float(os.getenv("REBLOCK_GRACE", "5.0"))  # giây

# (Tuỳ chọn) chỉ cài trên 1 DP (ví dụ sL3). 0 = tất cả DP.
TARGET_DPID     = int(os.getenv("TARGET_DPID", "0"))

COOKIE_BASE     = int(os.getenv("COOKIE_BASE", "0x66BB3000"), 16)

# Chỉ block khi severity <= SEVERITY_MIN (Suricata: 1=High, 2=Med, 3=Low)
SEVERITY_MIN    = int(os.getenv("SEVERITY_MIN", "2"))

WHITELIST_IPS   = set(ip.strip() for ip in os.getenv("WHITELIST_IPS", "127.0.0.1").split(",") if ip.strip())
WHITELIST_SIDS  = set()  # thêm sid nếu muốn miễn trừ theo signature

# Pipeline 0..10
TBL = {
    "T0":      0,
    "INGRESS": 1,
    "ACL":     2,
    "IDS":     IDS_TABLE,
    "CT":      4,
    "L3":      5,
    "L2":      6,
    "SVC":     7,
    "QOS":     8,
    "TLM":     9,
    "EGRESS": 10,
}


class IDSPipeline(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}                      # dpid -> datapath
        self.last_block_ts = defaultdict(float)  # key -> last ts (anti-spam)
        self.active_blocks_until = {}            # (dpid, key) -> expire_ts
        self.cookie_to_key = {}                  # (dpid, cookie) -> key  (FLOW_REMOVED)
        self.reader = hub.spawn(self._eve_reader_loop)
        self.logger.info("IDSPipeline ready. TABLE=%s MODE=%s HARD_TIMEOUT=%s TARGET_DPID=%s",
                         IDS_TABLE, BLOCK_MODE, HARD_TIMEOUT, TARGET_DPID)

    # ---------- pipeline install ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        self._install_pipeline(dp)
        self.logger.info("Installed pipeline 0..10 on dpid=%s", dp.id)

    def _install_pipeline(self, dp):
        ofp, p = dp.ofproto, dp.ofproto_parser

        def add(table, prio, match, inst):
            dp.send_msg(p.OFPFlowMod(datapath=dp, table_id=table, priority=prio,
                                     match=match, instructions=inst))

        # T0 -> INGRESS
        add(TBL["T0"], 0, p.OFPMatch(), [p.OFPInstructionGotoTable(TBL["INGRESS"])])

        # ARP fast-path -> EGRESS
        add(TBL["INGRESS"], 40000, p.OFPMatch(eth_type=0x0806),
            [p.OFPInstructionGotoTable(TBL["EGRESS"])])

        # Chuỗi mặc định
        add(TBL["INGRESS"], 0, p.OFPMatch(), [p.OFPInstructionGotoTable(TBL["ACL"])])
        add(TBL["ACL"],     0, p.OFPMatch(), [p.OFPInstructionGotoTable(TBL["IDS"])])
        add(TBL["IDS"],     0, p.OFPMatch(), [p.OFPInstructionGotoTable(TBL["CT"])])
        add(TBL["CT"],      0, p.OFPMatch(), [p.OFPInstructionGotoTable(TBL["L3"])])
        add(TBL["L3"],      0, p.OFPMatch(), [p.OFPInstructionGotoTable(TBL["L2"])])
        add(TBL["L2"],      0, p.OFPMatch(), [p.OFPInstructionGotoTable(TBL["SVC"])])
        add(TBL["SVC"],     0, p.OFPMatch(), [p.OFPInstructionGotoTable(TBL["QOS"])])
        add(TBL["QOS"],     0, p.OFPMatch(), [p.OFPInstructionGotoTable(TBL["TLM"])])
        add(TBL["TLM"],     0, p.OFPMatch(), [p.OFPInstructionGotoTable(TBL["EGRESS"])])

        # EGRESS: NORMAL
        add(TBL["EGRESS"], 0, p.OFPMatch(),
            [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [p.OFPActionOutput(ofp.OFPP_NORMAL)])])

    # ---------- dp state ----------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("DP connected dpid=%s", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)
            self.logger.info("DP disconnected dpid=%s", dp.id)

    # ---------- FLOW_REMOVED ----------
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def on_flow_removed(self, ev):
        dp = ev.msg.datapath
        cookie = ev.msg.cookie
        key = self.cookie_to_key.pop((dp.id, cookie), None)
        if key is not None:
            self.active_blocks_until.pop((dp.id, key), None)
            self.logger.info("FLOW_REMOVED dpid=%s key=%s reason=%s", dp.id, key, ev.msg.reason)

    # ---------- EVE tail ----------
    def _open_tail(self, path):
        while True:
            try:
                fp = open(path, "r", buffering=1)
                fp.seek(0, os.SEEK_END)  # chỉ đọc dòng mới
                self.logger.info("Tailing EVE: %s", path)
                return fp
            except FileNotFoundError:
                self.logger.warning("Waiting for %s ...", path)
                hub.sleep(1.0)

    def _eve_reader_loop(self):
        path, fp, ino = EVE_JSON_PATH, None, None
        while True:
            try:
                if fp is None:
                    fp = self._open_tail(path)
                    ino = os.fstat(fp.fileno()).st_ino

                line = fp.readline()
                if not line:
                    try:
                        if os.stat(path).st_ino != ino:  # rotated
                            fp.close(); fp = None
                            continue
                    except FileNotFoundError:
                        fp.close(); fp = None
                        continue
                    hub.sleep(0.1)
                    continue

                self._handle_eve_line(line.strip())

            except Exception as e:
                self.logger.error("EVE reader error: %s", e)
                hub.sleep(1.0)
                fp = None

    # ---------- utils (de-dup) ----------
    def _is_block_active(self, dpid, key, now):
        exp = self.active_blocks_until.get((dpid, key))
        return (exp is not None) and (now < exp)

    def _mark_block_active(self, dpid, key, now):
        # trừ 1s để phòng lệch clock
        self.active_blocks_until[(dpid, key)] = now + max(1, HARD_TIMEOUT - 1)

    # ---------- parse & block ----------
    def _handle_eve_line(self, line: str):
        if not line:
            return
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return

        if ev.get("event_type") != "alert":
            return

        alert = ev.get("alert", {})
        sid = alert.get("signature_id") or alert.get("sid")
        try: sid = int(sid) if sid is not None else None
        except: sid = None

        sev = alert.get("severity")
        try: sev = int(sev) if sev is not None else None
        except: sev = None

        if sev is not None and sev > SEVERITY_MIN:
            return

        sip   = ev.get("src_ip")
        dip   = ev.get("dest_ip") or ev.get("dst_ip")
        proto = (ev.get("proto") or "").upper()
        sp    = ev.get("src_port")
        dpn   = ev.get("dest_port") or ev.get("dst_port")

        if sid and sid in WHITELIST_SIDS: return
        if sip in WHITELIST_IPS or dip in WHITELIST_IPS: return

        # Xác định key theo BLOCK_MODE
        if BLOCK_MODE == "src_ip" and sip:
            key = ("src_ip", sip)
        elif BLOCK_MODE == "src_ip_proto" and sip and proto:
            key = ("src_ip_proto", sip, proto)
        elif BLOCK_MODE == "5tuple" and sip and dip and proto:
            sp_i  = int(sp)  if sp  not in (None, "", 0) else None
            dpn_i = int(dpn) if dpn not in (None, "", 0) else None
            key = ("5t", proto, sip, sp_i, dip, dpn_i)
        elif BLOCK_MODE == "dst_ip" and dip:
            key = ("dst_ip", dip)
        elif sip:
            key = ("src_ip", sip)  # fallback an toàn
        else:
            return

        now = time.time()

        # Throttle: tránh spam quá nhanh
        if now - self.last_block_ts[key] < REBLOCK_GRACE:
            return

        installed = 0
        skipped = 0

        # Đẩy lên các DP phù hợp
        for dpid, dp in list(self.datapaths.items()):
            if TARGET_DPID and dpid != TARGET_DPID:
                continue
            # Nếu flow còn hạn trên DP này -> bỏ qua
            if self._is_block_active(dpid, key, now):
                skipped += 1
                continue
            try:
                cookie = self._install_drop(dp, key, sid)
                self._mark_block_active(dpid, key, now)
                if cookie is not None:
                    self.cookie_to_key[(dp.id, cookie)] = key
                installed += 1
            except Exception as e:
                self.logger.error("install_drop failed dpid=%s key=%s err=%s", dpid, key, e)

        # cập nhật mốc throttle sau vòng for
        self.last_block_ts[key] = now

        if installed > 0:
            self.logger.warning(
                "BLOCK(installed=%d, skipped=%d): sid=%s sev=%s mode=%s key=%s %s:%s -> %s:%s proto=%s",
                installed, skipped, sid, sev, BLOCK_MODE, key, sip, sp, dip, dpn, proto
            )
        else:
            self.logger.debug(
                "SKIP (already active on all DPs): mode=%s key=%s skipped=%d",
                BLOCK_MODE, key, skipped
            )

    # ---------- install flow (return cookie) ----------
    def _install_drop(self, dp, key, sid):
        ofp, p = dp.ofproto, dp.ofproto_parser
        cookie = COOKIE_BASE | ((sid & 0xFFFF) if sid is not None else 0)

        def send(match, prio=BLOCK_PRIORITY):
            mod = p.OFPFlowMod(
                datapath=dp,
                table_id=IDS_TABLE,
                priority=prio,
                match=match,
                instructions=[],           # DROP
                hard_timeout=HARD_TIMEOUT,
                idle_timeout=0,
                cookie=cookie,
                flags=ofp.OFPFF_SEND_FLOW_REM  # nhận EventOFPFlowRemoved
            )
            dp.send_msg(mod)

        k0 = key[0]

        if k0 == "src_ip":
            _, sip = key
            send(p.OFPMatch(eth_type=0x0800, ipv4_src=sip))
            return cookie

        if k0 == "src_ip_proto":
            _, sip, proto = key
            m = dict(eth_type=0x0800, ipv4_src=sip)
            if proto == "TCP":    m["ip_proto"] = 6
            elif proto == "UDP":  m["ip_proto"] = 17
            elif proto == "ICMP": m["ip_proto"] = 1
            send(p.OFPMatch(**m))
            return cookie

        if k0 == "dst_ip":
            _, dip = key
            send(p.OFPMatch(eth_type=0x0800, ipv4_dst=dip))
            return cookie

        if k0 == "5t":
            _, proto, sip, sp, dip, dpn = key
            m = dict(eth_type=0x0800, ipv4_src=sip, ipv4_dst=dip)
            if proto == "TCP":
                m["ip_proto"] = 6
                if sp  is not None: m["tcp_src"] = int(sp)
                if dpn is not None: m["tcp_dst"] = int(dpn)
            elif proto == "UDP":
                m["ip_proto"] = 17
                if sp  is not None: m["udp_src"] = int(sp)
                if dpn is not None: m["udp_dst"] = int(dpn)
            elif proto == "ICMP":
                m["ip_proto"] = 1
            send(p.OFPMatch(**m))
            return cookie

        return None

