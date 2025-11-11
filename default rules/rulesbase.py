#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import mac

# Cập nhật theo topology của bạn
IP_HX = '192.168.10.100'
CIDR_DEPT1 = ('10.0.1.0', '255.255.255.0')
CIDR_DEPT2 = ('10.0.2.0', '255.255.255.0')

class ACLSL3(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Nếu muốn chỉ áp dụng trên sL3, điền đúng dpid của sL3 vào đây.
    # Mininet/OVS thường gán s1=1, s2=2, sL3=3 (hex). Nếu khác, sửa danh sách này.
    APPLY_DPIDS = {1,2,3}  # hoặc {3} nếu biết chắc sL3 là dpid=3

    def add_flow(self, datapath, table_id, priority, match, actions=None, inst=None):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        if inst is None:
            if actions is None:
                inst = []
            else:
                inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=table_id,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Chỉ áp dụng trên các switch mong muốn
        if dp.id not in self.APPLY_DPIDS:
            # Nhưng vẫn nên có table-miss ở table 1 để tránh treo
            self._ensure_table1_normal(dp)
            return

        # --- TABLE 0: ACL ---
        # Mặc định: goto table 1
        self.add_flow(dp, table_id=0, priority=0,
                      match=parser.OFPMatch(),
                      inst=[parser.OFPInstructionGotoTable(1)])

        # 1) ALLOW Nội bộ -> hX: ICMP echo-request (type 8)
        m = parser.OFPMatch(eth_type=0x0800,           # IPv4
                            ipv4_dst=IP_HX,
                            ip_proto=1,                # ICMP
                            icmpv4_type=8)             # echo-request
        self.add_flow(dp, 0, 30000, m,
                      inst=[parser.OFPInstructionGotoTable(1)])

        # 2) ALLOW Nội bộ -> hX: TCP dst 80
        m = parser.OFPMatch(eth_type=0x0800,
                            ipv4_dst=IP_HX,
                            ip_proto=6,                # TCP
                            tcp_dst=80)
        self.add_flow(dp, 0, 30000, m,
                      inst=[parser.OFPInstructionGotoTable(1)])

        # 3) ALLOW Nội bộ -> hX: TCP dst 443
        m = parser.OFPMatch(eth_type=0x0800,
                            ipv4_dst=IP_HX,
                            ip_proto=6,
                            tcp_dst=443)
        self.add_flow(dp, 0, 30000, m,
                      inst=[parser.OFPInstructionGotoTable(1)])

        # 4) ALLOW hX -> Nội bộ (chỉ gói trả lời): ICMP echo-reply (type 0)
        for cidr in (CIDR_DEPT1, CIDR_DEPT2):
            m = parser.OFPMatch(eth_type=0x0800,
                                ipv4_src=IP_HX,
                                ipv4_dst=cidr,         # masked match
                                ip_proto=1,
                                icmpv4_type=0)         # echo-reply
            self.add_flow(dp, 0, 30000, m,
                          inst=[parser.OFPInstructionGotoTable(1)])

        # 5) ALLOW hX -> Nội bộ (trả lời TCP/80)
        for cidr in (CIDR_DEPT1, CIDR_DEPT2):
            m = parser.OFPMatch(eth_type=0x0800,
                                ipv4_src=IP_HX,
                                ipv4_dst=cidr,
                                ip_proto=6,
                                tcp_src=80)
            self.add_flow(dp, 0, 30000, m,
                          inst=[parser.OFPInstructionGotoTable(1)])

        # 6) ALLOW hX -> Nội bộ (trả lời TCP/443)
        for cidr in (CIDR_DEPT1, CIDR_DEPT2):
            m = parser.OFPMatch(eth_type=0x0800,
                                ipv4_src=IP_HX,
                                ipv4_dst=cidr,
                                ip_proto=6,
                                tcp_src=443)
            self.add_flow(dp, 0, 30000, m,
                          inst=[parser.OFPInstructionGotoTable(1)])

        # 7) DROP hX -> Nội bộ (mọi thứ còn lại)
        for cidr in (CIDR_DEPT1, CIDR_DEPT2):
            m = parser.OFPMatch(eth_type=0x0800,
                                ipv4_src=IP_HX,
                                ipv4_dst=cidr)
            self.add_flow(dp, 0, 20000, m, actions=[])  # drop

        # --- TABLE 1: NORMAL ---
        self._ensure_table1_normal(dp)

    def _ensure_table1_normal(self, dp):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        # Table 1: table-miss -> NORMAL
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, table_id=1, priority=0,
                      match=parser.OFPMatch(), actions=actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        # App ACL này không cần xử lý PacketIn; mọi thứ đi qua flow sẵn có
        pass

