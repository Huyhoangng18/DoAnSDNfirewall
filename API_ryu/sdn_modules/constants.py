# -*- coding: utf-8 -*-
"""
constants.py — Shared constants split from unified_sdn.py

Contains file paths, cookies, table definitions, and environment-variable configuration
used across the SDN modules.
"""

import os

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
