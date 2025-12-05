# -*- coding: utf-8 -*-
"""
SDN Modules Package - Split from unified_sdn.py for improved maintainability.

This package provides modular components for the SDN firewall application:
- rules: RULES logic (table 0), CRUD, file handling
- ti: Threat Intelligence fetcher and TI APIs
- ids: EVE tailer, IDS auto-block, Suricata local.rules management
- pipeline: Datapath, pipeline install, sL3 pick, and flow helpers
- rest: UnifiedRest controller with WSGI routes
"""
