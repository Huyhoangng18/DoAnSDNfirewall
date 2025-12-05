# -*- coding: utf-8 -*-
"""
rest.py — UnifiedRest controller wiring to WSGI.

Split from unified_sdn.py for improved maintainability.
"""

import json
from ryu.app.wsgi import ControllerBase, route
from webob import Response

from .constants import APP_NAME, REST_BASE_RYU, REST_BASE_IDS


class UnifiedRest(ControllerBase):
    """REST API controller for the UnifiedSDN application."""

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[APP_NAME]

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
            reload_ = bool((req.GET or {}).get('reload', 'true').lower() != 'false')
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
        lim = int(q.get('limit', '200'))
        types = (q.get('types', 'alert') or 'alert').split(',')
        data = self.app.ids_alerts_list(limit=lim, types=types)
        return Response(body=json.dumps(data, ensure_ascii=False).encode('utf-8'),
                        content_type='application/json; charset=utf-8')
