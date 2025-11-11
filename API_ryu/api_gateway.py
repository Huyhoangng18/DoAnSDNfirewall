#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, send_from_directory
import requests, os

app = Flask(__name__, static_url_path='', static_folder='static')

RYU_BASE = os.environ.get('RYU_BASE', 'http://127.0.0.1:8080')
TIMEOUT = 8

@app.route('/')
def root():
    return send_from_directory('static', 'index.html')

# -------- RULES ----------
@app.get('/api/rules')
def list_rules():
    r = requests.get(f'{RYU_BASE}/ryu/rules', timeout=TIMEOUT)
    return (r.text, r.status_code, r.headers.items())

@app.post('/api/rules')
def upsert_rule():
    data = request.get_json(force=True)
    r = requests.post(f'{RYU_BASE}/ryu/rules', json=data, timeout=TIMEOUT)
    return (r.text, r.status_code, r.headers.items())

@app.delete('/api/rules/<rid>')
def delete_rule(rid):
    r = requests.delete(f'{RYU_BASE}/ryu/rules/{rid}', timeout=TIMEOUT)
    return (r.text, r.status_code, r.headers.items())

# -------- TI ----------
@app.get('/api/ti')
def ti_list():
    offset = request.args.get('offset','0')
    limit  = request.args.get('limit','500')
    r = requests.get(f'{RYU_BASE}/ryu/ti', params={'offset': offset, 'limit': limit}, timeout=TIMEOUT)
    return (r.text, r.status_code, r.headers.items())

@app.post('/api/ti')
def ti_add():
    data = request.get_json(force=True)
    r = requests.post(f'{RYU_BASE}/ryu/ti', json=data, timeout=TIMEOUT)
    return (r.text, r.status_code, r.headers.items())

@app.delete('/api/ti')
def ti_del():
    data = request.get_json(force=True)
    r = requests.delete(f'{RYU_BASE}/ryu/ti', json=data, timeout=TIMEOUT)
    return (r.text, r.status_code, r.headers.items())

# -------- IDS RULES ----------
@app.get('/api/ids/rules')
def ids_rules():
    r = requests.get(f'{RYU_BASE}/ids/rules', timeout=TIMEOUT)
    return (r.text, r.status_code, r.headers.items())

@app.post('/api/ids/rules')
def ids_rules_add():
    data = request.get_json(force=True)
    r = requests.post(f'{RYU_BASE}/ids/rules', json=data, timeout=TIMEOUT)
    return (r.text, r.status_code, r.headers.items())

@app.delete('/api/ids/rules/<sid>')
def ids_rules_delete(sid):
    reload_ = request.args.get('reload','true')
    r = requests.delete(f'{RYU_BASE}/ids/rules/{sid}', params={'reload': reload_}, timeout=TIMEOUT)
    return (r.text, r.status_code, r.headers.items())

# -------- IDS ALERTS ----------
@app.get('/api/ids/alerts')
def ids_alerts():
    limit = request.args.get('limit','200')
    types = request.args.get('types','alert,http,flow')
    r = requests.get(f'{RYU_BASE}/ids/alerts', params={'limit':limit,'types':types}, timeout=TIMEOUT)
    return (r.text, r.status_code, r.headers.items())

if __name__ == '__main__':
    app.run('0.0.0.0', 5000, debug=True)

