#!/usr/bin/env python3
"""Inline edge/worker.mjs's __FILES_JSON__ placeholder with base64 of the
public/ static files. Output: /tmp/vault.built.mjs ready to PUT against the
CF Workers Scripts API."""
import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / 'public'
WORKER = ROOT / 'edge' / 'worker.mjs'
OUT = Path('/tmp/vault.built.mjs')

files = {
    rel: base64.b64encode((PUBLIC / rel).read_bytes()).decode()
    for rel in ['index.html', 'app.js', 'style.css']
}
src = WORKER.read_text(encoding='utf-8')
out = src.replace('__FILES_JSON__', json.dumps(files))
OUT.write_text(out, encoding='utf-8')
print(f'wrote {OUT}  ({len(out)} bytes)')
