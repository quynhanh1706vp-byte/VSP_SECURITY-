#!/usr/bin/env python3
"""Recompute audit chain hashes after gateway restart/upgrade"""
import hashlib, subprocess

TENANT = '1bdf7f20-dbb3-4116-815f-26b4dc747e76'
DB = 'postgres://vsp:vsp@localhost:5432/vsp_go?sslmode=disable'

def psql(sql):
    return subprocess.run(['psql', DB, '-t', '-c', sql],
        capture_output=True, text=True).stdout

rows = []
for line in psql('SELECT seq, action, resource FROM audit_log ORDER BY seq ASC').strip().split('\n'):
    if '|' not in line: continue
    p = [x.strip() for x in line.split('|')]
    if len(p) >= 3 and p[0].isdigit():
        rows.append({'seq': int(p[0]), 'action': p[1], 'resource': p[2]})

prev_hash = ''
for row in rows:
    raw = f"{row['seq']}|{TENANT}|{row['action']}|{row['resource']}|{prev_hash}"
    h = hashlib.sha256(raw.encode()).hexdigest()
    psql(f"UPDATE audit_log SET hash='{h}', prev_hash='{prev_hash}' WHERE seq={row['seq']}")
    prev_hash = h

print(f'[+] Recomputed {len(rows)} audit chain entries')
