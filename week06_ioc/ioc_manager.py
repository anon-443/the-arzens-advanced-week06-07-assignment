#!/usr/bin/env python3
"""JSON-backed IOC lifecycle manager with export, reporting, and health checks."""
import argparse, csv, datetime as dt, html, json, subprocess, sys
from pathlib import Path

def today(): return dt.date.today()
def load(p):
    try: return json.loads(Path(p).read_text())
    except (FileNotFoundError, json.JSONDecodeError): return {"version": 1, "iocs": {}}
def save(p, d): Path(p).write_text(json.dumps(d, indent=2, sort_keys=True) + "\n")
def parse_input(path):
    with open(path, newline="", encoding="utf-8") as f: return [(r["indicator"].strip(), r.get("type", "unknown")) for r in csv.DictReader(f)]
def add_file(db, path, expiration):
    for indicator, typ in parse_input(path):
        old = db["iocs"].get(indicator, {})
        now = today().isoformat()
        db["iocs"][indicator] = {**old, "indicator": indicator, "type": typ, "first_seen": old.get("first_seen", now), "last_seen": now, "expiration": (today() + dt.timedelta(days=expiration)).isoformat(), "confidence": old.get("confidence", 0.25), "risk_score": old.get("risk_score", 0), "sources": old.get("sources", ["import"]), "status": "active"}
def expire(db):
    count = 0
    for item in db["iocs"].values():
        if item.get("expiration", "9999") < today().isoformat() and item.get("status") != "expired": item["status"] = "expired"; count += 1
    return count
def report(db, path):
    rows = [i for i in db["iocs"].values() if i.get("status") == "active"]
    body = "".join(f'<tr><td>{html.escape(i["indicator"])}</td><td>{html.escape(i.get("type", ""))}</td><td>{i.get("risk_score", 0)}</td><td>{i.get("confidence", 0)}</td><td>{i.get("expiration", "")}</td></tr>' for i in rows)
    Path(path).write_text(f'<!doctype html><html><head><meta charset="utf-8"><title>Weekly IOC Report</title><style>body{{font:15px Arial;margin:40px;color:#17202a}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccd;padding:8px;text-align:left}}th{{background:#eaf2f8}}</style></head><body><h1>Weekly IOC Intelligence Report</h1><p>Active indicators: {len(rows)} | Generated: {today()}</p><table><tr><th>Indicator</th><th>Type</th><th>Risk</th><th>Confidence</th><th>Expires</th></tr>{body}</table></body></html>', encoding="utf-8")
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--db", default=str(Path(__file__).with_name("ioc_database.json"))); ap.add_argument("--add-file"); ap.add_argument("--update-all", action="store_true"); ap.add_argument("--expire-check", action="store_true"); ap.add_argument("--export-blocklist", action="store_true"); ap.add_argument("--output", default=str(Path(__file__).with_name("blocklist.txt"))); ap.add_argument("--report"); ap.add_argument("--expiration-days", type=int, default=30); a=ap.parse_args(); db=load(a.db)
    if a.add_file: add_file(db, a.add_file, a.expiration_days)
    if a.update_all:
        for i in db["iocs"].values(): i["last_seen"] = today().isoformat(); i["status"] = "active"
    if a.expire_check: print(f"Expired {expire(db)} IOC(s)")
    if a.export_blocklist:
        Path(a.output).write_text("\n".join(f'{i["indicator"]}|{i.get("type", "unknown")}|{i.get("risk_score", 0)}|{i.get("confidence", 0)}' for i in db["iocs"].values() if i.get("status") == "active") + "\n")
    if a.report: report(db, a.report)
    save(a.db, db)
    print(f"IOC health: {len(db['iocs'])} total, {sum(i.get('status') == 'active' for i in db['iocs'].values())} active")
if __name__ == "__main__": main()
