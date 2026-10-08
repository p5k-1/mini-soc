"""Output: console table, JSON, and a self-contained HTML report."""
import html
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime

COLORS = {"Critical": "#b71c1c", "High": "#e65100", "Medium": "#f9a825", "Low": "#2e7d32"}


def print_console(alerts):
    if not alerts:
        print("No alerts. All quiet.")
        return
    print(f"{'SEVERITY':<9} {'RULE':<30} {'IP':<16} {'TIME':<20} COUNT")
    print("-" * 85)
    for a in alerts:
        print(f"{a.severity:<9} {a.rule:<30} {a.ip:<16} {a.time:<20} {a.count}")
    print("\nSummary:", dict(Counter(a.severity for a in alerts)))


def write_json(alerts, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(a) for a in alerts], f, indent=2, ensure_ascii=False)


def write_html(alerts, path):
    counts = Counter(a.severity for a in alerts)
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {COLORS[s]}"><b>{counts.get(s, 0)}</b><span>{s}</span></div>'
        for s in COLORS)
    rows = "".join(
        f'<tr><td><span class="tag" style="background:{COLORS[a.severity]}">{a.severity}</span></td>'
        f"<td>{html.escape(a.rule)}</td><td>{html.escape(a.ip)}</td><td>{html.escape(a.time)}</td>"
        f"<td>{a.count}</td><td>{html.escape(a.mitre)}</td><td>{html.escape(a.description)}</td></tr>"
        for a in alerts)
    page = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Mini-SOC Report</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;margin:2rem;background:#f5f6f8;color:#222}}
.cards{{display:flex;gap:1rem;margin:1rem 0}}
.card{{background:#fff;padding:1rem 1.5rem;border-radius:8px;display:flex;flex-direction:column;align-items:center}}
.card b{{font-size:1.8rem}}
table{{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden}}
th,td{{padding:.6rem .8rem;text-align:left;border-bottom:1px solid #eee;font-size:.9rem}}
th{{background:#263238;color:#fff}}
.tag{{color:#fff;padding:2px 8px;border-radius:10px;font-size:.8rem}}
</style></head><body>
<h1>Mini-SOC Report</h1><p>Generated {datetime.now():%Y-%m-%d %H:%M} &middot; {len(alerts)} alerts</p>
<div class="cards">{cards}</div>
<table><tr><th>Severity</th><th>Rule</th><th>IP</th><th>Time</th><th>Count</th><th>MITRE</th><th>Details</th></tr>{rows}</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
