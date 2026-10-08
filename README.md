# 🛡️ Mini-SOC

A small **Security Operations Center (SOC)** project in Python.
It reads SSH and web-server logs, detects suspicious behaviour with detection rules, maps each alert to **MITRE ATT&CK**, and produces a JSON file plus an HTML report.

أداة صغيرة تحاكي عمل مركز عمليات الأمن (SOC): تقرأ سجلات SSH وسجلات الويب، تكتشف السلوك المشبوه بقواعد كشف، وتطلع تقرير HTML وملف JSON.

## Features
| Rule | Severity | MITRE |
|------|----------|-------|
| SSH brute force (5+ failures in 5 min from one IP) | High | T1110 |
| Possible account compromise (success right after failures) | Critical | T1110 / T1078 |
| Off-hours login (00:00–05:00) | Medium | T1078 |
| Web scanning (15+ 4xx responses in 1 min) | Medium | T1595 |
| Web attacks: SQLi, XSS, Path Traversal | High | T1190 |
| Attack-tool User-Agent (sqlmap, nikto, nmap...) | Medium | T1595 |

## Requirements
Python 3.8+ only. No external libraries.

## Run
```bash
# 1) generate fake logs that contain simulated attacks
python generate_sample_logs.py

# 2) analyze them
python main.py --auth sample_logs/auth.log --web sample_logs/access.log

# 3) open the report
#    output/report.html   (visual report)
#    output/alerts.json   (machine-readable)
```
On real servers use: `--auth /var/log/auth.log --web /var/log/nginx/access.log`.

## Tests
```bash
python -m unittest discover -s tests -v
```

## How it works
```
 raw logs ──► parsers.py ──► Event objects ──► rules.py ──► Alerts ──► report.py ──► HTML / JSON
```
- `soc/parsers.py` – regex parsers that turn log lines into a common `Event` format.
- `soc/rules.py` – detection rules (sliding-window counting, pattern matching).
- `soc/report.py` – console table, JSON, HTML.
- `main.py` – command-line interface.

## Add your own rule
In `soc/rules.py` write a function that takes `events` and returns a list of `Alert`, then add it to `run_all()`.

## Ideas to extend
- Real-time monitoring (tail -f), email/Telegram notifications
- GeoIP lookup and IP reputation (AbuseIPDB)
- Automatic blocking via firewall
- Dashboard with Flask/Streamlit

## Disclaimer
For learning and defensive purposes. Sample logs use reserved documentation IP addresses (RFC 5737).

## License
MIT
