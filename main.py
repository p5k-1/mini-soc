"""Mini-SOC command line entry point."""
import argparse
import os
from datetime import datetime

from soc.parsers import parse_ssh, parse_web
from soc.report import print_console, write_html, write_json
from soc.rules import run_all


def main():
    p = argparse.ArgumentParser(description="Mini-SOC: detect suspicious activity in logs")
    p.add_argument("--auth", help="path to SSH auth log (syslog format)")
    p.add_argument("--web", help="path to web access log (combined format)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year for syslog dates")
    p.add_argument("--out", default="output", help="output directory")
    args = p.parse_args()

    if not args.auth and not args.web:
        p.error("give at least one of --auth / --web")

    events = []
    if args.auth:
        with open(args.auth, encoding="utf-8", errors="replace") as f:
            events += list(parse_ssh(f, args.year))
    if args.web:
        with open(args.web, encoding="utf-8", errors="replace") as f:
            events += list(parse_web(f))

    print(f"Parsed {len(events)} events\n")
    alerts = run_all(events)
    print_console(alerts)

    os.makedirs(args.out, exist_ok=True)
    write_json(alerts, os.path.join(args.out, "alerts.json"))
    write_html(alerts, os.path.join(args.out, "report.html"))
    print(f"\nSaved: {args.out}/alerts.json and {args.out}/report.html")


if __name__ == "__main__":
    main()
