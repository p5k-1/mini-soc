"""Detection rules. Each rule takes a list of Events and returns a list of Alerts."""
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import unquote_plus

from .parsers import Event

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Tunable thresholds
BRUTE_FORCE_THRESHOLD = 5          # failed logins ...
BRUTE_FORCE_WINDOW = timedelta(minutes=5)   # ... within this window
WEB_SCAN_THRESHOLD = 15            # 4xx responses ...
WEB_SCAN_WINDOW = timedelta(minutes=1)      # ... within this window
OFF_HOURS = (0, 5)                 # 00:00-04:59 logins are suspicious

ATTACK_PATTERNS = {
    "SQL Injection": re.compile(r"union\s+select|or\s+1=1|' or '|sleep\(\d+\)|information_schema"),
    "XSS": re.compile(r"<script|onerror=|javascript:"),
    "Path Traversal": re.compile(r"\.\./|/etc/passwd"),
}
BAD_USER_AGENTS = ("sqlmap", "nikto", "nmap", "masscan", "dirbuster", "hydra")


@dataclass
class Alert:
    rule: str
    severity: str
    ip: str
    time: str
    count: int
    description: str
    mitre: str


def _burst(times, window, threshold):
    """Sliding window: return (start_time, max_count) if >= threshold events fit in window."""
    times = sorted(times)
    best, start, j = 0, None, 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        n = i - j + 1
        if n >= threshold and n > best:
            best, start = n, times[j]
    return (start, best) if best else None


def ssh_brute_force(events):
    by_ip = defaultdict(list)
    for e in events:
        if e.kind == "ssh_failed":
            by_ip[e.ip].append(e.time)
    alerts = []
    for ip, times in by_ip.items():
        hit = _burst(times, BRUTE_FORCE_WINDOW, BRUTE_FORCE_THRESHOLD)
        if hit:
            start, n = hit
            alerts.append(Alert("SSH Brute Force", "High", ip, start.isoformat(" "), n,
                                f"{n} failed SSH logins within {BRUTE_FORCE_WINDOW}", "T1110"))
    return alerts


def ssh_compromise(events):
    """Successful login right after a burst of failures = likely compromised account."""
    failed = defaultdict(list)
    for e in events:
        if e.kind == "ssh_failed":
            failed[e.ip].append(e.time)
    alerts = []
    for e in events:
        if e.kind != "ssh_success":
            continue
        recent = [t for t in failed[e.ip] if timedelta(0) <= e.time - t <= timedelta(minutes=10)]
        if len(recent) >= BRUTE_FORCE_THRESHOLD:
            alerts.append(Alert("Possible Account Compromise", "Critical", e.ip,
                                e.time.isoformat(" "), len(recent),
                                f"Successful login as '{e.user}' after {len(recent)} failures", "T1110/T1078"))
    return alerts


def off_hours_login(events, skip_ips=()):
    alerts = []
    for e in events:
        if e.kind == "ssh_success" and OFF_HOURS[0] <= e.time.hour < OFF_HOURS[1] and e.ip not in skip_ips:
            alerts.append(Alert("Off-Hours Login", "Medium", e.ip, e.time.isoformat(" "), 1,
                                f"User '{e.user}' logged in at {e.time:%H:%M}", "T1078"))
    return alerts


def web_scanning(events):
    by_ip = defaultdict(list)
    for e in events:
        if e.kind == "web_request" and 400 <= e.status < 500:
            by_ip[e.ip].append(e.time)
    alerts = []
    for ip, times in by_ip.items():
        hit = _burst(times, WEB_SCAN_WINDOW, WEB_SCAN_THRESHOLD)
        if hit:
            start, n = hit
            alerts.append(Alert("Web Scanning", "Medium", ip, start.isoformat(" "), n,
                                f"{n} client-error responses within {WEB_SCAN_WINDOW}", "T1595"))
    return alerts


def web_attacks(events):
    found = {}  # (ip, attack) -> [first_time, count]
    for e in events:
        if e.kind != "web_request":
            continue
        decoded = unquote_plus(e.path).lower()
        for name, pattern in ATTACK_PATTERNS.items():
            if pattern.search(decoded):
                key = (e.ip, name)
                if key in found:
                    found[key][1] += 1
                else:
                    found[key] = [e.time, 1]
    return [Alert(f"Web Attack: {name}", "High", ip, t.isoformat(" "), n,
                  f"{n} request(s) matching {name} patterns", "T1190")
            for (ip, name), (t, n) in found.items()]


def bad_user_agent(events):
    found = {}
    for e in events:
        if e.kind != "web_request":
            continue
        ua = e.agent.lower()
        for tool in BAD_USER_AGENTS:
            if tool in ua:
                key = (e.ip, tool)
                if key in found:
                    found[key][1] += 1
                else:
                    found[key] = [e.time, 1]
    return [Alert("Attack Tool User-Agent", "Medium", ip, t.isoformat(" "), n,
                  f"User-Agent of known tool '{tool}' seen {n} time(s)", "T1595")
            for (ip, tool), (t, n) in found.items()]


def run_all(events):
    events = list(events)
    compromise = ssh_compromise(events)
    alerts = (
        ssh_brute_force(events)
        + compromise
        + off_hours_login(events, skip_ips={a.ip for a in compromise})
        + web_scanning(events)
        + web_attacks(events)
        + bad_user_agent(events)
    )
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], a.time))
