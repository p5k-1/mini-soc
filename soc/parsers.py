"""Parsers: turn raw log lines into normalized Event objects."""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator


@dataclass
class Event:
    time: datetime
    kind: str            # ssh_failed | ssh_success | web_request
    ip: str
    user: str = ""
    method: str = ""
    path: str = ""
    status: int = 0
    agent: str = ""


SSH_LINE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
SSH_FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
SSH_OK = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)")

WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<agent>[^"]*)"'
)


def parse_ssh(lines: Iterable[str], year: int) -> Iterator[Event]:
    """Parse sshd syslog lines. Syslog has no year, so we pass it in."""
    for line in lines:
        m = SSH_LINE.match(line.strip())
        if not m:
            continue
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
        msg = m["msg"]
        f = SSH_FAILED.search(msg)
        if f:
            yield Event(ts, "ssh_failed", f["ip"], user=f["user"])
            continue
        ok = SSH_OK.search(msg)
        if ok:
            yield Event(ts, "ssh_success", ok["ip"], user=ok["user"])


def parse_web(lines: Iterable[str]) -> Iterator[Event]:
    """Parse nginx/apache 'combined' access log lines."""
    for line in lines:
        m = WEB_LINE.match(line.strip())
        if not m:
            continue
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        yield Event(ts, "web_request", m["ip"], method=m["method"], path=m["path"],
                    status=int(m["status"]), agent=m["agent"])
