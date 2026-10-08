"""Generate fake logs (with embedded attacks) so you can test Mini-SOC safely.
All IPs come from documentation ranges (RFC 5737), so they are not real hosts."""
import os
import random
from datetime import datetime, timedelta

random.seed(42)
YEAR = datetime.now().year
BASE = datetime(YEAR, 10, 8, 0, 0, 0)
os.makedirs("sample_logs", exist_ok=True)


def sysl(t, msg):
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S} srv01 sshd[{random.randint(1000, 9999)}]: {msg}"


def web(t, ip, method, path, status, agent="Mozilla/5.0"):
    return f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} 512 "-" "{agent}"'


auth = []
for _ in range(30):  # normal daytime logins
    t = BASE + timedelta(hours=random.randint(8, 17), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
    auth.append((t, sysl(t, f"Accepted password for {random.choice(['ahmed', 'sara', 'omar'])} from 10.0.0.{random.randint(2, 50)} port 5{random.randint(1000, 9999)} ssh2")))
for _ in range(4):  # a few typos (should NOT alert)
    t = BASE + timedelta(hours=10, minutes=random.randint(0, 59))
    auth.append((t, sysl(t, f"Failed password for sara from 10.0.0.12 port 50000 ssh2")))
t0 = BASE + timedelta(hours=3, minutes=10)  # attack 1: brute force then success
for i in range(25):
    t = t0 + timedelta(seconds=i * 4)
    auth.append((t, sysl(t, f"Failed password for {'invalid user ' if i % 3 == 0 else ''}{random.choice(['root', 'admin', 'test'])} from 203.0.113.50 port 4{i:04d} ssh2")))
t = t0 + timedelta(seconds=110)
auth.append((t, sysl(t, "Accepted password for root from 203.0.113.50 port 44444 ssh2")))
t0 = BASE + timedelta(hours=14)  # attack 2: brute force, no success
for i in range(8):
    t = t0 + timedelta(seconds=i * 20)
    auth.append((t, sysl(t, f"Failed password for admin from 198.51.100.23 port 3{i:04d} ssh2")))
t = BASE + timedelta(hours=2, minutes=30)  # odd-hours login
auth.append((t, sysl(t, "Accepted publickey for omar from 10.0.0.9 port 51515 ssh2")))

logs = []
for _ in range(200):  # normal web traffic
    t = BASE + timedelta(seconds=random.randint(0, 86399))
    logs.append((t, web(t, f"10.0.1.{random.randint(2, 99)}", "GET", random.choice(["/", "/index.html", "/about", "/products"]), 200)))
t0 = BASE + timedelta(hours=11)  # scanner
for i, p in enumerate(["/admin", "/login.php", "/.env", "/backup.zip", "/phpmyadmin", "/wp-login.php"] * 5):
    t = t0 + timedelta(seconds=i)
    logs.append((t, web(t, "198.51.100.9", "GET", p, 404, "Nikto/2.1.6")))
t0 = BASE + timedelta(hours=16)  # injection attempts
for path in ["/products?id=1+UNION+SELECT+username,password+FROM+users", "/search?q=<script>alert(1)</script>",
             "/download?file=../../etc/passwd", "/products?id=1%20OR%201=1"]:
    t0 += timedelta(seconds=7)
    logs.append((t0, web(t0, "192.0.2.77", "GET", path, 200, "sqlmap/1.7")))

with open("sample_logs/auth.log", "w") as f:
    f.write("\n".join(l for _, l in sorted(auth)) + "\n")
with open("sample_logs/access.log", "w") as f:
    f.write("\n".join(l for _, l in sorted(logs)) + "\n")
print("Created sample_logs/auth.log and sample_logs/access.log")
