import unittest
from datetime import datetime, timedelta

from soc.parsers import Event, parse_ssh, parse_web
from soc.rules import run_all


def failed(ip, n, start=datetime(2026, 10, 8, 10, 0, 0), step=5):
    return [Event(start + timedelta(seconds=i * step), "ssh_failed", ip, user="root") for i in range(n)]


class TestRules(unittest.TestCase):
    def test_brute_force_detected(self):
        names = [a.rule for a in run_all(failed("1.1.1.1", 6))]
        self.assertIn("SSH Brute Force", names)

    def test_few_failures_ignored(self):
        self.assertEqual(run_all(failed("1.1.1.1", 3)), [])

    def test_slow_failures_ignored(self):
        self.assertEqual(run_all(failed("1.1.1.1", 6, step=120)), [])

    def test_compromise_is_critical(self):
        ev = failed("1.1.1.1", 6)
        ev.append(Event(ev[-1].time + timedelta(seconds=10), "ssh_success", "1.1.1.1", user="root"))
        self.assertEqual(run_all(ev)[0].severity, "Critical")

    def test_sql_injection(self):
        e = Event(datetime(2026, 10, 8, 10), "web_request", "2.2.2.2", method="GET",
                  path="/x?id=1+UNION+SELECT+1", status=200, agent="Mozilla")
        self.assertIn("Web Attack: SQL Injection", [a.rule for a in run_all([e])])

    def test_parsers(self):
        ssh = list(parse_ssh(["Oct  8 03:10:01 srv sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"], 2026))
        self.assertEqual((ssh[0].kind, ssh[0].ip), ("ssh_failed", "1.2.3.4"))
        web = list(parse_web(['5.6.7.8 - - [08/Oct/2026:10:00:01 +0000] "GET /a HTTP/1.1" 404 5 "-" "curl"']))
        self.assertEqual((web[0].status, web[0].path), (404, "/a"))


if __name__ == "__main__":
    unittest.main()
