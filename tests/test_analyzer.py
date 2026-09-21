import unittest

from analyzer import analyze_events, parse_log_line


class TestLogAnalyzer(unittest.TestCase):
    def test_parses_failed_login_for_invalid_user(self):
        event = parse_log_line(
            "2026-09-20 08:10:03 sshd[1001]: Failed password for invalid user "
            "admin from 192.0.2.10 port 52344 ssh2"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.action, "Failed")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.ip_address, "192.0.2.10")

    def test_flags_repeated_failures_and_success_after_failures(self):
        events = [
            parse_log_line("2026-09-20 08:10:03 sshd[1]: Failed password for admin from 192.0.2.10 port 1 ssh2"),
            parse_log_line("2026-09-20 08:10:04 sshd[2]: Failed password for admin from 192.0.2.10 port 2 ssh2"),
            parse_log_line("2026-09-20 08:10:05 sshd[3]: Failed password for admin from 192.0.2.10 port 3 ssh2"),
            parse_log_line("2026-09-20 08:10:06 sshd[4]: Accepted password for adriel from 192.0.2.10 port 4 ssh2"),
        ]
        report = analyze_events(events, failed_attempt_threshold=3)
        self.assertEqual(report["brute_force_ips"], {"192.0.2.10": 3})
        self.assertEqual(len(report["successful_after_failures"]), 1)


if __name__ == "__main__":
    unittest.main()
