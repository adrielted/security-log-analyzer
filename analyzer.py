#!/usr/bin/env python3
"""Analyze SSH authentication logs for simple suspicious activity patterns."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


SSH_EVENT_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"sshd\[\d+\]: (?P<action>Failed|Accepted) password for "
    r"(?:(?:invalid user) )?(?P<username>\S+) from "
    r"(?P<ip_address>\S+) port \d+ ssh2$"
)


@dataclass(frozen=True)
class AuthEvent:
    """One parsed SSH authentication event."""

    timestamp: str
    action: str
    username: str
    ip_address: str


def parse_log_line(line: str) -> AuthEvent | None:
    """Return an AuthEvent for a supported log line, otherwise return None."""
    match = SSH_EVENT_PATTERN.match(line.strip())
    return AuthEvent(**match.groupdict()) if match else None


def analyze_events(events: list[AuthEvent], failed_attempt_threshold: int = 3) -> dict:
    """Count activity and identify straightforward alert patterns."""
    failed_by_ip = Counter(event.ip_address for event in events if event.action == "Failed")
    failed_by_user = Counter(event.username for event in events if event.action == "Failed")
    failed_ips = set(failed_by_ip)

    brute_force_ips = {
        ip_address: attempts
        for ip_address, attempts in failed_by_ip.items()
        if attempts >= failed_attempt_threshold
    }
    successful_after_failures = [
        event for event in events
        if event.action == "Accepted" and event.ip_address in failed_ips
    ]

    return {
        "total_events": len(events),
        "successful_logins": sum(event.action == "Accepted" for event in events),
        "failed_logins": sum(event.action == "Failed" for event in events),
        "failed_by_ip": failed_by_ip,
        "failed_by_user": failed_by_user,
        "brute_force_ips": brute_force_ips,
        "successful_after_failures": successful_after_failures,
    }


def read_events(log_path: Path) -> tuple[list[AuthEvent], int]:
    """Read supported events from a log file and count ignored lines."""
    events: list[AuthEvent] = []
    ignored_lines = 0
    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            event = parse_log_line(line)
            if event is None:
                ignored_lines += 1
            else:
                events.append(event)
    return events, ignored_lines


def print_report(report: dict, ignored_lines: int, threshold: int) -> None:
    """Print a readable command-line report."""
    print("\nSecurity Log Analysis Report")
    print("=" * 28)
    print(f"Parsed events:       {report['total_events']}")
    print(f"Successful logins:   {report['successful_logins']}")
    print(f"Failed logins:       {report['failed_logins']}")
    print(f"Ignored log lines:   {ignored_lines}")

    print("\nFailed attempts by IP:")
    if report["failed_by_ip"]:
        for ip_address, attempts in report["failed_by_ip"].most_common():
            print(f"  - {ip_address}: {attempts}")
    else:
        print("  None")

    print(f"\nAlerts (threshold: {threshold} failed attempts):")
    if report["brute_force_ips"]:
        for ip_address, attempts in report["brute_force_ips"].items():
            print(f"  [HIGH] Possible brute-force activity from {ip_address} ({attempts} failures)")
    else:
        print("  No brute-force pattern detected.")
    for event in report["successful_after_failures"]:
        print(f"  [MEDIUM] Successful login for {event.username} from {event.ip_address} after earlier failures from that IP")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze OpenSSH authentication logs for suspicious activity."
    )
    parser.add_argument("log_file", type=Path, help="Path to an SSH authentication log")
    parser.add_argument(
        "--threshold", type=int, default=3,
        help="Failed attempts from one IP before an alert (default: 3)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.threshold < 1:
        raise SystemExit("Error: --threshold must be at least 1.")
    if not args.log_file.is_file():
        raise SystemExit(f"Error: log file not found: {args.log_file}")
    events, ignored_lines = read_events(args.log_file)
    print_report(analyze_events(events, args.threshold), ignored_lines, args.threshold)


if __name__ == "__main__":
    main()
