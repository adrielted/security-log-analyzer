# Security Log Analyzer

This is a beginner Python and cybersecurity project. It reads an SSH authentication log and looks for login activity that could be suspicious, such as several failed passwords from the same IP address.

I made this project to practice reading files with Python, working with log data, and thinking about basic security events.

## What it does

- Reads supported OpenSSH login entries from a log file
- Counts successful and failed password attempts
- Shows which IP addresses had failed login attempts
- Flags IP addresses with repeated failed attempts
- Flags a successful login from an IP address that had failed attempts earlier

An alert does not automatically mean an attack happened. It is a sign that someone should investigate the activity.

## How to run it

Clone the repository, open a terminal in the project folder, and run:

```bash
python3 analyzer.py auth.log
```

To change the number of failed attempts needed for an alert, use `--threshold`:

```bash
python3 analyzer.py auth.log --threshold 5
```

## Example output

```text
Security Log Analysis Report
============================
Parsed events:       31
Successful logins:   12
Failed logins:       19
Ignored log lines:   0

Failed attempts by IP:
  - 192.0.2.44: 5
  - 192.0.2.10: 4
  - 192.0.2.61: 4

Alerts (threshold: 3 failed attempts):
  [HIGH] Possible brute-force activity from 192.0.2.10 (4 failures)
  [HIGH] Possible brute-force activity from 192.0.2.44 (5 failures)
  [HIGH] Possible brute-force activity from 192.0.2.61 (4 failures)
  [MEDIUM] Successful login for adriel from 192.0.2.10 after earlier failures from that IP
```

## How it works

The program reads the log one line at a time. It uses a regular expression to find the date, login result, username, and source IP address in each supported line. Then it uses Python counters to add up failed attempts and print alerts.

The sample `auth.log` file is fictional and uses `192.0.2.x` addresses, which are reserved for documentation and examples.

## Files in this project

```text
analyzer.py             Main Python program
auth.log                Sample SSH authentication log
tests/test_analyzer.py  Basic tests for the parser and alerts
```

## Testing

Run the tests with:

```bash
python3 -m unittest discover -s tests -v
```

## Things I want to add later

- Support for more Linux log formats
- Exporting results to JSON or CSV
- Checking login attempts within a time window
- An allow-list for trusted IP addresses
