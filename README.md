# Security Log Analyzer

This is a Python and cybersecurity project. It reads an SSH authentication log and looks for login activity that could be suspicious. It also sends a report containing security alerts to the analyst email.

## Why I built this

When I worked at Kyndryl/IBM on mainframe security I built an automation using Python + Ansible that read the mainframe logs and detected user passphrase expiration events to send a notification email to the user's address. So I decided to create a slightly different version that would apply to SSH logs and detect security concerns.

## What it does

- Reads supported OpenSSH login entries from a log file
- Ignores non-login lines to run the code smoothly and counts them as ignored lines.
- Flags possible brute force attacks: IP addresses with repeated failed attempts
- Flags a successful login from an IP address that had failed attempts earlier
- Summarizes all the Alerts, events, and ignored lines.
- Sends a report with all the events and alerts to the analyst email.

## How to run it

Clone the repository, open a terminal in the project folder, and run:

```bash
python3 analyzer.py auth.log # Will run and print the email, alerts and events.
```

Use --send at the end to send the email using the variables:

| Variable | Required | Description |
|---|---|---|
| `SMTP_HOST` | Yes | SMTP server address (e.g. `sandbox.smtp.mailtrap.io`) |
| `SMTP_PORT` | Yes | SMTP port address (e.g. `587`) |
| `SMTP_USER` | Yes | SMTP user (e.g. `your_smtp_user`) | 
| `SMTP_PASSWORD` | Yes | SMTP password (using read -s to safely hide the password) | 
| `ALERT_FROM` | No| Sender address (default: `analyzer@example.com`) |
| `ALERT_TO` | No | Recipient address (default: `iamsec@example.com`) |

```bash
python3 analyzer.py auth.log --send # Was tested using Mailtrap.
```

## Example output (with --send)

```text
[ALERT] Successful login by adriel from 192.0.2.10, after a previous failed attempt
[ALERT] Successful login by maria from 192.0.2.30, after a previous failed attempt
[ALERT] Successful login by joao from 192.0.2.31, after a previous failed attempt
[ALERT] Possible Brute Force from 192.0.2.10 (4 failed attempts)
[ALERT] Possible Brute Force from 192.0.2.44 (5 failed attempts)
[ALERT] Possible Brute Force from 192.0.2.61 (4 failed attempts)
Events:31 Ignored:0
Email sent.
```

## How it works

For each line, a regular expression extracts the login outcome (Failed/Accepted), the username and the source IP. Lines that don't match (e.g. `Connection closed`) are skipped and counted as ignored. Failed attempts are counted per IP in a dictionary. The "successful login after failures" check runs while the log is being read, so only failures that happened *before* the login count. At the end, the program builds the email report.

## Design decisions

- **Login-order bug fix.** The first version collected every failure in the file before checking successful logins, so a failure that happened *after* a login still triggered an alert (a false positive). This version checks in chronological order while reading. `test_order.log` proves the fix.
- **One email per run.** All alerts from a run go into a single email, so a large brute-force attack doesn't flood the inbox. In production, the analyzer would run every 15 minutes (e.g. via cron), keeping the maximum delay at 15 minutes, plus a daily summary email (even with no alerts) as a heartbeat: if it doesn't arrive, the analyzer is down.
- **Credentials in environment variables.** SMTP host, port, user and password come from environment variables, so no secrets are stored in the code or on GitHub, and any mail provider works without code changes.

## Files in this project

```text
analyzer.py             Main Python program
auth.log                Sample SSH authentication log
test_noise.log          Log to test and prove line ignoring fix
test_order.log          Log to test and prove reading line order fix.
test_analyzer.py        Basic tests for the parser and alerts
```

## Testing

Run the tests with:

```bash
python3 test_analyzer.py
```

They will:

- `test_order.log`: a successful login *before* a failure must not trigger an alert.
- `test_noise.log`: non-login lines are skipped and counted as ignored.
- `auth.log`: the full sample produces 31 events, 0 ignored lines and 6 alerts.

## Limitations

- The threshold is limited at 3.
- The alerts have no timestamp.
- The log is analyzed entirely (no time window).
- The regex only catches IPv4 format.

## Next steps

- Support for more Linux log formats.
- Exporting results to JSON or CSV.
- Checking login attempts within a time window.
- More detailed alerts and reports.
