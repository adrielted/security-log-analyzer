import smtplib
import os
import re
import sys
from email.message import EmailMessage

def analyze(path):

    failures_by_ip = {}
    ignored = 0
    events = 0
    alerts = []

    with open(path) as log_file:
        for line in log_file:
            match = re.search(r"(Failed|Accepted)", line)
            if match is None:
                ignored += 1
                continue
            outcome = match.group(1)
        
            ip = re.search(r"\d+\.\d+\.\d+\.\d+", line).group()
            user = re.search(r"(\S+) from", line).group(1) 
            events += 1
            if outcome == "Failed":
                if ip in failures_by_ip:
                    failures_by_ip[ip] += 1
                else:
                    failures_by_ip[ip] = 1
            else:
                if ip in failures_by_ip:
                    alerts.append(f"[ALERT] Successful login by {user} from {ip}, after a previous failed attempt")

    threshold = 3
    for ip, total in failures_by_ip.items():
        if total >= threshold:
            alerts.append(f"[ALERT] Possible Brute Force from {ip} ({total} failed attempts)")
    return {"events": events, "ignored": ignored, "alerts": alerts}

def build_email(report, path):
    msg = EmailMessage()
    msg["From"] = os.environ.get("GMAIL_USER", "analyzer_v2@example.com")
    msg["To"] = os.environ.get("ALERT_TO", "iamsec@example.com")
    if len(report["alerts"]) >= 1:
        msg["Subject"] = f"[ALERT] {len(report['alerts'])} security alerts in {path}"
        body = f"The security analyzer has detected alerts in the last scan of {path}.\n"
        body += "\n"
        body += "Please check below:\n"
        body += "\n"
        body += f"Events: {report['events']}, Ignored: {report['ignored']}\n"  
        body += "\n"
        for alert in (report["alerts"]):
            body += alert + "\n"
    else:
        msg["Subject"] = f"[OK] No security alerts in {path}"
        body = f"The security analyzer has not detected alerts in the last scan of {path}.\n"
        body += "\n"
        body += "Summary:\n"
        body += "\n"
        body += f"Events: {report['events']}, Ignored: {report['ignored']}\n"
        
    msg.set_content(body)
    return msg

def send_email(msg):
    user = os.environ["GMAIL_USER"]
    password = os.environ["GMAIL_APP_PASSWORD"]
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
    # Gmail drops AUTH PLAIN from this client; force AUTH LOGIN
        server.ehlo()
        server.esmtp_features["auth"] = "LOGIN"
        server.login(user, password)
        server.send_message(msg)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 analyzer_v2.py <log_file>")

    report = analyze(sys.argv[1])
    for alert in report["alerts"]:
        print(alert)
    print(f"Events:{report['events']} Ignored:{report['ignored']}")
    msg = build_email(report, sys.argv[1])
    if "--send" in sys.argv:
        send_email(msg)
        print("Email sent.")
    else: 
        print(msg)
        
    
