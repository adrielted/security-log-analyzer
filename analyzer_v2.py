import re
import sys

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

if len(sys.argv) < 2:
    sys.exit("Uso: python3 analyzer_v2.py <log_file>")

report = analyze(sys.argv[1])
for alert in report["alerts"]:
    print(alert)
print(f"Events:{report['events']} Ignored:{report['ignored']}")