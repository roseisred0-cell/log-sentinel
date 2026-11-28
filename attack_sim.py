"""
Buoc 4 + Lat cat 5 (GameDay): gia lap tan cong web cho LogSentinel.

  # Che do 1 - bom log gia thang vao CloudWatch (khong can EC2, test luat cua Detector):
  python attack_sim.py logs --ip 198.51.100.23

  # Che do 2 - tan cong that (E2E: 403 SOAR, DynamoDB BLOCKED_IP#, email/Telegram):
  python attack_sim.py http --target https://<chuoi>.cloudfront.net      # che do edge (output SocConsoleUrl)
  python attack_sim.py http --target https://<Public-IP> --insecure       # che do truc tiep (chung chi tu ky)
  Chay tu mang KHAC admin_cidr (vd 4G): IP trong admin_cidr duoc ghi nhan nhung khong bao gio bi khoa.

Chi dung tren he thong cua chinh ban. IP mau thuoc dai tai lieu RFC 5737.
"""
import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

LOG_GROUP = "/logsentinel/sample-app"
REGION = "ap-southeast-1"


# ------------------------------------------------------------ che do logs
def _event(event_type: str, ip: str, **extra) -> dict:
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "source": "attack-sim",
            "event_type": event_type, "client_ip": ip, **extra}


def run_logs(ip: str) -> None:
    import boto3

    events = [_event("FAILED_LOGIN", ip, username="admin", status_code=401) for _ in range(6)]
    events += [
        _event("SQL_INJECTION", ip, payload="' OR 1=1 --", status_code=403, severity="CRITICAL"),
        _event("MFA_BYPASS_ATTEMPT", ip, username="admin", status_code=403, severity="CRITICAL"),
        {"garbage": True},  # input xau: Detector phai bo qua, khong sap
    ]
    client = boto3.client("logs", region_name=REGION)
    stream = f"attack-sim-{int(time.time())}"
    client.create_log_stream(logGroupName=LOG_GROUP, logStreamName=stream)
    base = int(time.time() * 1000)
    client.put_log_events(logGroupName=LOG_GROUP, logStreamName=stream, logEvents=[
        {"timestamp": base + i, "message": json.dumps(e)} for i, e in enumerate(events)])
    print(f"[+] Sent {len(events)} events to {LOG_GROUP}/{stream}.")
    print("    Expected: 1 BRUTE_FORCE_DETECTED (not 2), 1 SQL_INJECTION, 1 MFA_BYPASS_ATTEMPT,")
    print(f"    and the item BLOCKED_IP#{ip} / ACTIVE in IncidentTable.")


# ------------------------------------------------------------ che do http
def _request(url: str, ctx, data: dict = None):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method="POST" if body else "GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def run_http(target: str, insecure: bool) -> None:
    ctx = ssl.create_default_context()
    if insecure:  # chi cho chung chi tu ky cua lab
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    target = target.rstrip("/")

    print("[1] Brute force: 6 wrong passwords (0.3 s apart, below the Nginx rate limit)")
    for i in range(6):
        code = _request(f"{target}/login", ctx, {"username": "admin", "password": f"wrong{i}"})
        print(f"    attempt {i + 1}: HTTP {code}")
        time.sleep(0.3)

    print("[2] Waiting for the Detector to block the IP (up to ~20 s)...")
    for _ in range(10):
        time.sleep(2)
        code = _request(f"{target}/health", ctx)
        if code == 403:
            print("    [OK] HTTP 403 - Access Denied by SOAR Active Defense")
            return
    print("    [!] Not blocked yet. Check the /logsentinel/detector log and the CloudWatch Agent on EC2.")
    sys.exit(1)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="mode", required=True)
    pl = sub.add_parser("logs")
    pl.add_argument("--ip", default="198.51.100.23")
    ph = sub.add_parser("http")
    ph.add_argument("--target", required=True)
    ph.add_argument("--insecure", action="store_true", help="bo qua kiem tra chung chi tu ky")
    a = p.parse_args()
    run_logs(a.ip) if a.mode == "logs" else run_http(a.target, a.insecure)


if __name__ == "__main__":
    main()
