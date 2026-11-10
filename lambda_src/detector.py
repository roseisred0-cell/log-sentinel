"""
LogSentinel Anomaly Detector Lambda (SIEM + SOAR).

Kien truc theo "deep module": moi khoi duoi day co giao dien nho, che giau chi tiet ben trong.

    handler(event)                      <- cong vao duy nhat (CloudWatch Logs subscription)
      |-- evaluate_webapp_log(raw)      <- Rules: log ung dung
      |-- evaluate_cloudtrail_log(raw)  <- Rules: log CloudTrail
            |
            v
      record_incident(rule, sev, details, raw)   <- Incident sink: DynamoDB + metric + SNS + Telegram
      auto_block_attacker_ip(ip, reason)         <- SOAR: ghi BLOCKED_IP#<ip> (idempotent, TTL 24h)
      count_failed_login(ip)                     <- State: bo dem brute-force nguyen tu (60s)

Quy uoc: rule chi QUYET DINH, khong goi AWS truc tiep. Moi loi I/O deu bi chan tai sink,
nen mot dich vu hong (Telegram, SNS) khong bao gio lam mat ban ghi su co.
"""
import base64
import gzip
import ipaddress
import json
import os
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import boto3

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
secrets = boto3.client("secretsmanager")

TABLE_NAME = os.environ.get("INCIDENT_TABLE", "")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
SECRET_ARN = os.environ.get("SECRET_ARN", "")
table = dynamodb.Table(TABLE_NAME) if TABLE_NAME else None

APP_LOG_GROUP = "/logsentinel/sample-app"
TRAIL_LOG_GROUP = "/logsentinel/cloudtrail"

INCIDENT_TTL_S = 7 * 86400
BLOCK_TTL_S = 86400
BRUTE_FORCE_WINDOW_S = 60
BRUTE_FORCE_THRESHOLD = 5
MAX_FIELD_CHARS = 512
METRIC_NAMESPACE = "LogSentinel"


# ============================================================ helpers chung
def _now() -> int:
    return int(time.time())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_json(raw: str):
    """JSON -> dict hoac None. Dung Decimal cho so thuc vi DynamoDB khong nhan float."""
    try:
        data = json.loads(raw, parse_float=Decimal)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _compact(value, depth: int = 0):
    """Cat ngan du lieu do ke tan cong kiem soat truoc khi luu (chong phinh item 400KB)."""
    if depth > 4:
        return "<truncated>"
    if isinstance(value, str):
        return value[:MAX_FIELD_CHARS]
    if isinstance(value, dict):
        return {str(k)[:64]: _compact(v, depth + 1) for k, v in list(value.items())[:50]}
    if isinstance(value, list):
        return [_compact(v, depth + 1) for v in value[:50]]
    if isinstance(value, float):
        return Decimal(str(value))
    return value


def _is_conditional_failure(exc: Exception) -> bool:
    """Nhan dien ConditionalCheckFailedException ma khong can import botocore."""
    code = getattr(exc, "response", {}).get("Error", {}).get("Code")
    return code == "ConditionalCheckFailedException"


def _parse_allowlist(raw: str):
    nets = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            print(f"[WARN] Bo qua CIDR allowlist khong hop le: {part[:50]}")
    return nets


# IP quan tri / SOC khong bao gio bi SOAR tu khoa (chong tu khoa chinh minh).
BLOCK_ALLOWLIST = _parse_allowlist(os.environ.get("BLOCK_ALLOWLIST_CIDRS", ""))


def _blockable_ip(raw_ip):
    """Tra ve IP chuan hoa neu duoc phep khoa, nguoc lai None."""
    try:
        ip = ipaddress.ip_address(str(raw_ip).strip())
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
        return None
    if any(ip in net for net in BLOCK_ALLOWLIST):
        return None
    return str(ip)


# ================================================================ Telegram
# Cache cau hinh Telegram trong container Lambda: cau hinh hop le giu 5 phut,
# cau hinh chua dien/loi thi thu lai sau 60 giay.
_telegram_cache = {"cfg": None, "fetched_at": 0.0}
_telegram_failed_this_run = False
TELEGRAM_TIMEOUT_S = 5
TELEGRAM_MAX_CHARS = 3500
PLACEHOLDER = "REPLACE_ME"


def _get_telegram_config():
    """Tra ve (bot_token, chat_id) hoac None neu chua cau hinh."""
    now = time.time()
    ttl = 300 if _telegram_cache["cfg"] else 60
    if now - _telegram_cache["fetched_at"] < ttl:
        return _telegram_cache["cfg"]

    _telegram_cache["fetched_at"] = now
    _telegram_cache["cfg"] = None
    if not SECRET_ARN:
        return None
    try:
        raw = secrets.get_secret_value(SecretId=SECRET_ARN)["SecretString"]
        data = json.loads(raw)
        token = str(data.get("BOT_TOKEN", "")).strip()
        chat_id = str(data.get("CHAT_ID", "")).strip()
        if token and chat_id and PLACEHOLDER not in (token, chat_id):
            _telegram_cache["cfg"] = (token, chat_id)
    except Exception as exc:
        print(f"[WARN] Khong doc duoc secret Telegram: {type(exc).__name__}")
    return _telegram_cache["cfg"]


def send_telegram_alert(severity: str, rule: str, details: dict, inc_id: str, now_iso: str) -> None:
    """Gui canh bao Telegram. Ngat mach: loi 1 lan thi bo qua phan con lai cua batch."""
    global _telegram_failed_this_run
    if _telegram_failed_this_run:
        return
    cfg = _get_telegram_config()
    if not cfg:
        return
    token, chat_id = cfg
    text = _render_alert(severity, rule, details, inc_id, now_iso)[:TELEGRAM_MAX_CHARS]
    try:
        body = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TELEGRAM_TIMEOUT_S) as resp:
            resp.read()
    except Exception as exc:
        # URL chua token nen khong in noi dung loi, chi in loai loi.
        _telegram_failed_this_run = True
        print(f"[ERROR] Gui Telegram that bai: {type(exc).__name__}")


# =========================================================== Incident sink
def _render_alert(severity: str, rule: str, details: dict, inc_id: str, now_iso: str) -> str:
    """Mot dinh dang duy nhat cho moi kenh (SNS email, Telegram)."""
    return (
        f"[LogSentinel {severity}] {rule}\n"
        f"Thoi gian: {now_iso}\n"
        f"Chi tiet: {json.dumps(details, ensure_ascii=False, default=str)}\n"
        f"Ma su co: {inc_id}"
    )


def _emit_incident_metric(rule: str, severity: str) -> None:
    """CloudWatch Embedded Metric Format: metric mien phi IAM, hien tren dashboard."""
    print(json.dumps({
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": [["Severity"]],
                "Metrics": [{"Name": "IncidentsDetected", "Unit": "Count"}],
            }],
        },
        "Severity": severity,
        "Rule": rule,
        "IncidentsDetected": 1,
    }))


def record_incident(rule: str, severity: str, details: dict, raw_payload: str) -> str:
    """Ghi su co + canh bao. Khong bao gio nem loi ra ngoai. Tra ve incident_id."""
    inc_id = str(uuid.uuid4())
    now_iso = _now_iso()
    details = _compact(details)

    if table:
        try:
            table.put_item(Item={
                "incident_id": inc_id,
                "timestamp": now_iso,
                "rule": rule,
                "severity": severity,
                "details": details,
                "raw_payload": str(raw_payload)[:1000],
                "ttl": _now() + INCIDENT_TTL_S,
            })
        except Exception as exc:
            print(f"[ERROR] DynamoDB put_item failed: {type(exc).__name__}: {exc}")

    _emit_incident_metric(rule, severity)

    if SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"[LogSentinel {severity}] {rule}"[:100],
                Message=_render_alert(severity, rule, details, inc_id, now_iso),
            )
        except Exception as exc:
            print(f"[ERROR] SNS publish failed: {type(exc).__name__}")

    send_telegram_alert(severity, rule, details, inc_id, now_iso)
    return inc_id


# ===================================================================== SOAR
def auto_block_attacker_ip(ip_address, reason: str) -> bool:
    """Khoa IP 24h. Khoa co dinh BLOCKED_IP#<ip>/ACTIVE nen ghi lai chi gia han, khong phinh bang."""
    ip = _blockable_ip(ip_address)
    if not ip or not table:
        return False
    try:
        table.put_item(Item={
            "incident_id": f"BLOCKED_IP#{ip}",
            "timestamp": "ACTIVE",
            "blocked_at": _now_iso(),
            "rule": "ACTIVE_REMEDIATION_BLOCKED",
            "blocked_ip": ip,
            "reason": reason[:200],
            "status": "ENFORCED",
            # Web app tu kiem tra ttl > now, vi DynamoDB co the tre toi 48h moi xoa item het han.
            "ttl": _now() + BLOCK_TTL_S,
        })
        print(f"[SOAR] Da khoa IP {ip} | Ly do: {reason[:200]}")
        return True
    except Exception as exc:
        print(f"[ERROR] Khong the khoa IP {ip}: {type(exc).__name__}")
        return False


# ==================================================== State: brute-force
def count_failed_login(ip: str) -> int:
    """
    Dem so lan dang nhap sai cua 1 IP trong cua so 60 giay, nguyen tu tuyet doi.

    Buoc 1: ADD +1 neu cua so con hieu luc (window_start > now-60).
    Buoc 2: neu cua so het han / chua co -> mo cua so moi (dieu kien nguoc lai), count = 1.
    Buoc 3: neu buoc 2 thua cuoc dua (Lambda khac vua mo cua so) -> quay lai buoc 1.
    """
    key = {"incident_id": f"STATE#FAILED_LOGIN#{ip}", "timestamp": "WINDOW"}
    names = {"#ttl": "ttl"}

    def _increment():
        now = _now()
        res = table.update_item(
            Key=key,
            UpdateExpression="ADD failure_count :one SET #ttl = :ttl",
            ConditionExpression="window_start > :floor",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues={":one": 1, ":floor": now - BRUTE_FORCE_WINDOW_S,
                                       ":ttl": now + 2 * BRUTE_FORCE_WINDOW_S},
            ReturnValues="UPDATED_NEW",
        )
        return int(res["Attributes"]["failure_count"])

    try:
        return _increment()
    except Exception as exc:
        if not _is_conditional_failure(exc):
            raise

    now = _now()
    try:
        table.update_item(
            Key=key,
            UpdateExpression="SET failure_count = :one, window_start = :now, #ttl = :ttl",
            ConditionExpression="attribute_not_exists(window_start) OR window_start <= :floor",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues={":one": 1, ":now": now, ":floor": now - BRUTE_FORCE_WINDOW_S,
                                       ":ttl": now + 2 * BRUTE_FORCE_WINDOW_S},
        )
        return 1
    except Exception as exc:
        if not _is_conditional_failure(exc):
            raise
    return _increment()


# ============================================================ Rules: web app
def evaluate_webapp_log(raw_message: str) -> None:
    data = _parse_json(raw_message)
    if data is None:
        return

    event_type = data.get("event_type", "")
    client_ip = data.get("client_ip", "unknown")

    if event_type == "MFA_BYPASS_ATTEMPT":
        record_incident("MFA_BYPASS_ATTEMPT", "CRITICAL", data, raw_message)
        auto_block_attacker_ip(client_ip, "Dung mat khau nhung sai ma 2FA TOTP")

    elif event_type == "SQL_INJECTION":
        record_incident("SQL_INJECTION", "CRITICAL", data, raw_message)
        auto_block_attacker_ip(client_ip, "Phat hien payload SQL Injection / Path Traversal")

    elif event_type == "FAILED_LOGIN":
        ip = _blockable_ip(client_ip) or str(client_ip)[:64]
        if not table:
            return
        try:
            count = count_failed_login(ip)
        except Exception as exc:
            print(f"[ERROR] State tracking failed: {type(exc).__name__}")
            return
        # Bang dung 1 lan / cua so -> 1 canh bao, khong bao cao canh bao (alert fatigue).
        if count == BRUTE_FORCE_THRESHOLD:
            data["attempt_count"] = count
            data["window_seconds"] = BRUTE_FORCE_WINDOW_S
            record_incident("BRUTE_FORCE_DETECTED", "HIGH", data, raw_message)
            auto_block_attacker_ip(client_ip, f"Brute-force: {count} lan sai / {BRUTE_FORCE_WINDOW_S}s")


# ========================================================= Rules: CloudTrail
# Cac hanh dong IAM co the dung de leo thang dac quyen hoac giu quyen truy cap.
IAM_PRIVILEGE_EVENTS = ("CreateAccessKey", "AttachUserPolicy", "PutUserPolicy")
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def evaluate_cloudtrail_log(raw_message: str) -> None:
    data = _parse_json(raw_message)
    if data is None:
        return

    event_name = data.get("eventName", "")
    user_identity = data.get("userIdentity") or {}
    add_data = data.get("additionalEventData") or {}
    ip = data.get("sourceIPAddress", "unknown")
    who = user_identity.get("userName") or user_identity.get("arn") or user_identity.get("type")

    # Ghi chu: KHONG auto-block IP o tang CloudTrail vi sourceIPAddress co the la
    # endpoint dich vu AWS (vd "cloudformation.amazonaws.com") -> chi canh bao cho SOC.
    if event_name == "ConsoleLogin" and add_data.get("MFAUsed") == "No":
        record_incident("CONSOLE_LOGIN_NO_MFA", "HIGH", {"user": who, "ip": ip}, raw_message)
    elif event_name in ("DeactivateMFADevice", "DeleteVirtualMFADevice"):
        record_incident("MFA_TAMPERING", "CRITICAL", {"action": event_name, "user": who, "ip": ip}, raw_message)
    elif event_name in ("StopLogging", "DeleteTrail"):
        record_incident("CLOUDTRAIL_TAMPERING", "CRITICAL", {"action": event_name, "user": who, "ip": ip}, raw_message)
    elif event_name in IAM_PRIVILEGE_EVENTS:
        evaluate_iam_privilege_event(data, event_name, user_identity, ip, raw_message)


def evaluate_iam_privilege_event(data: dict, event_name: str, user_identity: dict, ip: str, raw_message: str) -> None:
    """3 luat CloudTrail IAM: CreateAccessKey, AttachUserPolicy, PutUserPolicy."""
    params = data.get("requestParameters") or {}  # CloudTrail dat null khi khong co tham so
    actor = user_identity.get("userName") or user_identity.get("arn") or user_identity.get("type")
    details = {
        "action": event_name,
        "actor": actor,
        "target_user": params.get("userName"),
        "ip": ip,
    }
    if data.get("errorCode"):
        details["error_code"] = data.get("errorCode")  # van ghi nhan ca lan thu bi tu choi

    if event_name == "CreateAccessKey":
        record_incident("IAM_ACCESS_KEY_CREATED", "HIGH", details, raw_message)
    elif event_name == "AttachUserPolicy":
        policy_arn = params.get("policyArn")
        details["policy_arn"] = policy_arn
        severity = "CRITICAL" if policy_arn == ADMIN_POLICY_ARN else "HIGH"
        record_incident("IAM_POLICY_ATTACHED", severity, details, raw_message)
    elif event_name == "PutUserPolicy":
        details["policy_name"] = params.get("policyName")
        record_incident("IAM_INLINE_POLICY_PUT", "HIGH", details, raw_message)


# ================================================================== handler
_ROUTES = ((APP_LOG_GROUP, evaluate_webapp_log), (TRAIL_LOG_GROUP, evaluate_cloudtrail_log))


def _decode_envelope(event: dict) -> dict:
    compressed = base64.b64decode(event["awslogs"]["data"])
    return json.loads(gzip.decompress(compressed).decode("utf-8"))


def handler(event, context):
    """
    - Envelope hong (khong giai ma duoc)  -> NEM LOI de metric AWS/Lambda Errors tang,
      DetectorErrorsAlarm moi thuc su bao duoc "detector dang mu".
    - Mot dong log hong trong batch        -> bo qua dong do, xu ly tiep phan con lai.
    """
    global _telegram_failed_this_run
    _telegram_failed_this_run = False

    payload = _decode_envelope(event)
    log_group = payload.get("logGroup", "")
    evaluate = next((fn for prefix, fn in _ROUTES if log_group.startswith(prefix)), None)
    if evaluate is None:
        print(f"[WARN] Log group khong duoc dinh tuyen: {log_group[:100]}")
        return {"statusCode": 200, "body": "IGNORED"}

    bad_events = 0
    for log_event in payload.get("logEvents", []):
        try:
            evaluate(log_event.get("message", ""))
        except Exception as exc:
            bad_events += 1
            print(f"[ERROR] Bo qua 1 log event loi: {type(exc).__name__}")

    return {"statusCode": 200, "body": f"OK ({bad_events} bad events)"}
