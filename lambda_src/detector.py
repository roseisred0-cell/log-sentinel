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
      ######################################################################################
Quy uoc: rule chi QUYET DINH, khong goi AWS truc tiep. Moi loi I/O deu bi chan tai sink,
nen mot dich vu hong (Telegram, SNS) khong bao gio lam mat ban ghi su co.
"""
import base64
import gzip
import html
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

INCIDENT_TTL_S = 30 * 86400  # bang thoi gian luu log (LOG_RETENTION_DAYS) de su co va log goc het han cung luc
BLOCK_TTL_S = 86400
BRUTE_FORCE_WINDOW_S = 60
BRUTE_FORCE_THRESHOLD = 5
# Brute-force cham tu 1 IP (moi lan doan cach nhau du lau de ne cua so 60s o tren).
SLOW_BRUTE_FORCE_WINDOW_S = 3600
SLOW_BRUTE_FORCE_THRESHOLD = 20
# Brute-force phan tan vao 1 tai khoan (nhieu IP, moi IP duoi nguong tren).
ACCOUNT_ATTACK_WINDOW_S = 300
ACCOUNT_ATTACK_THRESHOLD = 10
# Spike: tong dang nhap sai cua TOAN he thong (nhieu IP x nhieu tai khoan, moi cap chi thu 1 lan).
LOGIN_SPIKE_WINDOW_S = 300
LOGIN_SPIKE_THRESHOLD = 50
# Do quet duong dan: so lan 404 cua 1 IP. Phai bang LOCAL_SCAN_THRESHOLD trong sample_app/app.py.
SCAN_WINDOW_S = 60
SCAN_THRESHOLD = 30
# Doan mat khau AWS Console tu 1 IP.
CONSOLE_FAIL_WINDOW_S = 300
CONSOLE_FAIL_THRESHOLD = 5
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


_SEVERITY_ICON = {"CRITICAL": chr(0x1F534), "HIGH": chr(0x1F7E0)}   # cham do / cham cam
TELEGRAM_VALUE_CHARS = 300
TELEGRAM_MAX_FIELDS = 8
# Truong quen thuoc dua len dau voi nhan de doc; phan con lai liet ke theo ten truong.
_TELEGRAM_LABELS = (("client_ip", "IP"), ("ip", "IP"), ("username", "Tai khoan"), ("user", "Tai khoan"),
                    ("actor", "Nguoi thuc hien"), ("action", "Hanh dong"))
_TELEGRAM_SKIP = {"timestamp", "source", "event_type", "severity"} | {k for k, _ in _TELEGRAM_LABELS}


def _tg(value, limit: int = TELEGRAM_VALUE_CHARS) -> str:
    """
    Gia tri -> van ban an toan cho parse_mode HTML cua Telegram. Du lieu do ke tan cong nhap (payload, username)
    khong the chen the HTML hay lam hong tin nhan. Cat TRUOC khi escape de khong cat ngang mot thuc the (&amp;).
    """
    raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    escaped = html.escape(raw[:limit], quote=False)
    if len(escaped) > limit:   # toan ky tu phai escape: moi ky tu no ra toi da 5 lan
        escaped = html.escape(raw[:limit // 5], quote=False)
    return escaped


def _telegram_time(now_iso: str) -> str:
    try:
        return datetime.fromisoformat(now_iso).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError):
        return _tg(now_iso, 40)


def _render_telegram(severity: str, rule: str, details: dict, inc_id: str, now_iso: str) -> str:
    """Tin nhan cho man hinh dien thoai: moi dong mot y, gia tri ky thuat nam trong <code> de cham la sao chep."""
    details = details if isinstance(details, dict) else {}
    lines = [f"{_SEVERITY_ICON.get(severity, chr(0x26A0))} <b>{_tg(severity, 20)}</b> | <b>{_tg(rule, 60)}</b>",
             f"Thoi gian: {_telegram_time(now_iso)}"]
    seen = set()
    for key, label in _TELEGRAM_LABELS:
        if details.get(key) not in (None, "") and label not in seen:
            seen.add(label)
            lines.append(f"{label}: <code>{_tg(details[key])}</code>")
    extra = [k for k in details if k not in _TELEGRAM_SKIP and details[k] not in (None, "")]
    for key in extra[:TELEGRAM_MAX_FIELDS]:
        lines.append(f"{_tg(str(key), 40)}: <code>{_tg(details[key])}</code>")
    if len(extra) > TELEGRAM_MAX_FIELDS:
        lines.append(f"(+{len(extra) - TELEGRAM_MAX_FIELDS} truong khac, xem SOC Console)")
    lines.append(f"Ma su co: <code>{_tg(inc_id, 60)}</code>")
    return "\n".join(lines)


def send_telegram_alert(severity: str, rule: str, details: dict, inc_id: str, now_iso: str) -> None:
    """Gui canh bao Telegram. Ngat mach: loi 1 lan thi bo qua phan con lai cua batch."""
    global _telegram_failed_this_run
    if _telegram_failed_this_run:
        return
    cfg = _get_telegram_config()
    if not cfg:
        return
    token, chat_id = cfg
    message = {"chat_id": chat_id, "text": _render_telegram(severity, rule, details, inc_id, now_iso),
               "parse_mode": "HTML", "disable_web_page_preview": True}
    if len(message["text"]) > TELEGRAM_MAX_CHARS:
        # Khong cat ngang chuoi HTML (the dang do se bi Telegram tu choi -> mat canh bao): gui ban van ban thuong.
        message = {"chat_id": chat_id,
                   "text": _render_alert(severity, rule, details, inc_id, now_iso)[:TELEGRAM_MAX_CHARS]}
    try:
        body = json.dumps(message).encode("utf-8")
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
    """Van ban thuong: noi dung email SNS, va ban du phong cho Telegram khi tin HTML qua dai (_render_telegram)."""
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
                "record_type": "INCIDENT",  # khoa GSI by_type: SOC Console liet ke ma khong can Scan
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
            "record_type": "BLOCK",
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
    """Dem so lan dang nhap sai cua 1 IP trong cua so 60 giay."""
    return count_in_window(f"STATE#FAILED_LOGIN#{ip}", BRUTE_FORCE_WINDOW_S)


def count_in_window(state_id: str, window_s: int) -> int:
    """
    Bo dem su kien theo cua so thoi gian, nguyen tu tuyet doi (nhieu Lambda chay song song van dung).

    Buoc 1: ADD +1 neu cua so con hieu luc (window_start > now-window).
    Buoc 2: neu cua so het han / chua co -> mo cua so moi (dieu kien nguoc lai), count = 1.
    Buoc 3: neu buoc 2 thua cuoc dua (Lambda khac vua mo cua so) -> quay lai buoc 1.
    """
    key = {"incident_id": state_id, "timestamp": "WINDOW"}
    names = {"#ttl": "ttl"}

    def _increment():
        now = _now()
        res = table.update_item(
            Key=key,
            UpdateExpression="ADD failure_count :one SET #ttl = :ttl",
            ConditionExpression="window_start > :floor",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues={":one": 1, ":floor": now - window_s,
                                       ":ttl": now + 2 * window_s},
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
            ExpressionAttributeValues={":one": 1, ":now": now, ":floor": now - window_s,
                                       ":ttl": now + 2 * window_s},
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

    elif event_type == "NOT_FOUND":
        # Do quet: 1 IP goi nhieu duong dan khong ton tai (/.env, /wp-admin, /phpmyadmin...) trong thoi gian ngan.
        if not table:
            return
        ip = _blockable_ip(client_ip) or str(client_ip)[:64]
        try:
            count = count_in_window(f"STATE#NOT_FOUND#{ip}", SCAN_WINDOW_S)
        except Exception as exc:
            print(f"[ERROR] Scan state tracking failed: {type(exc).__name__}")
            return
        if count == SCAN_THRESHOLD:
            record_incident("SCAN_DETECTED", "HIGH",
                            {**data, "attempt_count": count, "window_seconds": SCAN_WINDOW_S}, raw_message)
            auto_block_attacker_ip(client_ip, f"Do quet: {count} duong dan khong ton tai / {SCAN_WINDOW_S}s")

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
            record_incident("BRUTE_FORCE_DETECTED", "HIGH",
                            {**data, "attempt_count": count, "window_seconds": BRUTE_FORCE_WINDOW_S}, raw_message)
            auto_block_attacker_ip(client_ip, f"Brute-force: {count} lan sai / {BRUTE_FORCE_WINDOW_S}s")
        # IP da cham nguong thi da co canh bao rieng o tren: khong tinh tiep vao 2 bo dem THEO IP / TAI KHOAN,
        # de 1 IP don le khong sinh 2 canh bao cho cung 1 cuoc tan cong.
        if count < BRUTE_FORCE_THRESHOLD:
            _track_slow_brute_force(data, ip, client_ip, raw_message)
            _track_account_under_attack(data, raw_message)
        # Spike la TONG cua ca he thong: dem moi lan sai, ke ca tu IP da bi khoa (spec: "bat ke IP hay tai khoan").
        _track_login_failure_spike(data, raw_message)


def _track_login_failure_spike(data: dict, raw_message: str) -> None:
    """
    SPIKE toan he thong: tong so dang nhap sai tang dot bien, bat ke IP hay tai khoan nao. Bat kieu
    "credential stuffing" - moi IP va moi tai khoan chi thu 1 lan nen ca hai bo dem kia deu khong thay.
    Chi canh bao: khong co IP don le nao dang trach.
    """
    try:
        count = count_in_window("STATE#FAILED_LOGIN_GLOBAL", LOGIN_SPIKE_WINDOW_S)
    except Exception as exc:
        print(f"[ERROR] Spike state tracking failed: {type(exc).__name__}")
        return
    if count == LOGIN_SPIKE_THRESHOLD + 1:   # "vuot 50" = lan thu 51; bang dung 1 lan / cua so -> 1 canh bao
        record_incident("LOGIN_FAILURE_SPIKE", "HIGH", {
            "attempt_count": count, "window_seconds": LOGIN_SPIKE_WINDOW_S,
            "last_ip": data.get("client_ip"), "last_username": data.get("username"),
        }, raw_message)


def _track_slow_brute_force(data: dict, ip: str, client_ip, raw_message: str) -> None:
    """Brute-force CHAM: 1 lan doan moi phut khong bao gio cham nguong 5 lan/60s -> dem them cua so 1 gio."""
    try:
        count = count_in_window(f"STATE#FAILED_LOGIN_SLOW#{ip}", SLOW_BRUTE_FORCE_WINDOW_S)
    except Exception as exc:
        print(f"[ERROR] Slow state tracking failed: {type(exc).__name__}")
        return
    if count == SLOW_BRUTE_FORCE_THRESHOLD:
        record_incident("SLOW_BRUTE_FORCE", "HIGH",
                        {**data, "attempt_count": count, "window_seconds": SLOW_BRUTE_FORCE_WINDOW_S}, raw_message)
        auto_block_attacker_ip(client_ip, f"Brute-force cham: {count} lan sai / {SLOW_BRUTE_FORCE_WINDOW_S}s")


def _track_account_under_attack(data: dict, raw_message: str) -> None:
    """
    Brute-force PHAN TAN: nhieu IP, moi IP sai duoi nguong, cung nham 1 tai khoan. Bo dem theo IP khong
    thay duoc -> dem them theo ten tai khoan. Chi canh bao (khong khoa IP: khoa ai khi co ca tram IP?).
    """
    username = str(data.get("username") or "").strip().lower()[:64]
    if not username or username == "unknown":
        return
    try:
        count = count_in_window(f"STATE#FAILED_LOGIN_USER#{username}", ACCOUNT_ATTACK_WINDOW_S)
    except Exception as exc:
        print(f"[ERROR] Account state tracking failed: {type(exc).__name__}")
        return
    if count == ACCOUNT_ATTACK_THRESHOLD:
        record_incident("ACCOUNT_UNDER_ATTACK", "HIGH", {
            "username": username, "attempt_count": count, "window_seconds": ACCOUNT_ATTACK_WINDOW_S,
            "last_ip": data.get("client_ip"),
        }, raw_message)


# ========================================================= Rules: CloudTrail
# Cac hanh dong IAM co the dung de leo thang dac quyen hoac giu quyen truy cap -> ten luat.
# Bao phu ca user, role va group: ke tan cong chon duong nao it bi theo doi nhat.
# PHAI khop voi danh sach tu khoa cua CloudTrailSubscription trong log_sentinel_stack.py
# (su kien khong co trong filter se khong bao gio toi Lambda).
IAM_PRIVILEGE_EVENTS = {
    "CreateAccessKey": "IAM_ACCESS_KEY_CREATED",
    "AttachUserPolicy": "IAM_POLICY_ATTACHED",
    "AttachRolePolicy": "IAM_POLICY_ATTACHED",
    "AttachGroupPolicy": "IAM_POLICY_ATTACHED",
    "PutUserPolicy": "IAM_INLINE_POLICY_PUT",
    "PutRolePolicy": "IAM_INLINE_POLICY_PUT",
    "PutGroupPolicy": "IAM_INLINE_POLICY_PUT",
    "CreatePolicyVersion": "IAM_POLICY_VERSION_CREATED",   # sua noi dung policy dang duoc gan san
    "UpdateAssumeRolePolicy": "IAM_TRUST_POLICY_CHANGED",  # cho phep ben ngoai assume role
    "CreateLoginProfile": "IAM_LOGIN_PROFILE_CHANGED",     # dat mat khau Console cho user khac
    "UpdateLoginProfile": "IAM_LOGIN_PROFILE_CHANGED",
    "AddUserToGroup": "IAM_USER_ADDED_TO_GROUP",
}
# Vo hieu hoa khoa KMS = lam mu toan bo he thong (CloudTrail va IncidentTable deu ma hoa bang CMK).
KMS_TAMPER_EVENTS = ("ScheduleKeyDeletion", "DisableKey")
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
    login_failed = (data.get("responseElements") or {}).get("ConsoleLogin") == "Failure"
    if event_name == "ConsoleLogin" and user_identity.get("type") == "Root":
        # Tai khoan root khong nen dung hang ngay (CIS AWS 1.7): moi lan dang nhap (ke ca that bai) deu la su co.
        record_incident("ROOT_ACCOUNT_LOGIN", "CRITICAL",
                        {"user": "root", "ip": ip, "mfa_used": add_data.get("MFAUsed"),
                         "outcome": "Failure" if login_failed else "Success"}, raw_message)
    elif event_name == "ConsoleLogin" and login_failed:
        # CloudTrail ghi MFAUsed="No" cho MOI lan dang nhap that bai: neu khong tach rieng thi doan sai mat khau
        # bi bao nham la "dang nhap khong MFA". Lan sai le te la binh thuong; nhieu lan tu 1 IP la do mat khau.
        _track_console_brute_force(who, ip, raw_message)
    elif event_name == "ConsoleLogin" and add_data.get("MFAUsed") == "No":
        record_incident("CONSOLE_LOGIN_NO_MFA", "HIGH", {"user": who, "ip": ip}, raw_message)
    elif event_name in ("DeactivateMFADevice", "DeleteVirtualMFADevice"):
        record_incident("MFA_TAMPERING", "CRITICAL", {"action": event_name, "user": who, "ip": ip}, raw_message)
    elif event_name in ("StopLogging", "DeleteTrail"):
        record_incident("CLOUDTRAIL_TAMPERING", "CRITICAL", {"action": event_name, "user": who, "ip": ip}, raw_message)
    elif event_name in KMS_TAMPER_EVENTS:
        params = data.get("requestParameters") or {}
        record_incident("KMS_KEY_TAMPERING", "CRITICAL",
                        {"action": event_name, "user": who, "ip": ip, "key_id": params.get("keyId")}, raw_message)
    elif event_name in IAM_PRIVILEGE_EVENTS:
        evaluate_iam_privilege_event(data, event_name, user_identity, ip, raw_message)


def _track_console_brute_force(who, ip, raw_message: str) -> None:
    """Chi canh bao, khong khoa: muc tieu la AWS Console, khoa IP o web app cua ta khong ngan duoc gi."""
    if not table:
        return
    try:
        count = count_in_window(f"STATE#CONSOLE_LOGIN_FAILED#{str(ip)[:64]}", CONSOLE_FAIL_WINDOW_S)
    except Exception as exc:
        print(f"[ERROR] Console state tracking failed: {type(exc).__name__}")
        return
    if count == CONSOLE_FAIL_THRESHOLD:
        record_incident("CONSOLE_BRUTE_FORCE", "HIGH", {
            "user": who, "ip": ip, "attempt_count": count, "window_seconds": CONSOLE_FAIL_WINDOW_S,
        }, raw_message)


def evaluate_iam_privilege_event(data: dict, event_name: str, user_identity: dict, ip: str, raw_message: str) -> None:
    """Luat leo thang dac quyen IAM (xem IAM_PRIVILEGE_EVENTS). Lan thu bi tu choi cung duoc ghi nhan."""
    params = data.get("requestParameters") or {}  # CloudTrail dat null khi khong co tham so
    actor = user_identity.get("userName") or user_identity.get("arn") or user_identity.get("type")
    details = {
        "action": event_name,
        "actor": actor,
        "target_user": params.get("userName"),
        "ip": ip,
    }
    for field, param in (("target_role", "roleName"), ("target_group", "groupName"),
                         ("policy_arn", "policyArn"), ("policy_name", "policyName")):
        if param in params:
            details[field] = params[param]
    if data.get("errorCode"):
        details["error_code"] = data.get("errorCode")  # van ghi nhan ca lan thu bi tu choi
    # CloudFormation (vd `cdk deploy`) cung tao/sua role: van bao, nhung danh dau de SOC phan biet nhanh.
    # Khong bo qua, vi CloudFormation chinh la mot duong leo thang quyen quen thuoc.
    if user_identity.get("invokedBy"):
        details["via_service"] = user_identity.get("invokedBy")

    severity = "CRITICAL" if params.get("policyArn") == ADMIN_POLICY_ARN else "HIGH"
    record_incident(IAM_PRIVILEGE_EVENTS[event_name], severity, details, raw_message)


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
