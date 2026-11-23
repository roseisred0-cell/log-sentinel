"""
LogSentinel target web app (Flask, chay sau Nginx TLS -> Gunicorn 127.0.0.1:8080).

Deep modules (giao dien nho, chi tiet an ben trong):
    AppConfig / load_config_from_env()  - cau hinh, KHONG co gia tri mac dinh nhay cam
    resolve_client_ip(...)              - chong gia mao IP (chi tin header khi den tu Nginx noi bo)
    BlockList.is_blocked / block_locally - cache TTL tren RAM truoc DynamoDB (chong Denial of Wallet)
    is_malicious_query(...)             - nhan dien SQLi / path traversal
    DynamoIncidentStore                 - doc su co / IP bi khoa, go khoa (cho SOC Console)
    create_app(config, blocklist, store) - lap rap Flask app; test truyen dependency gia vao day

Giao dien khach hang: https://<host>/console  (phien 30 phut). Hai cach dang nhap:
    - Tai khoan "admin" noi bo: mat khau + OTP trong webapp.env (du phong, 2FA bat buoc)
    - Tai khoan Cognito: tu dang ky, xac nhan email, cho admin duyet; tu bat/tat 2FA TOTP trong giao dien
    Vai tro: admin (go khoa IP, muc Phan quyen; bat buoc 2FA) | viewer (chi xem) | pending (chua duoc duyet)
    Module: cognito_identity.py (Cognito), password_strength.py (muc do manh mat khau),
            admin_governance.py (muc Phan quyen: PIN rieng, bo phieu nang/ha/vo hieu hoa, che do khoi tao),
            governance_lambda.py (Lambda thuc thi phan quyen + LambdaExecutor de EC2 goi Lambda),
            caller_auth.py (Lambda xac minh nguoi goi bang token Cognito),
            chat_assistant.py (tro ly AI: huong dan + phan tich su co, goi OpenAI tu may chu)

Gunicorn (xem deploy/webapp.service): gthread, 2 worker x 16 luong, bind 127.0.0.1:8080
"""
import base64
import binascii
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from functools import wraps
from typing import Callable, Mapping, Optional
from urllib.parse import unquote

import pyotp
from flask import Flask, g, jsonify, render_template, render_template_string, request, session
from markupsafe import Markup

import admin_governance as governance_mod
import chat_assistant
import cognito_identity as cognito
import governance_lambda
import incident_stats
import password_strength


# ================================================================== config
@dataclass(frozen=True)
class AppConfig:
    admin_user: str
    admin_password: str
    totp_secret: str
    setup_token: str
    incident_table: str
    region: str
    trust_proxy: bool
    session_secret: str
    log_path: str = "/var/log/webapp/access.log"
    # Rong = tat dang ky/dang nhap Cognito (console chi con tai khoan admin noi bo).
    cognito_user_pool_id: str = ""
    cognito_client_id: str = ""
    # Lambda thuc thi phan quyen (EC2 khong co quyen ghi Cognito). Rong = chay ngay trong app (test / may dev).
    governance_function: str = ""
    # Tro ly AI (OpenAI). Rong = tat. Key nam trong Secrets Manager, khong bao gio xuong trinh duyet.
    chat_model: str = ""
    chat_secret_id: str = ""
    chat_daily_limit: int = 30


_REQUIRED_ENV = ("APP_ADMIN_PASSWORD", "APP_TOTP_SECRET", "APP_SETUP_TOKEN", "APP_SESSION_SECRET",
                 "INCIDENT_TABLE")


def load_config_from_env(env: Mapping[str, str] = os.environ) -> AppConfig:
    """Thieu bien bat buoc -> RuntimeError ngay khi khoi dong (fail fast, khong co mat khau mac dinh)."""
    missing = [k for k in _REQUIRED_ENV if not env.get(k)]
    if missing:
        raise RuntimeError(f"Thieu bien moi truong bat buoc: {', '.join(missing)}")
    totp_secret = env["APP_TOTP_SECRET"].strip().upper()
    try:
        base64.b32decode(totp_secret + "=" * (-len(totp_secret) % 8))
    except (binascii.Error, ValueError):
        raise RuntimeError("APP_TOTP_SECRET phai la chuoi base32 (RFC 4648)") from None
    if len(env["APP_SETUP_TOKEN"]) < 24:
        raise RuntimeError("APP_SETUP_TOKEN qua ngan (>= 24 ky tu)")
    if len(env["APP_SESSION_SECRET"]) < 32:
        raise RuntimeError("APP_SESSION_SECRET qua ngan (>= 32 ky tu)")
    return AppConfig(
        admin_user=env.get("APP_ADMIN_USER", "admin"),
        admin_password=env["APP_ADMIN_PASSWORD"],
        totp_secret=totp_secret,
        setup_token=env["APP_SETUP_TOKEN"],
        incident_table=env["INCIDENT_TABLE"],
        region=env.get("AWS_DEFAULT_REGION", "ap-southeast-1"),
        trust_proxy=env.get("TRUST_PROXY", "false").lower() == "true",
        session_secret=env["APP_SESSION_SECRET"],
        log_path=env.get("APP_LOG_PATH", "/var/log/webapp/access.log"),
        cognito_user_pool_id=env.get("COGNITO_USER_POOL_ID", "").strip(),
        cognito_client_id=env.get("COGNITO_CLIENT_ID", "").strip(),
        governance_function=env.get("GOVERNANCE_FUNCTION", "").strip(),
        chat_model=env.get("CHAT_MODEL", "").strip(),
        chat_secret_id=env.get("CHAT_SECRET_ID", "").strip(),
        chat_daily_limit=int(env.get("CHAT_DAILY_LIMIT", "30") or 30),
    )


# ============================================================ client IP
_LOCAL_PROXIES = ("127.0.0.1", "::1")


def _valid_ip(value) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def resolve_client_ip(remote_addr: Optional[str], headers: Mapping[str, str], trust_proxy: bool) -> str:
    """
    Chi tin X-Real-IP / X-Forwarded-For khi: TRUST_PROXY=true VA ket noi vat ly den tu Nginx noi bo.
    Nginx ghi de ca hai header bang $remote_addr nen client khong the chen IP gia.
    """
    peer = _valid_ip(remote_addr) or "0.0.0.0"
    if not (trust_proxy and peer in _LOCAL_PROXIES):
        return peer
    forwarded = headers.get("X-Real-IP") or (headers.get("X-Forwarded-For") or "").split(",")[0]
    return _valid_ip(forwarded) or peer


# =============================================================== blocklist
Lookup = Callable[[str], Optional[int]]  # ip -> epoch het han khoa, hoac None


class BlockList:
    """
    Cache TTL tren RAM truoc DynamoDB.
      - IP bi khoa: tu choi 403 tu cache, chi xac minh lai DynamoDB moi `positive_ttl` giay
        (de SOC go khoa bang tay co hieu luc trong <= 60s, khong phai restart app).
      - IP sach   : nho ket qua `negative_ttl` giay -> 1 IP spam 1000 req/s chi ton ~1 GetItem / 5s.
      - DynamoDB loi: fail-open (khong khoa nham nguoi dung) nhung van cache de khong don dap API.
    Moi Gunicorn worker co 1 instance rieng; nguon su that duy nhat van la DynamoDB.
    """

    def __init__(self, lookup: Lookup, clock: Callable[[], float] = time.time,
                 negative_ttl: float = 5.0, positive_ttl: float = 60.0, max_entries: int = 10_000):
        self._lookup = lookup
        self._clock = clock
        self._negative_ttl = negative_ttl
        self._positive_ttl = positive_ttl
        self._max_entries = max_entries
        self._cache = {}  # ip -> (blocked: bool, valid_until: float)
        self._lock = threading.Lock()

    def is_blocked(self, ip: str) -> bool:
        if ip in _LOCAL_PROXIES:
            return False
        now = self._clock()
        with self._lock:
            hit = self._cache.get(ip)
        if hit and hit[1] > now:
            return hit[0]
        try:
            expires_at = self._lookup(ip)
        except Exception as exc:
            print(f"[WARN] Blocklist lookup loi ({type(exc).__name__}) -> fail-open", flush=True)
            expires_at = None
        blocked = bool(expires_at and expires_at > now)
        if blocked:
            self._store(ip, True, min(expires_at, now + self._positive_ttl))
        else:
            self._store(ip, False, now + self._negative_ttl)
        return blocked

    def block_locally(self, ip: str) -> None:
        """
        Khoa tam thoi ngay trong worker hien tai (0ms), truoc khi Lambda kip ghi DynamoDB.
        Het `positive_ttl` thi hoi lai DynamoDB: neu Detector da khoa -> tiep tuc 403 den het 24h;
        neu IP nam trong allowlist (Detector khong khoa) -> tu mo, admin khong bi ket 24h vi go nham.
        """
        if ip not in _LOCAL_PROXIES:
            self._store(ip, True, self._clock() + self._positive_ttl)

    def forget(self, ip: str) -> None:
        """Xoa cache cua 1 IP (sau khi SOC go khoa) de worker nay hoi lai DynamoDB ngay."""
        with self._lock:
            self._cache.pop(ip, None)

    def _store(self, ip: str, blocked: bool, valid_until: float) -> None:
        with self._lock:
            if len(self._cache) >= self._max_entries:
                # Chong can RAM khi ke tan cong xoay vong IP: bo cac muc het han, roi bo muc cu nhat.
                now = self._clock()
                for k in [k for k, v in self._cache.items() if v[1] <= now]:
                    del self._cache[k]
                while len(self._cache) >= self._max_entries:
                    del self._cache[next(iter(self._cache))]
            self._cache[ip] = (blocked, valid_until)


def _table_per_thread(table_name: str, region: str) -> Callable[[], object]:
    """
    Gunicorn chay worker da luong (gthread). boto3 *resource* khong an toan khi dung chung giua cac luong
    (khac voi *client*), nen moi luong giu mot Table rieng, tao lan dau khi can.
    """
    import boto3  # import tre: test khong can boto3

    local = threading.local()

    def get():
        if not hasattr(local, "table"):
            local.table = boto3.resource("dynamodb", region_name=region).Table(table_name)
        return local.table

    return get


def dynamodb_lookup(table_name: str, region: str) -> Lookup:
    table = _table_per_thread(table_name, region)

    def lookup(ip: str) -> Optional[int]:
        item = table().get_item(Key={"incident_id": f"BLOCKED_IP#{ip}", "timestamp": "ACTIVE"}).get("Item")
        # Tu kiem tra ttl: DynamoDB co the tre toi 48h moi xoa item het han.
        return int(item["ttl"]) if item and "ttl" in item else None

    return lookup


# ========================================================= incident store
class DynamoIncidentStore:
    """
    Cua so doc du lieu cho SOC Console. Query tren GSI `by_type` (record_type, timestamp):
    khong Scan, khong dung duoc vao bo dem STATE#. Quyen IAM cua EC2 chi cho xoa BLOCKED_IP#*.
    """
    INDEX = "by_type"

    def __init__(self, table_name: str, region: str):
        from boto3.dynamodb.conditions import Key  # import tre: test khong can boto3

        self._table_for_thread = _table_per_thread(table_name, region)
        self._key = Key

    @property
    def _table(self):
        return self._table_for_thread()

    def _by_type(self, record_type: str, limit: int) -> list:
        res = self._table.query(
            IndexName=self.INDEX,
            KeyConditionExpression=self._key("record_type").eq(record_type),
            ScanIndexForward=False,
            Limit=limit,
        )
        return res.get("Items", [])

    def incidents_since(self, since_iso: str, limit: int) -> list:
        """Su co co timestamp >= since_iso, moi nhat truoc, toi da `limit` (doc nhieu trang neu can)."""
        items, kwargs = [], dict(
            IndexName=self.INDEX, ScanIndexForward=False,
            KeyConditionExpression=self._key("record_type").eq("INCIDENT") & self._key("timestamp").gte(since_iso))
        while len(items) < limit:
            res = self._table.query(Limit=limit - len(items), **kwargs)
            items.extend(res.get("Items", []))
            if "LastEvaluatedKey" not in res:
                break
            kwargs["ExclusiveStartKey"] = res["LastEvaluatedKey"]
        return items[:limit]

    def recent_incidents(self, limit: int = 50) -> list:
        return self._by_type("INCIDENT", limit)

    def active_blocks(self, now: float) -> list:
        return [i for i in self._by_type("BLOCK", 200) if int(i.get("ttl", 0)) > now]

    def unblock(self, ip: str) -> None:
        self._table.delete_item(Key={"incident_id": f"BLOCKED_IP#{ip}", "timestamp": "ACTIVE"})

    # Phien da dang xuat. IAM cua EC2 chi cho PutItem voi khoa REVOKED_SESSION#*.
    def revoke_session(self, sid: str, expires_at: int) -> None:
        self._table.put_item(Item={"incident_id": f"REVOKED_SESSION#{sid}", "timestamp": "REVOKED",
                                   "ttl": int(expires_at)})

    # Huy moi phien cua mot nguoi (doi vai tro / vo hieu hoa): cung tien to REVOKED_SESSION# nen dung chung quyen IAM.
    # sid la token_urlsafe (khong co ':') nen khoa "user:..." khong trung voi phien nao.
    def revoke_user(self, principal: str, at: float, expires_at: int) -> None:
        self._table.put_item(Item={"incident_id": f"REVOKED_SESSION#user:{principal}", "timestamp": "REVOKED",
                                   "revoked_at": Decimal(str(at)), "ttl": int(expires_at)})

    def user_revoked_at(self, principal: str) -> float:
        item = self._table.get_item(Key={"incident_id": f"REVOKED_SESSION#user:{principal}",
                                         "timestamp": "REVOKED"}).get("Item")
        return float(item["revoked_at"]) if item else 0.0

    def session_revoked(self, sid: str) -> bool:
        return "Item" in self._table.get_item(Key={"incident_id": f"REVOKED_SESSION#{sid}", "timestamp": "REVOKED"})


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)  # fromtimestamp() loi voi so am tren Windows


def _read_secret(secret_id: str, region: str) -> str:
    import boto3
    return boto3.client("secretsmanager", region_name=region).get_secret_value(SecretId=secret_id)["SecretString"].strip()


def _jsonable(value):
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return value


def _incident_view(item: dict) -> dict:
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    return _jsonable({
        "id": item.get("incident_id"),
        "time": item.get("timestamp"),
        "rule": item.get("rule"),
        "severity": item.get("severity"),
        "ip": details.get("client_ip") or details.get("ip"),
        "actor": details.get("username") or details.get("user") or details.get("actor"),
        "details": details,
    })


def _block_view(item: dict) -> dict:
    return _jsonable({
        "ip": item.get("blocked_ip"),
        "reason": item.get("reason"),
        "blocked_at": item.get("blocked_at"),
        "expires_at": item.get("ttl"),
    })


# ============================================================ detection
_MALICIOUS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"\bunion\b[\s\S]*\bselect\b",
    r"'\s*(or|and)\s+['\d\w]+\s*=\s*['\d\w]+",
    r"\bor\s+1\s*=\s*1\b",
    r";\s*(drop|delete|insert|update|shutdown)\b",
    r"\b(drop|truncate)\s+table\b",
    r"'\s*--",
    r"/\*.*\*/",
    r"\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(",
    r"(\.\./|\.\.\\|%2e%2e%2f)",
    # --- bo sung sau dot red-team (tests/unit/test_redteam_scenarios.py) ---
    r"'\s*#",                                                    # admin' #   (comment MySQL)
    r"\b(or|and)\s+\d+\s*(=|<>|!=|<=|>=|<|>)\s*\d+",             # 1 AND 1=1, 1 OR 2>1
    r"'\s*(or|and)\s+'?\w+'?\s+(not\s+)?like\b",                 # ' OR 'a' LIKE 'a
    r"'\s*\|\|\s*'",                                             # ' || '1'='1
    r"'\s*(having|order\s+by|group\s+by)\b",                     # ' HAVING 1=1, ' ORDER BY 10
    r";\s*(select|exec|execute|create|alter|declare|waitfor)\b",  # stacked query
    r"\bpg_sleep\s*\(|\bwaitfor\s+delay\b",
    r"\b(extractvalue|updatexml|load_file|xp_cmdshell|information_schema|pg_catalog|sysobjects|sqlite_master)\b",
    r"\binto\s+(out|dump)file\b",
    r"/etc/(passwd|shadow|hosts)\b|/proc/self/|\bfile://|\b(win|boot)\.ini\b",
    r"%c0%af|%c1%9c|%e0%80%af",                                  # UTF-8 overlong cua '/' va '\'
)]
_INVISIBLE = re.compile("[\u200b-\u200f\u2060\ufeff]")  # zero-width space/joiner, word joiner, BOM


def _normalize_query(query: str) -> str:
    """Dua moi bien the ma hoa ve mot dang truoc khi so mau: %2527 (ma hoa kep), ky tu toan chieu rong
    (U+FF07 -> '), ky tu vo hinh chen giua tu khoa. Ke tan cong khong ne duoc chi bang cach doi cach viet."""
    s = query or ""
    for _ in range(3):
        decoded = unquote(s)
        if decoded == s:
            break
        s = decoded
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", s))


def is_malicious_query(query: str) -> bool:
    """Regex co ranh gioi tu: 'how to select a laptop' KHONG bi khoa nham 24h nhu ban cu."""
    raw = query or ""
    normalized = _normalize_query(raw)
    if "\x00" in normalized:  # byte NUL khong bao gio hop le trong o tim kiem / ten dang nhap
        return True
    return any(p.search(text) for text in (raw, normalized) for p in _MALICIOUS_PATTERNS)


# ================================================================ app
_SETUP_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>LogSentinel 2FA Setup</title></head>
<body style="font-family: Arial, sans-serif; text-align: center; padding-top: 40px;">
  <h2>Thiet lap xac thuc 2 yeu to (TOTP)</h2>
  {% if qr_svg %}<div style="width:220px;margin:auto">{{ qr_svg }}</div>{% endif %}
  <p>Ma khoa thu cong: <code><b>{{ secret }}</b></code></p>
  <p style="color:#a00">Trang nay chua bi mat. Dong tab sau khi quet ma.</p>
</body></html>"""


def _render_qr_svg(uri: str) -> Optional[Markup]:
    """QR sinh NOI BO (khong gui secret cho dich vu QR ben thu ba nhu ban cu)."""
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return None
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8)
    return Markup(img.to_string(encoding="unicode"))


def _security_logger(path: str) -> logging.Logger:
    logger = logging.getLogger("LogSentinelWebApp")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    handler = logging.FileHandler(path)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


SESSION_MINUTES = 30
# Tuoi tho TUYET DOI cua phien tinh tu luc dang nhap (ngoai 30 phut khong hoat dong cua cookie):
#   cognito: 30 phut, vi vai tro chi doc luc dang nhap -> thu hoi quyen co hieu luc <= 30 phut
#   local  : 8 gio, de mot cookie bi danh cap khong the duoc "gia han" mai mai
SESSION_ABSOLUTE_SECONDS = {"cognito": SESSION_MINUTES * 60, "local": 8 * 3600}
MFA_CHALLENGE_SECONDS = 170  # Cognito giu phien thu thach MFA 3 phut
LOCAL_BRUTE_FORCE_THRESHOLD = 5  # phai bang BRUTE_FORCE_THRESHOLD trong lambda_src/detector.py
LOCAL_SCAN_THRESHOLD = 30        # phai bang SCAN_THRESHOLD trong lambda_src/detector.py
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,250}\.[^@\s.]{2,}$")
_ADMIN_ROLES = ("admin",)
_DATA_ROLES = ("viewer", "admin")  # "pending" (moi dang ky, chua duoc duyet) khong xem duoc du lieu


class RateLimiter:
    """Dem so lan / cua so thoi gian theo khoa (IP). Bo nho cuc bo tung worker -> gioi han thuc te ~ N x limit."""

    def __init__(self, limit: int, window: float, clock: Callable[[], float] = time.time, max_keys: int = 10_000):
        self._limit, self._window, self._clock, self._max_keys = limit, window, clock, max_keys
        self._hits = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            if len(self._hits) >= self._max_keys:
                self._hits = {k: v for k, v in self._hits.items() if v and v[-1] > now - self._window}
            recent = [t for t in self._hits.get(key, []) if t > now - self._window]
            if len(recent) >= self._limit:
                self._hits[key] = recent
                return False
            recent.append(now)
            self._hits[key] = recent
            return True


class SessionRevocations:
    """
    Danh sach phien da dang xuat. Phien nam trong cookie da ky nen neu khong co danh sach nay thi cookie bi
    danh cap van dung duoc sau khi nan nhan dang xuat.
      - Worker nhan lenh dang xuat: tu choi ngay (RAM).
      - Worker khac: hoi DynamoDB, nho ket qua "chua thu hoi" `negative_ttl` giay -> cookie cu chet trong <= 15s.
      - Store khong ho tro / DynamoDB loi: fail-open (khong da nguoi dung that ra), van thu hoi trong worker nay.
    """

    def __init__(self, store, clock: Callable[[], float] = time.time, negative_ttl: float = 15.0,
                 max_entries: int = 10_000):
        self._store, self._clock, self._negative_ttl, self._max_entries = store, clock, negative_ttl, max_entries
        self._revoked = {}   # sid -> het han (epoch)
        self._clean = {}     # sid -> thoi diem phai hoi lai
        # principal -> (thoi diem huy moi phien, hoi lai DynamoDB sau thoi diem nay). It muc: chi khi doi vai tro.
        self._user_revoked = {}
        self._lock = threading.Lock()

    def revoke_user(self, principal: str, at: float) -> None:
        """Huy moi phien cua `principal` dang nhap truoc hoac dung thoi diem `at` (vua bi doi vai tro / vo hieu hoa).
        Worker nay: ngay lap tuc. Worker khac: trong <= negative_ttl giay (ban ghi REVOKED_SESSION#user:...)."""
        with self._lock:
            self._user_revoked[principal] = (at, self._clock() + self._negative_ttl)
        if hasattr(self._store, "revoke_user"):
            try:
                self._store.revoke_user(principal, at, int(at + SESSION_ABSOLUTE_SECONDS["local"] + 60))
            except Exception as exc:
                print(f"[WARN] Khong ghi duoc thu hoi theo nguoi dung ({type(exc).__name__})", flush=True)

    def user_revoked_at(self, principal: str) -> float:
        """Thoi diem gan nhat moi phien cua `principal` bi huy (0 neu chua)."""
        now = self._clock()
        with self._lock:
            hit = self._user_revoked.get(principal)
        if hit and hit[1] > now:
            return hit[0]
        at = hit[0] if hit else 0.0
        if hasattr(self._store, "user_revoked_at"):
            try:
                at = max(at, float(self._store.user_revoked_at(principal) or 0))
            except Exception as exc:
                print(f"[WARN] Khong doc duoc thu hoi theo nguoi dung ({type(exc).__name__}) -> fail-open", flush=True)
        with self._lock:
            if len(self._user_revoked) >= self._max_entries:
                self._user_revoked.clear()
            self._user_revoked[principal] = (at, now + self._negative_ttl)
        return at

    def revoke(self, sid: str, expires_at: float) -> None:
        with self._lock:
            self._trim()
            self._revoked[sid] = expires_at
            self._clean.pop(sid, None)
        if hasattr(self._store, "revoke_session"):
            try:
                self._store.revoke_session(sid, int(expires_at))
            except Exception as exc:
                print(f"[WARN] Khong ghi duoc phien thu hoi ({type(exc).__name__})", flush=True)

    def is_revoked(self, sid: str) -> bool:
        now = self._clock()
        with self._lock:
            if self._revoked.get(sid, 0) > now:
                return True
            if self._clean.get(sid, 0) > now:
                return False
        revoked = False
        if hasattr(self._store, "session_revoked"):
            try:
                revoked = bool(self._store.session_revoked(sid))
            except Exception as exc:
                print(f"[WARN] Khong doc duoc phien thu hoi ({type(exc).__name__}) -> fail-open", flush=True)
        with self._lock:
            self._trim()
            if revoked:
                self._revoked[sid] = now + SESSION_ABSOLUTE_SECONDS["local"]
            else:
                self._clean[sid] = now + self._negative_ttl
        return revoked

    def _trim(self) -> None:
        now = self._clock()
        for cache in (self._revoked, self._clean):
            if len(cache) >= self._max_entries:
                for k in [k for k, v in cache.items() if v <= now]:
                    del cache[k]
                while len(cache) >= self._max_entries:
                    del cache[next(iter(cache))]


def _clean_email(value) -> Optional[str]:
    email = value.strip().lower() if isinstance(value, str) else ""
    return email if len(email) <= 254 and _EMAIL_RE.match(email) else None


def create_app(config: Optional[AppConfig] = None, blocklist: Optional[BlockList] = None,
               store=None, identity=None, clock: Callable[[], float] = time.time,
               governance_store=None, executor=None, chat=None) -> Flask:
    config = config or load_config_from_env()
    blocklist = blocklist or BlockList(dynamodb_lookup(config.incident_table, config.region))
    store = store or DynamoIncidentStore(config.incident_table, config.region)
    if identity is None and config.cognito_user_pool_id and config.cognito_client_id:
        identity = cognito.CognitoIdentity(config.cognito_user_pool_id, config.cognito_client_id, config.region)
    governance_store = governance_store or governance_mod.DynamoGovernanceStore(config.incident_table, config.region)
    governance = governance_mod.Governance(governance_store,
                                           identity=identity, clock=clock,
                                           local_principal=f"local:{config.admin_user}")
    if executor is None:
        executor = (governance_lambda.LambdaExecutor(config.governance_function, config.region)
                    if config.governance_function else governance_lambda.InProcessExecutor(governance, identity))
    if chat is None and config.chat_model and config.chat_secret_id:
        chat = chat_assistant.ChatAssistant(
            chat_assistant.OpenAIProvider(config.chat_model,
                                          key_loader=lambda: _read_secret(config.chat_secret_id, config.region)),
            chat_assistant.DynamoChatQuota(config.incident_table, config.region),
            knowledge=chat_assistant.load_knowledge(), daily_limit=config.chat_daily_limit)
    totp = pyotp.TOTP(config.totp_secret)
    logger = _security_logger(config.log_path)
    revocations = SessionRevocations(store, clock=clock)
    signup_limiter = RateLimiter(limit=5, window=600, clock=clock)    # dang ky / gui lai ma
    confirm_limiter = RateLimiter(limit=10, window=600, clock=clock)  # doan ma xac nhan email
    forgot_limiter = RateLimiter(limit=5, window=600, clock=clock)    # yeu cau ma dat lai mat khau
    reset_limiter = RateLimiter(limit=10, window=600, clock=clock)    # doan ma dat lai mat khau
    # Lan sai thu LOCAL_BRUTE_FORCE_THRESHOLD trong 60s -> chan tai cho (cung nguong voi Detector).
    fail_tracker = RateLimiter(limit=LOCAL_BRUTE_FORCE_THRESHOLD - 1, window=60, clock=clock)
    scan_tracker = RateLimiter(limit=LOCAL_SCAN_THRESHOLD - 1, window=60, clock=clock)

    app = Flask(__name__)
    app.secret_key = config.session_secret
    app.config.update(
        MAX_CONTENT_LENGTH=16 * 1024,
        SESSION_COOKIE_NAME="ls_session",
        SESSION_COOKIE_SECURE=True,       # chi gui qua HTTPS
        SESSION_COOKIE_HTTPONLY=True,     # JavaScript khong doc duoc
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_MINUTES),
    )

    def require_session(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("user"):
                return jsonify({"error": "Unauthorized"}), 401
            # Thieu sid / login_at (cookie cu) -> coi nhu het han. Qua tuoi tho tuyet doi hoac da dang xuat -> tu choi.
            sid, limit = session.get("sid"), SESSION_ABSOLUTE_SECONDS.get(session.get("auth"), 0)
            login_at = session.get("login_at", 0)
            principal = f"{session.get('auth', 'local')}:{session['user']}"
            if not sid or clock() - login_at > limit or revocations.is_revoked(sid) \
                    or revocations.user_revoked_at(principal) >= login_at:  # vai tro vua doi / bi vo hieu hoa
                session.clear()
                return jsonify({"error": "Unauthorized"}), 401
            return view(*args, **kwargs)
        return wrapper

    def require_role(*roles):
        """Dung SAU require_session. Thieu role -> tu choi (fail-closed)."""
        def decorator(view):
            @wraps(view)
            def wrapper(*args, **kwargs):
                if session.get("role") not in roles:
                    return jsonify({"error": "Forbidden"}), 403
                if session.get("mfa_setup_required"):  # admin Cognito chua bat 2FA: chi duoc vao man hinh bat 2FA
                    return jsonify({"error": "mfa_setup_required"}), 403
                return view(*args, **kwargs)
            return wrapper
        return decorator

    def require_cognito(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if identity is None or session.get("auth") != "cognito":
                return jsonify({"error": "mfa_managed_locally"}), 400
            return view(*args, **kwargs)
        return wrapper

    def require_csrf(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            sent = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(sent.encode(), str(session.get("csrf", "")).encode()) or not sent:
                return jsonify({"error": "Bad CSRF token"}), 403
            return view(*args, **kwargs)
        return wrapper

    def _unlocked() -> bool:
        return session.get("gov_unlocked_until", 0) > clock()

    def require_unlocked(view):
        """Dung SAU require_role: muc Phan quyen phai dang mo (nhap PIN dung trong 10 phut qua)."""
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not _unlocked():
                return jsonify({"error": "pin_required"}), 403
            return view(*args, **kwargs)
        return wrapper

    def write_security_log(event_type: str, status_code: int, **details) -> None:
        # Truong co dinh dat SAU details: khong chi tiet nao (ke ca do loi lap trinh sau nay) ghi de duoc
        # event_type / client_ip - hai truong Detector dung de quyet dinh khoa IP.
        logger.info(json.dumps({
            **details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "sample-webapp",
            "event_type": event_type,
            "client_ip": g.client_ip,
            "status_code": status_code,
            "path": request.path,
        }))  # ensure_ascii mac dinh: U+2028 / U+0085 (ngat dong Unicode) thanh \uXXXX -> luon dung 1 dong / su kien

    def critical(event_type: str, **details):
        write_security_log(event_type, 403, severity="CRITICAL", **details)
        blocklist.block_locally(g.client_ip)  # chan ngay, khong cho vong Lambda

    def failed_login(status_code: int, **details) -> None:
        """Ghi FAILED_LOGIN va tu chan tai cho khi 1 IP sai du nguong. Detector van la noi quyet dinh khoa 24h
        (ghi DynamoDB), nhung log mat vai giay moi toi Lambda: khong chan ngay thi ke tan cong doan tiep
        hang tram lan trong luc cho. Chan tam 60s, het han thi hoi lai DynamoDB nhu moi block_locally."""
        write_security_log("FAILED_LOGIN", status_code, **details)
        if not fail_tracker.allow(g.client_ip):
            blocklist.block_locally(g.client_ip)

    def reject_injection(value: str, field: str):
        """Payload SQLi/path traversal dat o o dang nhap cung la tan cong, khong chi o o tim kiem."""
        if not is_malicious_query(value):
            return None
        critical("SQL_INJECTION", payload=value[:512], field=field)
        return jsonify({"error": "Forbidden - Phat hien payload doc hai"}), 403

    @app.before_request
    def enforce_soar_defense():
        g.client_ip = resolve_client_ip(request.remote_addr, request.headers, config.trust_proxy)
        if blocklist.is_blocked(g.client_ip):
            return jsonify({
                "error": "Access Denied by SOAR Active Defense",
                "message": f"Dia chi IP {g.client_ip} da bi LogSentinel tu dong khoa.",
            }), 403

    @app.errorhandler(404)
    def log_not_found(error):
        """Duong dan khong ton tai: ghi lai de Detector nhan ra IP dang do quet. Tra ve trang 404 mac dinh."""
        write_security_log("NOT_FOUND", 404)
        # Lan 404 thu 30 trong 60s -> chan tai cho (cung nguong voi Detector), gioi han so dong log 1 scanner tao ra.
        if not scan_tracker.allow(g.client_ip):
            blocklist.block_locally(g.client_ip)
        return error

    @app.after_request
    def harden_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Cache-Control", "no-store")
        # Console chi nap script/style tu chinh no: payload tan cong hien trong bang khong the chay.
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        return resp

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    @app.get("/setup-2fa")
    def setup_2fa():
        supplied = request.headers.get("X-Setup-Token") or request.args.get("token", "")
        if not hmac.compare_digest(supplied.encode(), config.setup_token.encode()):
            # Dem nhu FAILED_LOGIN -> do token 5 lan / 60s se bi brute-force rule khoa IP.
            failed_login(404, username="setup-2fa", reason="Invalid setup token")
            return jsonify({"error": "Not Found"}), 404
        uri = totp.provisioning_uri(name=f"{config.admin_user}@logsentinel.fcaj", issuer_name="LogSentinel-FCAJ")
        return render_template_string(_SETUP_TEMPLATE, secret=config.totp_secret, qr_svg=_render_qr_svg(uri))

    @app.post("/login")
    def login():
        user = (request.form.get("username") or "unknown")[:64]
        pwd = request.form.get("password") or ""
        otp_code = (request.form.get("otp") or "").strip()[:10]
        if (rejected := reject_injection(user, "username")):
            return rejected

        user_ok = hmac.compare_digest(user.encode(), config.admin_user.encode())
        pass_ok = hmac.compare_digest(pwd.encode(), config.admin_password.encode())
        if not (user_ok and pass_ok):
            failed_login(401, username=user, reason="Invalid credentials")
            return jsonify({"error": "Unauthorized"}), 401

        if not otp_code:
            write_security_log("MFA_REQUIRED", 403, username=user, reason="Missing 2FA OTP code")
            return jsonify({"error": "MFA Required - Vui long cung cap ma OTP 6 so"}), 403

        if not totp.verify(otp_code, valid_window=1):
            # Mat khau dung + OTP sai = mat khau da bi lo -> CRITICAL. Khong ghi lai ma OTP.
            critical("MFA_BYPASS_ATTEMPT", username=user, otp_length=len(otp_code))
            return jsonify({"error": "Forbidden - Ma 2FA OTP khong hop le!"}), 403

        session.clear()  # chong session fixation
        session.permanent = True
        session["user"] = user
        session["auth"] = "local"
        session["role"] = "admin"
        session["sid"] = secrets.token_urlsafe(16)
        session["login_at"] = clock()
        session["csrf"] = secrets.token_urlsafe(32)
        write_security_log("LOGIN_SUCCESS", 200, username=user, mfa_verified=True, auth="local")
        return jsonify({"message": "Dang nhap thanh cong voi bao mat 2FA!"}), 200

    # ------------------------------------- dang ky / dang nhap Cognito (cong khai)
    def _json() -> dict:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    def _start_cognito_session(result, mfa_verified: bool):
        session.clear()  # chong session fixation
        session.permanent = True
        session["user"] = result.email
        session["auth"] = "cognito"
        session["role"] = result.role
        session["access_token"] = result.access_token
        session["sid"] = secrets.token_urlsafe(16)
        session["login_at"] = clock()
        session["csrf"] = secrets.token_urlsafe(32)
        # Admin bat buoc 2FA. Admin da bat 2FA luon di qua buoc OTP (mfa_verified=True).
        session["mfa_setup_required"] = result.role in _ADMIN_ROLES and not mfa_verified
        write_security_log("LOGIN_SUCCESS", 200, username=result.email, mfa_verified=mfa_verified,
                           auth="cognito", role=result.role)
        return jsonify({"ok": True, "role": result.role}), 200

    @app.get("/api/config")
    def api_config():
        return jsonify({"cognito": identity is not None, "chat": chat is not None,
                        "min_password_level": password_strength.MIN_ACCEPTED_LEVEL}), 200

    def _identity_or_404():
        return None if identity is not None else (jsonify({"error": "Not Found"}), 404)

    def _identity_error_response(exc: Exception):
        if isinstance(exc, cognito.RateLimited):
            return jsonify({"error": "rate_limited"}), 429
        print(f"[ERROR] Cognito loi: {type(exc).__name__}: {exc}", flush=True)
        return jsonify({"error": "upstream"}), 502

    @app.post("/auth/register")
    def auth_register():
        if (missing := _identity_or_404()):
            return missing
        if not signup_limiter.allow(g.client_ip):
            return jsonify({"error": "rate_limited"}), 429
        body = _json()
        email, password = _clean_email(body.get("email")), body.get("password")
        if not email:
            return jsonify({"error": "invalid_email"}), 400
        if not isinstance(password, str) or len(password) > 128 \
                or password_strength.evaluate(password, email) < password_strength.MIN_ACCEPTED_LEVEL:
            return jsonify({"error": "weak_password"}), 400
        try:
            identity.sign_up(email, password)
        except cognito.PasswordRejected:
            return jsonify({"error": "weak_password"}), 400
        except cognito.IdentityError as exc:
            return _identity_error_response(exc)
        write_security_log("REGISTER_REQUEST", 200, username=email)
        return jsonify({"ok": True}), 200  # luon nhu nhau du email da ton tai hay chua

    @app.post("/auth/confirm")
    def auth_confirm():
        if (missing := _identity_or_404()):
            return missing
        if not confirm_limiter.allow(g.client_ip):
            return jsonify({"error": "rate_limited"}), 429
        body = _json()
        email, code = _clean_email(body.get("email")), str(body.get("code") or "").strip()[:10]
        if not email or not code:
            return jsonify({"error": "invalid_code"}), 400
        try:
            identity.confirm_sign_up(email, code)
        except (cognito.CodeInvalid, cognito.AuthFailed):
            return jsonify({"error": "invalid_code"}), 400
        except cognito.IdentityError as exc:
            return _identity_error_response(exc)
        write_security_log("REGISTER_CONFIRMED", 200, username=email)
        return jsonify({"ok": True}), 200

    @app.post("/auth/resend")
    def auth_resend():
        if (missing := _identity_or_404()):
            return missing
        if not signup_limiter.allow(g.client_ip):
            return jsonify({"error": "rate_limited"}), 429
        email = _clean_email(_json().get("email"))
        if email:
            try:
                identity.resend_code(email)
            except cognito.IdentityError as exc:
                return _identity_error_response(exc)
        return jsonify({"ok": True}), 200

    @app.post("/auth/forgot")
    def auth_forgot():
        if (missing := _identity_or_404()):
            return missing
        if not forgot_limiter.allow(g.client_ip):
            return jsonify({"error": "rate_limited"}), 429
        email = _clean_email(_json().get("email"))
        if email:
            try:
                identity.forgot_password(email)
            except cognito.IdentityError as exc:
                return _identity_error_response(exc)
            write_security_log("PASSWORD_RESET_REQUEST", 200, username=email)
        return jsonify({"ok": True}), 200  # giong nhau du email co dang ky hay khong

    @app.post("/auth/reset")
    def auth_reset():
        if (missing := _identity_or_404()):
            return missing
        if not reset_limiter.allow(g.client_ip):
            return jsonify({"error": "rate_limited"}), 429
        body = _json()
        email, code, password = _clean_email(body.get("email")), str(body.get("code") or "").strip()[:10], body.get("password")
        if not email or not code:
            return jsonify({"error": "invalid_code"}), 400
        if not isinstance(password, str) or len(password) > 128                 or password_strength.evaluate(password, email) < password_strength.MIN_ACCEPTED_LEVEL:
            return jsonify({"error": "weak_password"}), 400
        try:
            identity.confirm_forgot_password(email, code, password)
        except (cognito.CodeInvalid, cognito.AuthFailed):
            return jsonify({"error": "invalid_code"}), 400
        except cognito.PasswordRejected:
            return jsonify({"error": "weak_password"}), 400
        except cognito.IdentityError as exc:
            return _identity_error_response(exc)
        write_security_log("PASSWORD_RESET_DONE", 200, username=email)
        return jsonify({"ok": True}), 200

    @app.post("/auth/login")
    def auth_login():
        if (missing := _identity_or_404()):
            return missing
        body = _json()
        email, password = _clean_email(body.get("email")), body.get("password")
        if (rejected := reject_injection(str(body.get("email") or "")[:254], "email")):
            return rejected
        if not email or not isinstance(password, str) or not password or len(password) > 128:
            failed_login(401, username=str(body.get("email") or "unknown")[:64], reason="Invalid credentials")
            return jsonify({"error": "unauthorized"}), 401
        try:
            result = identity.login(email, password)
        except cognito.AuthFailed:
            failed_login(401, username=email, reason="Invalid credentials")
            return jsonify({"error": "unauthorized"}), 401
        except cognito.NotConfirmed:
            return jsonify({"error": "not_confirmed"}), 403
        except cognito.UnsupportedChallenge:
            return jsonify({"error": "unsupported_challenge"}), 400
        except cognito.IdentityError as exc:
            return _identity_error_response(exc)
        if result.mfa_required:
            session.clear()
            session["mfa_pending"] = {"session": result.mfa_session, "username": result.username,
                                      "email": email, "exp": clock() + MFA_CHALLENGE_SECONDS}
            write_security_log("MFA_REQUIRED", 403, username=email, reason="Cognito TOTP challenge")
            return jsonify({"ok": True, "mfa_required": True}), 200
        return _start_cognito_session(result, mfa_verified=False)

    @app.post("/auth/mfa")
    def auth_mfa():
        if (missing := _identity_or_404()):
            return missing
        pending = session.get("mfa_pending")
        if not pending or pending.get("exp", 0) < clock():
            session.clear()
            return jsonify({"error": "expired"}), 401
        code = str(_json().get("code") or "").strip()[:10]
        try:
            result = identity.complete_mfa(pending["session"], pending["username"], code)
        except cognito.CodeInvalid:
            # Mat khau dung + OTP sai = mat khau da bi lo -> CRITICAL, giong tai khoan admin noi bo.
            critical("MFA_BYPASS_ATTEMPT", username=pending["email"], otp_length=len(code))
            return jsonify({"error": "invalid_otp"}), 403
        except cognito.AuthFailed:
            session.clear()
            return jsonify({"error": "expired"}), 401
        except cognito.IdentityError as exc:
            return _identity_error_response(exc)
        if not result.email:
            result = cognito.LoginResult(email=pending["email"], role=result.role,
                                         access_token=result.access_token)
        return _start_cognito_session(result, mfa_verified=True)

    # ------------------------------------------------ SOC Console (khach hang)
    @app.get("/console")
    def console():
        return render_template("console.html")

    @app.get("/api/session")
    @require_session
    def api_session():
        return jsonify({"user": session["user"], "csrf": session["csrf"],
                        "role": session.get("role"), "auth": session.get("auth", "local"),
                        "mfa_setup_required": bool(session.get("mfa_setup_required"))}), 200

    # ----------------------------- tai khoan & 2FA (nguoi dung tu bat/tat)
    @app.get("/api/account")
    @require_session
    def api_account():
        info = {"email": session["user"], "role": session.get("role"), "auth": session.get("auth", "local")}
        if session.get("auth") == "cognito":
            try:
                info["mfa_enabled"] = identity.mfa_enabled(session["access_token"])
            except cognito.AuthFailed:
                session.clear()
                return jsonify({"error": "Unauthorized"}), 401
            except cognito.IdentityError as exc:
                return _identity_error_response(exc)
        else:
            info["mfa_enabled"] = True   # admin noi bo: 2FA bat buoc, cau hinh trong webapp.env
        return jsonify(info), 200

    @app.post("/api/mfa/setup")
    @require_session
    @require_csrf
    @require_cognito
    def api_mfa_setup():
        try:
            secret = identity.begin_mfa_setup(session["access_token"])
        except cognito.AuthFailed:
            session.clear()
            return jsonify({"error": "Unauthorized"}), 401
        except cognito.IdentityError as exc:
            return _identity_error_response(exc)
        uri = cognito.totp_uri(session["user"], secret)
        qr = _render_qr_svg(uri)
        return jsonify({"secret": secret, "otpauth_uri": uri, "qr_svg": str(qr) if qr else None}), 200

    @app.post("/api/mfa/enable")
    @require_session
    @require_csrf
    @require_cognito
    def api_mfa_enable():
        code = str(_json().get("code") or "").strip()[:10]
        try:
            identity.confirm_mfa_setup(session["access_token"], code)
        except cognito.CodeInvalid:
            return jsonify({"error": "invalid_otp"}), 400
        except cognito.AuthFailed:
            session.clear()
            return jsonify({"error": "Unauthorized"}), 401
        except cognito.IdentityError as exc:
            return _identity_error_response(exc)
        session["mfa_setup_required"] = False  # vua chung minh duoc ma TOTP
        write_security_log("MFA_ENABLED", 200, username=session["user"])
        return jsonify({"ok": True, "mfa_enabled": True}), 200

    @app.post("/api/mfa/disable")
    @require_session
    @require_csrf
    @require_cognito
    def api_mfa_disable():
        if session.get("role") in _ADMIN_ROLES:
            return jsonify({"error": "admin_mfa_required"}), 403  # admin bat buoc giu 2FA
        # Tat 2FA = ha muc bao ve -> hoi lai mat khau + OTP hien tai (chong ke chiem phien tu tat 2FA).
        body = _json()
        password, code = body.get("password"), str(body.get("code") or "").strip()[:10]
        if not isinstance(password, str) or not password or len(password) > 128 or not code:
            return jsonify({"error": "reauth_required"}), 400
        try:
            identity.reauthenticate(session["user"], password, code)
        except (cognito.AuthFailed, cognito.CodeInvalid, cognito.NotConfirmed):
            # Tinh nhu FAILED_LOGIN: doan sai 5 lan / 60s se bi luat brute-force khoa IP.
            failed_login(403, username=session["user"], reason="Invalid re-authentication")
            return jsonify({"error": "reauth_failed"}), 403
        except cognito.IdentityError as exc:
            return _identity_error_response(exc)
        try:
            identity.set_mfa_disabled(session["access_token"])
        except cognito.AuthFailed:
            session.clear()
            return jsonify({"error": "Unauthorized"}), 401
        except cognito.IdentityError as exc:
            return _identity_error_response(exc)
        write_security_log("MFA_DISABLED", 200, username=session["user"])  # dau vet kiem toan
        return jsonify({"ok": True, "mfa_enabled": False}), 200

    # ------------------------------------------- quan tri: duyet nguoi dung
    @app.get("/api/users")
    @require_session
    @require_role(*_ADMIN_ROLES)
    def api_users():
        if identity is None:
            return jsonify({"pending": [], "viewers": [], "admins": []}), 200
        try:
            return jsonify(identity.list_users()), 200
        except cognito.IdentityError as exc:
            return _identity_error_response(exc)

    # ------------------------------------------- quan tri: muc Phan quyen (PIN rieng)
    # Quy tac nam trong admin_governance.py; o day chi xac thuc, ghi log va dich loi sang HTTP.
    def _principal() -> str:
        return f"{session.get('auth', 'local')}:{session['user']}"

    def _unlock_section() -> None:
        session["gov_unlocked_until"] = clock() + governance_mod.UNLOCK_SECONDS

    def _governance_error(exc: governance_mod.GovernanceError):
        return jsonify({"error": exc.code}), exc.http

    def _verify_pin(pin):
        """None neu PIN dung, nguoc lai la response loi. Lan sai lam khoa PIN -> ADMIN_PIN_LOCKED (Detector canh bao)."""
        try:
            governance.check_pin(_principal(), pin)
        except governance_mod.WrongPin as exc:
            if exc.just_locked:
                write_security_log("ADMIN_PIN_LOCKED", 403, username=session["user"], auth=session.get("auth"))
            return _governance_error(exc)
        except governance_mod.GovernanceError as exc:  # PinLocked
            return _governance_error(exc)
        return None

    def _governed(call, pin_required: bool = True):
        """Thao tac chay tren EC2 (doc trang thai, PIN): (ket qua, None) hoac (None, response loi)."""
        if pin_required and (refused := _verify_pin(_json().get("pin"))):
            return None, refused
        try:
            return call(), None
        except governance_mod.GovernanceError as exc:
            return None, _governance_error(exc)
        except cognito.IdentityError as exc:
            return None, _identity_error_response(exc)

    # Su kien ghi khi thao tac ket thuc. Detector canh bao ADMIN_ROLE_CHANGED / USER_DISABLED (HIGH).
    _EXECUTED_EVENT = {"promote": "ADMIN_ROLE_CHANGED", "demote": "ADMIN_ROLE_CHANGED", "disable": "USER_DISABLED"}

    def _log_outcome(outcome: dict, created: bool = False) -> None:
        common = dict(username=session["user"], action=outcome["action"], target_user=outcome["target_user"],
                      request_id=outcome["id"])
        if outcome["status"] == "executed":
            # Vai tro doc luc dang nhap: huy moi phien cua nguoi bi tac dong de thay doi co hieu luc ngay
            # (bi ha / vo hieu hoa mat quyen; duoc nang phai dang nhap lai va bat 2FA).
            revocations.revoke_user(f"cognito:{outcome['target_user']}", clock())
            write_security_log(_EXECUTED_EVENT[outcome["action"]], 200, approvers=outcome["approvers"],
                               bootstrap=bool(outcome.get("bootstrap")), **common)
        elif outcome["status"] == "rejected":
            write_security_log("ROLE_REQUEST_REJECTED", 200, **common)
        elif outcome["status"] == "pending" and created:
            write_security_log("ROLE_REQUEST_CREATED", 200, **common)  # bao cac admin khac vao bo phieu
        elif outcome["status"] == "failed":
            write_security_log("ROLE_CHANGE_FAILED", 502, **common)

    def _caller() -> dict:
        """Danh tinh gui cho Lambda: token Cognito cua CHINH nguoi bam (Lambda tu hoi Cognito), hoac admin noi bo."""
        return ({"access_token": session.get("access_token", "")} if session.get("auth") == "cognito"
                else {"local": True})

    def _execute(op: str, pin_required: bool = True, **params):
        """Gui thao tac phan quyen cho executor (Lambda) kem token Cognito cua CHINH nguoi bam; Lambda tu xac minh
        nguoi do la ai. Admin noi bo khong co token -> {"local": true}, Lambda chi tin trong che do khoi tao.
        Tra ve (ket qua, None) hoac (None, response loi)."""
        if pin_required and (refused := _verify_pin(_json().get("pin"))):
            return None, refused
        reply = executor({"op": op, "caller": _caller(), **params})
        if "error" in reply:
            if isinstance(reply.get("outcome"), dict):
                _log_outcome(reply["outcome"])   # vd Cognito loi khi thuc thi -> ROLE_CHANGE_FAILED
            return None, (jsonify({"error": reply["error"]}), int(reply.get("http", 502)))
        return reply["result"], None

    def _manage_viewer(op: str, log_event: str):
        email, refused = _execute(op, pin_required=False, username=str(_json().get("username") or "")[:128])
        if refused:
            return refused
        # Vai tro doc luc dang nhap: huy moi phien de thay doi co hieu luc ngay (bi thu hoi mat quyen doc;
        # duoc duyet dang nhap lai la thanh Nguoi xem).
        revocations.revoke_user(f"cognito:{email}", clock())
        write_security_log(log_event, 200, username=session["user"], target_user=email)
        return jsonify({"ok": True}), 200

    @app.post("/api/users/approve")
    @require_session
    @require_csrf
    @require_role(*_ADMIN_ROLES)
    @require_unlocked
    def api_users_approve():
        return _manage_viewer("approve_viewer", "USER_APPROVED")

    @app.post("/api/users/revoke")
    @require_session
    @require_csrf
    @require_role(*_ADMIN_ROLES)
    @require_unlocked
    def api_users_revoke():
        return _manage_viewer("revoke_viewer", "USER_REVOKED")

    @app.get("/api/governance")
    @require_session
    @require_role(*_ADMIN_ROLES)
    def api_governance():
        info, refused = _governed(governance.summary, pin_required=False)  # canh bao do: ca khi chua mo PIN
        if refused:
            return refused
        info.update(has_pin=governance.has_pin(_principal()), unlocked=_unlocked(), server_time=clock(),
                    unlocked_until=session.get("gov_unlocked_until") if _unlocked() else None)
        if _unlocked():
            requests, refused = _governed(governance.pending_requests, pin_required=False)
            if refused:
                return refused
            info["requests"] = requests
        return jsonify(info), 200

    @app.post("/api/governance/pin")
    @require_session
    @require_csrf
    @require_role(*_ADMIN_ROLES)
    def api_governance_set_pin():
        _, refused = _governed(lambda: governance.set_pin(_principal(), _json().get("pin")), pin_required=False)
        if refused:
            return refused
        _unlock_section()
        return jsonify({"ok": True}), 200

    @app.post("/api/governance/unlock")
    @require_session
    @require_csrf
    @require_role(*_ADMIN_ROLES)
    def api_governance_unlock():
        if (refused := _verify_pin(_json().get("pin"))):
            return refused
        _unlock_section()
        return jsonify({"ok": True}), 200

    @app.post("/api/governance/pin/reset")
    @require_session
    @require_csrf
    @require_role(*_ADMIN_ROLES)
    @require_unlocked
    def api_governance_reset_pin():
        email, refused = _governed(lambda: governance.reset_pin(_principal(), _json().get("username")))
        if refused:
            return refused
        write_security_log("ADMIN_PIN_RESET", 200, username=session["user"], target_user=email)
        return jsonify({"ok": True}), 200

    @app.post("/api/governance/requests")
    @require_session
    @require_csrf
    @require_role(*_ADMIN_ROLES)
    @require_unlocked
    def api_governance_create_request():
        body = _json()
        outcome, refused = _execute("create", action=body.get("action"), username=body.get("username"))
        if refused:
            return refused
        _log_outcome(outcome, created=True)
        return jsonify(outcome), 200

    @app.post("/api/governance/requests/<request_id>/vote")
    @require_session
    @require_csrf
    @require_role(*_ADMIN_ROLES)
    @require_unlocked
    def api_governance_vote(request_id):
        decision = _json().get("decision")
        if decision not in ("approve", "reject"):
            return jsonify({"error": "invalid_request"}), 400
        outcome, refused = _execute("vote", request_id=request_id[:64], approve=decision == "approve")
        if refused:
            return refused
        _log_outcome(outcome)
        return jsonify(outcome), 200

    @app.post("/api/logout")
    @require_session
    @require_csrf
    def api_logout():
        # Thu hoi phia may chu: cookie nay (va moi ban sao bi danh cap) khong dung lai duoc nua.
        limit = SESSION_ABSOLUTE_SECONDS.get(session.get("auth"), 0)
        revocations.revoke(session["sid"], session.get("login_at", clock()) + limit + 60)
        session.clear()
        return jsonify({"ok": True}), 200

    @app.get("/api/overview")
    @require_session
    @require_role(*_DATA_ROLES)
    def api_overview():
        try:
            incidents = [_incident_view(i) for i in store.recent_incidents(50)]
            blocks = [_block_view(b) for b in store.active_blocks(time.time())]
        except Exception as exc:
            print(f"[ERROR] Console doc du lieu loi: {type(exc).__name__}", flush=True)
            return jsonify({"error": "Không đọc được dữ liệu sự cố."}), 502
        return jsonify({"incidents": incidents, "blocks": blocks, "server_time": int(time.time())}), 200

    # khoang -> (so o, do dai o, so su co doc toi da, giay luu ket qua). 7/30 ngay doc nhieu hon nen luu 5 phut:
    # nhieu nguoi xem / bam lien tuc chi ton 1 lan doc DynamoDB (chong Denial of Wallet).
    STATS_RANGES = {"24h": (24, 3600, 1000, 0), "7d": (7, 86400, 5000, 300), "30d": (30, 86400, 5000, 300)}
    stats_cache, stats_lock = {}, threading.Lock()

    @app.get("/api/stats")
    @require_session
    @require_role(*_DATA_ROLES)
    def api_stats():
        rng = request.args.get("range", "24h")
        try:
            tz = int(request.args.get("tz", "0"))
        except ValueError:
            tz = None
        if rng not in STATS_RANGES or tz is None or not -720 <= tz <= 840:
            return jsonify({"error": "Khoảng thời gian hoặc múi giờ không hợp lệ."}), 400
        slots, slot_seconds, limit, ttl = STATS_RANGES[rng]
        now = clock()
        with stats_lock:
            hit = stats_cache.get((rng, tz))
        if hit and hit[0] > now:
            return jsonify(hit[1]), 200
        since = (_EPOCH + timedelta(seconds=incident_stats.window_start(now, slots, slot_seconds, tz))).isoformat()
        try:
            items = store.incidents_since(since, limit)
        except Exception as exc:
            print(f"[ERROR] Thong ke doc du lieu loi: {type(exc).__name__}", flush=True)
            return jsonify({"error": "Không đọc được dữ liệu sự cố."}), 502
        summary = incident_stats.summarize(items, now, slots=slots, slot_seconds=slot_seconds, tz_minutes=tz)
        summary.update(range=rng, limit=limit, truncated=len(items) >= limit)
        if ttl:
            with stats_lock:
                if len(stats_cache) >= 64:   # tz tuy y khong lam phinh bo nho
                    stats_cache.clear()
                stats_cache[(rng, tz)] = (now + ttl, summary)
        return jsonify(summary), 200

    @app.post("/api/unblock")
    @require_session
    @require_csrf
    @require_role(*_ADMIN_ROLES)
    def api_unblock():
        ip = _valid_ip(_json().get("ip", ""))  # _json(): body khong phai object (vd so, mang) -> {} thay vi 500
        if not ip:
            return jsonify({"error": "IP khong hop le"}), 400
        return _unblock(ip, "Go khoa that bai")

    @app.post("/api/chat")
    @require_session
    @require_csrf
    @require_role(*_DATA_ROLES)
    def api_chat():
        if chat is None:
            return jsonify({"error": "Not Found"}), 404
        body = _json()
        incident_id = body.get("incident_id")
        try:
            recent = [_incident_view(i) for i in store.recent_incidents(50)]
        except Exception as exc:
            print(f"[ERROR] Chat doc su co loi: {type(exc).__name__}", flush=True)
            return jsonify({"error": "Không đọc được dữ liệu sự cố."}), 502
        if incident_id is not None:
            # Chi su co nguoi dung von xem duoc trong Console (50 su co gan nhat)
            recent = [i for i in recent if i["id"] == incident_id]
            if not recent:
                return jsonify({"error": "Không tìm thấy sự cố"}), 404
        try:
            answer = chat.ask(_principal(), body.get("message"), incidents=recent)
        except chat_assistant.ChatError as exc:
            if isinstance(exc, chat_assistant.ChatUnavailable):
                print(f"[ERROR] Tro ly AI loi: {type(exc.__cause__).__name__}", flush=True)
            return jsonify({"error": str(exc)}), exc.status
        # Khong ghi noi dung cau hoi/tra loi vao log (co the chua thong tin nhay cam)
        write_security_log("CHAT_QUESTION", 200, username=session["user"],
                           incident_id=incident_id, question_chars=len(body.get("message") or ""))
        return jsonify({"answer": answer}), 200

    def _unblock(ip: str, failure_message: str, **audit):
        """Go khoa IP va ghi ADMIN_UNBLOCK (+ truong audit)."""
        try:
            store.unblock(ip)
        except Exception as exc:
            print(f"[ERROR] Go khoa loi: {type(exc).__name__}", flush=True)
            return jsonify({"error": failure_message}), 502
        blocklist.forget(ip)
        write_security_log("ADMIN_UNBLOCK", 200, username=session["user"], unblocked_ip=ip, **audit)
        return jsonify({"ok": True, "ip": ip}), 200

    @app.get("/search")
    def search():
        query = (request.args.get("q") or "")[:512]
        if is_malicious_query(query):
            critical("SQL_INJECTION", payload=query)
            return jsonify({"error": "Forbidden - Phat hien payload doc hai"}), 403
        return jsonify({"result": "Ket qua tim kiem an toan", "query": query}), 200

    return app
