"""
LogSentinel target web app (Flask, chay sau Nginx TLS -> Gunicorn 127.0.0.1:8080).

Deep modules (giao dien nho, chi tiet an ben trong):
    AppConfig / load_config_from_env()  - cau hinh, KHONG co gia tri mac dinh nhay cam
    resolve_client_ip(...)              - chong gia mao IP (chi tin header khi den tu Nginx noi bo)
    BlockList.is_blocked / block_locally - cache TTL tren RAM truoc DynamoDB (chong Denial of Wallet)
    is_malicious_query(...)             - nhan dien SQLi / path traversal
    create_app(config, blocklist)       - lap rap Flask app; test truyen dependency gia vao day

Gunicorn: gunicorn -w 4 -b 127.0.0.1:8080 'app:create_app()'
"""
import base64
import binascii
import hmac
import ipaddress
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping, Optional

import pyotp
from flask import Flask, g, jsonify, render_template_string, request
from markupsafe import Markup


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
    log_path: str = "/var/log/webapp/access.log"


_REQUIRED_ENV = ("APP_ADMIN_PASSWORD", "APP_TOTP_SECRET", "APP_SETUP_TOKEN", "INCIDENT_TABLE")


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
    return AppConfig(
        admin_user=env.get("APP_ADMIN_USER", "admin"),
        admin_password=env["APP_ADMIN_PASSWORD"],
        totp_secret=totp_secret,
        setup_token=env["APP_SETUP_TOKEN"],
        incident_table=env["INCIDENT_TABLE"],
        region=env.get("AWS_DEFAULT_REGION", "ap-southeast-1"),
        trust_proxy=env.get("TRUST_PROXY", "false").lower() == "true",
        log_path=env.get("APP_LOG_PATH", "/var/log/webapp/access.log"),
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


def dynamodb_lookup(table_name: str, region: str) -> Lookup:
    import boto3  # import tre: test khong can boto3

    table = boto3.resource("dynamodb", region_name=region).Table(table_name)

    def lookup(ip: str) -> Optional[int]:
        item = table.get_item(Key={"incident_id": f"BLOCKED_IP#{ip}", "timestamp": "ACTIVE"}).get("Item")
        # Tu kiem tra ttl: DynamoDB co the tre toi 48h moi xoa item het han.
        return int(item["ttl"]) if item and "ttl" in item else None

    return lookup


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
)]


def is_malicious_query(query: str) -> bool:
    """Regex co ranh gioi tu: 'how to select a laptop' KHONG bi khoa nham 24h nhu ban cu."""
    return any(p.search(query or "") for p in _MALICIOUS_PATTERNS)


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


def create_app(config: Optional[AppConfig] = None, blocklist: Optional[BlockList] = None) -> Flask:
    config = config or load_config_from_env()
    blocklist = blocklist or BlockList(dynamodb_lookup(config.incident_table, config.region))
    totp = pyotp.TOTP(config.totp_secret)
    logger = _security_logger(config.log_path)

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

    def write_security_log(event_type: str, status_code: int, **details) -> None:
        logger.info(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "sample-webapp",
            "event_type": event_type,
            "client_ip": g.client_ip,
            "status_code": status_code,
            "path": request.path,
            **details,
        }, ensure_ascii=False))

    def critical(event_type: str, **details):
        write_security_log(event_type, 403, severity="CRITICAL", **details)
        blocklist.block_locally(g.client_ip)  # chan ngay, khong cho vong Lambda

    @app.before_request
    def enforce_soar_defense():
        g.client_ip = resolve_client_ip(request.remote_addr, request.headers, config.trust_proxy)
        if blocklist.is_blocked(g.client_ip):
            return jsonify({
                "error": "Access Denied by SOAR Active Defense",
                "message": f"Dia chi IP {g.client_ip} da bi LogSentinel tu dong khoa.",
            }), 403

    @app.after_request
    def harden_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    @app.get("/setup-2fa")
    def setup_2fa():
        supplied = request.headers.get("X-Setup-Token") or request.args.get("token", "")
        if not hmac.compare_digest(supplied.encode(), config.setup_token.encode()):
            # Dem nhu FAILED_LOGIN -> do token 5 lan / 60s se bi brute-force rule khoa IP.
            write_security_log("FAILED_LOGIN", 404, username="setup-2fa", reason="Invalid setup token")
            return jsonify({"error": "Not Found"}), 404
        uri = totp.provisioning_uri(name=f"{config.admin_user}@logsentinel.fcaj", issuer_name="LogSentinel-FCAJ")
        return render_template_string(_SETUP_TEMPLATE, secret=config.totp_secret, qr_svg=_render_qr_svg(uri))

    @app.post("/login")
    def login():
        user = (request.form.get("username") or "unknown")[:64]
        pwd = request.form.get("password") or ""
        otp_code = (request.form.get("otp") or "").strip()[:10]

        user_ok = hmac.compare_digest(user.encode(), config.admin_user.encode())
        pass_ok = hmac.compare_digest(pwd.encode(), config.admin_password.encode())
        if not (user_ok and pass_ok):
            write_security_log("FAILED_LOGIN", 401, username=user, reason="Invalid credentials")
            return jsonify({"error": "Unauthorized"}), 401

        if not otp_code:
            write_security_log("MFA_REQUIRED", 403, username=user, reason="Missing 2FA OTP code")
            return jsonify({"error": "MFA Required - Vui long cung cap ma OTP 6 so"}), 403

        if not totp.verify(otp_code, valid_window=1):
            # Mat khau dung + OTP sai = mat khau da bi lo -> CRITICAL. Khong ghi lai ma OTP.
            critical("MFA_BYPASS_ATTEMPT", username=user, otp_length=len(otp_code))
            return jsonify({"error": "Forbidden - Ma 2FA OTP khong hop le!"}), 403

        write_security_log("LOGIN_SUCCESS", 200, username=user, mfa_verified=True)
        return jsonify({"message": "Dang nhap thanh cong voi bao mat 2FA!"}), 200

    @app.get("/search")
    def search():
        query = (request.args.get("q") or "")[:512]
        if is_malicious_query(query):
            critical("SQL_INJECTION", payload=query)
            return jsonify({"error": "Forbidden - Phat hien payload doc hai"}), 403
        return jsonify({"result": "Ket qua tim kiem an toan", "query": query}), 200

    return app
