"""Test web app muc tieu: chong gia mao IP, cache chan, 2FA, config fail-fast. Khong can AWS."""
import importlib
import json
import sys
import types
from pathlib import Path

import pytest

pytest.importorskip("flask")

APP_SRC = str(Path(__file__).resolve().parents[2] / "sample_app")
GOOD_OTP = "123456"
TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
SETUP_TOKEN = "t" * 32


class FakeTOTP:
    def __init__(self, secret):
        self.secret = secret

    def verify(self, code, valid_window=0):
        return code == GOOD_OTP

    def provisioning_uri(self, name, issuer_name):
        return f"otpauth://totp/{issuer_name}:{name}?secret={self.secret}"


@pytest.fixture
def mod(monkeypatch):
    fake = types.ModuleType("pyotp")
    fake.TOTP = FakeTOTP
    monkeypatch.setitem(sys.modules, "pyotp", fake)
    monkeypatch.syspath_prepend(APP_SRC)
    sys.modules.pop("app", None)
    return importlib.import_module("app")


@pytest.fixture
def env(tmp_path):
    return {
        "APP_ADMIN_PASSWORD": "S3cure-Pass",
        "APP_TOTP_SECRET": TOTP_SECRET,
        "APP_SETUP_TOKEN": SETUP_TOKEN,
        "APP_SESSION_SECRET": "s" * 48,
        "INCIDENT_TABLE": "tbl",
        "TRUST_PROXY": "true",
        "APP_LOG_PATH": str(tmp_path / "access.log"),
    }


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def harness(mod, env):
    blocked, calls, clock = {}, [], Clock()

    def lookup(ip):
        calls.append(ip)
        return blocked.get(ip)

    class FakeStore:
        def __init__(self):
            self.incidents, self.blocks, self.unblocked = [], [], []

        def recent_incidents(self, limit=50):
            return self.incidents[:limit]

        def active_blocks(self, now):
            return [b for b in self.blocks if b["ttl"] > now]

        def unblock(self, ip):
            self.unblocked.append(ip)
            blocked.pop(ip, None)

    store = FakeStore()
    bl = mod.BlockList(lookup, clock=clock, negative_ttl=5)
    app = mod.create_app(mod.load_config_from_env(env), bl, store)
    client = app.test_client()
    log_path = Path(env["APP_LOG_PATH"])

    def logs():
        return [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]

    return types.SimpleNamespace(client=client, blocked=blocked, calls=calls, clock=clock, logs=logs, bl=bl,
                                 store=store)


def via_nginx(ip):
    """Mo phong request da di qua Nginx: ket noi vat ly tu 127.0.0.1, header do Nginx ghi de, HTTPS."""
    return {"environ_base": {"REMOTE_ADDR": "127.0.0.1"}, "headers": {"X-Real-IP": ip, "X-Forwarded-For": ip},
            "base_url": "https://localhost"}


# ------------------------------------------------------------- config
@pytest.mark.parametrize("missing", ["APP_ADMIN_PASSWORD", "APP_TOTP_SECRET", "APP_SETUP_TOKEN",
                                     "APP_SESSION_SECRET", "INCIDENT_TABLE"])
def test_missing_secret_fails_fast(mod, env, missing):
    env.pop(missing)
    with pytest.raises(RuntimeError, match=missing):
        mod.load_config_from_env(env)


def test_non_base32_totp_rejected(mod, env):
    env["APP_TOTP_SECRET"] = "not-base32!!"
    with pytest.raises(RuntimeError, match="base32"):
        mod.load_config_from_env(env)


def test_no_hardcoded_secrets_in_source():
    src = (Path(APP_SRC) / "app.py").read_text()
    for leaked in ("JBSWY3DPEHPK3PXP", "CorrectPassword123!", "IncidentTable8CE1664B", "api.qrserver.com"):
        assert leaked not in src


# ---------------------------------------------------------- client IP
def test_header_trusted_only_from_local_proxy(mod):
    h = {"X-Forwarded-For": "6.6.6.6"}
    assert mod.resolve_client_ip("127.0.0.1", h, True) == "6.6.6.6"
    assert mod.resolve_client_ip("203.0.113.9", h, True) == "203.0.113.9"  # goi thang, bypass Nginx
    assert mod.resolve_client_ip("127.0.0.1", h, False) == "127.0.0.1"   # TRUST_PROXY tat


def test_garbage_forwarded_header_falls_back_to_peer(mod):
    assert mod.resolve_client_ip("127.0.0.1", {"X-Real-IP": "<script>"}, True) == "127.0.0.1"


def test_spoofed_header_from_internet_cannot_frame_victim(harness):
    harness.client.get("/search?q=' OR 1=1 --", environ_base={"REMOTE_ADDR": "203.0.113.66"},
                       headers={"X-Forwarded-For": "8.8.8.8"})
    assert harness.logs()[-1]["client_ip"] == "203.0.113.66"


# ------------------------------------------------------------ blocklist
def test_blocked_ip_gets_403(harness):
    harness.blocked["198.51.100.1"] = harness.clock.t + 3600
    r = harness.client.get("/health", **via_nginx("198.51.100.1"))
    assert r.status_code == 403 and "SOAR" in r.get_json()["error"]


def test_expired_block_is_not_enforced_even_if_item_still_exists(harness):
    harness.blocked["198.51.100.1"] = harness.clock.t - 1  # TTL qua han nhung DynamoDB chua xoa
    assert harness.client.get("/health", **via_nginx("198.51.100.1")).status_code == 200


def test_clean_ip_is_cached_no_dynamodb_per_request(harness):
    for _ in range(50):
        harness.client.get("/health", **via_nginx("198.51.100.2"))
    assert harness.calls.count("198.51.100.2") == 1
    harness.clock.t += 6
    harness.client.get("/health", **via_nginx("198.51.100.2"))
    assert harness.calls.count("198.51.100.2") == 2


def test_blocked_ip_cached_but_revalidated_every_60s(harness):
    harness.blocked["198.51.100.3"] = harness.clock.t + 3600
    for _ in range(20):
        harness.client.get("/health", **via_nginx("198.51.100.3"))
    assert harness.calls.count("198.51.100.3") == 1
    del harness.blocked["198.51.100.3"]  # SOC go khoa bang tay trong DynamoDB
    harness.clock.t += 61
    assert harness.client.get("/health", **via_nginx("198.51.100.3")).status_code == 200


def test_local_block_is_provisional_until_detector_confirms(harness):
    harness.client.get("/search?q=' OR 1=1 --", **via_nginx("198.51.100.12"))
    assert harness.client.get("/health", **via_nginx("198.51.100.12")).status_code == 403
    harness.blocked["198.51.100.12"] = harness.clock.t + 86400  # Detector da ghi BLOCKED_IP#
    harness.clock.t += 61
    assert harness.client.get("/health", **via_nginx("198.51.100.12")).status_code == 403


def test_lookup_failure_fails_open(mod):
    def boom(ip):
        raise RuntimeError("dynamodb down")
    assert mod.BlockList(boom).is_blocked("198.51.100.4") is False


def test_cache_bounded_against_ip_rotation(mod):
    bl = mod.BlockList(lambda ip: None, max_entries=100)
    for i in range(1000):
        bl.is_blocked(f"10.0.{i // 256}.{i % 256}")
    assert len(bl._cache) <= 100


def test_sqli_blocks_attacker_locally_before_lambda(harness):
    r = harness.client.get("/search?q=1 UNION SELECT password FROM users", **via_nginx("198.51.100.5"))
    assert r.status_code == 403
    assert harness.client.get("/health", **via_nginx("198.51.100.5")).status_code == 403
    assert harness.logs()[-1]["event_type"] == "SQL_INJECTION"


@pytest.mark.parametrize("q", ["how to select a laptop", "drop shipping", "rock--paper", "o'reilly books"])
def test_benign_queries_not_flagged(mod, q):
    assert mod.is_malicious_query(q) is False


@pytest.mark.parametrize("q", ["' OR '1'='1", "1 or 1=1", "x'; DROP TABLE users", "a UNION ALL SELECT 1",
                               "admin'--", "../../etc/passwd", "1 AND SLEEP(5)"])
def test_attack_queries_flagged(mod, q):
    assert mod.is_malicious_query(q) is True


# ----------------------------------------------------------------- 2FA
def test_setup_2fa_requires_token_and_logs_failure(harness):
    r = harness.client.get("/setup-2fa", **via_nginx("198.51.100.6"))
    assert r.status_code == 404
    assert harness.logs()[-1]["event_type"] == "FAILED_LOGIN"


def test_setup_2fa_never_shows_current_otp_or_third_party_qr(harness):
    kw = via_nginx("198.51.100.7")
    kw["headers"]["X-Setup-Token"] = SETUP_TOKEN
    r = harness.client.get("/setup-2fa", **kw)
    body = r.get_data(as_text=True)
    assert r.status_code == 200 and TOTP_SECRET in body
    assert "OTP hien tai" not in body and "qrserver" not in body
    assert r.headers["Cache-Control"] == "no-store"


def _login(h, ip, **form):
    return h.client.post("/login", data=form, **via_nginx(ip))


def test_wrong_password_logged_as_failed_login(harness):
    assert _login(harness, "198.51.100.8", username="admin", password="x").status_code == 401
    assert harness.logs()[-1]["event_type"] == "FAILED_LOGIN"


def test_right_password_wrong_otp_is_critical_and_otp_not_logged(harness):
    r = _login(harness, "198.51.100.9", username="admin", password="S3cure-Pass", otp="000000")
    assert r.status_code == 403
    entry = harness.logs()[-1]
    assert entry["event_type"] == "MFA_BYPASS_ATTEMPT" and "000000" not in json.dumps(entry)


def test_full_login_success(harness):
    r = _login(harness, "198.51.100.10", username="admin", password="S3cure-Pass", otp=GOOD_OTP)
    assert r.status_code == 200 and harness.logs()[-1]["event_type"] == "LOGIN_SUCCESS"


def test_oversized_body_rejected(harness):
    r = harness.client.post("/login", data={"username": "a" * 50_000}, **via_nginx("198.51.100.11"))
    assert r.status_code == 413


# ---------------------------------------------------------- SOC Console
from decimal import Decimal  # noqa: E402

ADMIN_IP = "198.51.100.50"


def _sign_in(h):
    assert _login(h, ADMIN_IP, username="admin", password="S3cure-Pass", otp=GOOD_OTP).status_code == 200
    return h.client.get("/api/session", **via_nginx(ADMIN_IP)).get_json()["csrf"]


def _post(h, path, csrf=None, json_body=None):
    kw = via_nginx(ADMIN_IP)
    if csrf:
        kw["headers"]["X-CSRF-Token"] = csrf
    return h.client.post(path, json=json_body, **kw)


def test_console_page_served_with_csp(harness):
    r = harness.client.get("/console", **via_nginx(ADMIN_IP))
    assert r.status_code == 200 and "SOC Console" in r.get_data(as_text=True)
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


@pytest.mark.parametrize("path", ["/api/session", "/api/overview"])
def test_console_api_requires_login(harness, path):
    assert harness.client.get(path, **via_nginx(ADMIN_IP)).status_code == 401


def test_session_cookie_is_hardened(harness):
    r = _login(harness, ADMIN_IP, username="admin", password="S3cure-Pass", otp=GOOD_OTP)
    cookie = r.headers["Set-Cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_overview_returns_incidents_and_only_active_blocks(harness):
    harness.store.incidents = [{
        "incident_id": "abc", "timestamp": "2026-11-11T08:00:00+00:00", "rule": "SQL_INJECTION",
        "severity": "CRITICAL", "raw_payload": "SECRET-RAW",
        "details": {"client_ip": "203.0.113.5", "payload": "<script>alert(1)</script>", "latency": Decimal("0.25")},
    }]
    now = int(__import__("time").time())
    harness.store.blocks = [
        {"blocked_ip": "203.0.113.5", "reason": "sqli", "blocked_at": "x", "ttl": Decimal(now + 3600)},
        {"blocked_ip": "203.0.113.6", "reason": "old", "blocked_at": "x", "ttl": Decimal(now - 10)},
    ]
    _sign_in(harness)
    r = harness.client.get("/api/overview", **via_nginx(ADMIN_IP))
    body = r.get_json()
    assert r.status_code == 200 and r.mimetype == "application/json"
    assert body["incidents"][0]["ip"] == "203.0.113.5" and body["incidents"][0]["details"]["latency"] == 0.25
    assert [b["ip"] for b in body["blocks"]] == ["203.0.113.5"]
    assert "SECRET-RAW" not in r.get_data(as_text=True)  # raw_payload khong lo ra giao dien


def test_unblock_requires_csrf_token(harness):
    _sign_in(harness)
    assert _post(harness, "/api/unblock", json_body={"ip": "203.0.113.5"}).status_code == 403
    assert _post(harness, "/api/unblock", csrf="wrong", json_body={"ip": "203.0.113.5"}).status_code == 403
    assert harness.store.unblocked == []


def test_unblock_removes_block_immediately_and_is_audited(harness):
    harness.blocked["203.0.113.5"] = harness.clock.t + 3600
    assert harness.client.get("/health", **via_nginx("203.0.113.5")).status_code == 403
    csrf = _sign_in(harness)
    assert _post(harness, "/api/unblock", csrf=csrf, json_body={"ip": "203.0.113.5"}).status_code == 200
    assert harness.store.unblocked == ["203.0.113.5"]
    assert harness.client.get("/health", **via_nginx("203.0.113.5")).status_code == 200
    audit = [e for e in harness.logs() if e["event_type"] == "ADMIN_UNBLOCK"][-1]
    assert audit["unblocked_ip"] == "203.0.113.5" and audit["username"] == "admin"


@pytest.mark.parametrize("bad", ["", "not-an-ip", "1.2.3.4; rm -rf", None])
def test_unblock_rejects_invalid_ip(harness, bad):
    csrf = _sign_in(harness)
    assert _post(harness, "/api/unblock", csrf=csrf, json_body={"ip": bad}).status_code == 400


def test_logout_ends_session(harness):
    csrf = _sign_in(harness)
    assert _post(harness, "/api/logout", csrf=csrf).status_code == 200
    assert harness.client.get("/api/overview", **via_nginx(ADMIN_IP)).status_code == 401


def test_store_failure_returns_502_not_stacktrace(harness):
    _sign_in(harness)
    harness.store.recent_incidents = lambda limit=50: (_ for _ in ()).throw(RuntimeError("AccessDenied arn:aws:..."))
    r = harness.client.get("/api/overview", **via_nginx(ADMIN_IP))
    assert r.status_code == 502 and "arn:aws" not in r.get_data(as_text=True)


def test_console_script_never_uses_innerhtml():
    js = (Path(APP_SRC) / "static" / "console.js").read_text(encoding="utf-8")
    code = "\n".join(l for l in js.splitlines() if not l.strip().startswith("//"))
    assert "innerHTML" not in code and "document.write" not in code and "eval(" not in code


# ------------------------------------------------------- do quet (404)
def test_missing_path_is_logged_so_the_detector_can_spot_scanners(harness):
    r = harness.client.get("/wp-login.php", **via_nginx("198.51.100.30"))
    entry = harness.logs()[-1]
    assert r.status_code == 404
    assert entry["event_type"] == "NOT_FOUND" and entry["path"] == "/wp-login.php"
    assert entry["client_ip"] == "198.51.100.30" and entry["status_code"] == 404


def test_scanner_is_cut_off_locally_at_the_thirtieth_missing_path(harness):
    """Khong chan tai cho thi scanner ghi hang nghin dong log trong luc cho Detector (ton tien log + Lambda)."""
    codes = [harness.client.get(f"/probe-{i}.php", **via_nginx("198.51.100.31")).status_code for i in range(40)]
    assert codes == [404] * 30 + [403] * 10
    assert sum(e["event_type"] == "NOT_FOUND" for e in harness.logs()) == 30
    assert harness.client.get("/health", **via_nginx("198.51.100.32")).status_code == 200   # IP khac khong bi anh huong
