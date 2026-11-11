"""
Kich ban tan cong (red-team) chay offline. Moi nhom la mot MUC TIEU cua ke tan cong:

    A. Ne bo phat hien            D. Chiem phien / leo quyen trong Console
    B. Vu oan IP nguoi vo toi     E. Lam sap dich vu / do thong tin noi bo
    C. Doan mat khau              F. Bat bien ha tang (Nginx, bo loc CloudTrail)
    G. DIEM YEU CON LAI (xfail strict): he thong CHUA chong duoc. Khi ai do va xong, test se bao XPASS.
       (G1 brute-force cham va G2 cookie sau dang xuat da duoc va -> nay la C15 va D8.)

Chay rieng:  python -m pytest tests/unit/test_redteam_scenarios.py -v
"""
import base64
import gzip
import json
import re
from pathlib import Path

import pytest

pytest.importorskip("flask")

from .test_console_accounts import (  # noqa: E402,F401  (fixture + tro giup dung chung)
    GOOD_TOTP, STRONG, acct, get, local_admin, post, sign_in)
from .test_detector_core import FakeStateTable, _load  # noqa: E402
from .test_sample_app import APP_SRC, env, harness, mod, via_nginx  # noqa: E402,F401

ROOT = Path(__file__).resolve().parents[2]
ATTACKER, VICTIM = "203.0.113.66", "198.51.100.200"

# ---- bo payload ne bo loc: ma hoa kep, comment, chu hoa/thuong, ky tu Unicode, cu phap tung DBMS ----
EVASIONS = [
    "' OR '1'='1", "1 or 1=1", "admin'--", "admin' #", "' OR ''='", "1 OR 2>1", "1' OR 'a' LIKE 'a",
    "' || '1'='1", "1;SELECT pg_sleep(5)", "1; WAITFOR DELAY '0:0:5'", "1 UNION/**/SELECT 1",
    "UN/**/ION SEL/**/ECT", "1 uNiOn sElEcT 1", "1%20UNION%20SELECT%201", "%27%20OR%201%3D1%20--",
    "%2527%2520OR%25201%253D1", "1 AND 1=1", "1' AND '1'='1", "' HAVING 1=1 --", "' ORDER BY 10--",
    "x' AND extractvalue(1,concat(0x7e,version()))--", "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
    "'; EXEC xp_cmdshell('dir')--", "' UNION SELECT load_file('/etc/passwd')", "1 INTO OUTFILE '/tmp/x'",
    "../../etc/passwd", "..%2f..%2fetc%2fpasswd", "%252e%252e%252fetc%252fpasswd", "....//....//etc/passwd",
    "..%c0%af..%c0%afetc/passwd", "/etc/passwd", "/proc/self/environ", "..\\..\\windows\\win.ini",
    "file:///etc/passwd", "x%00.png", "＇ OR 1=1", "' OR 1=1​--", "1'/**/OR/**/1=1",
    "1'%09OR%091=1", "1' oR/*x*/1=1", "\\' OR 1=1 --",
]
BENIGN = [
    "how to select a laptop", "drop shipping", "rock--paper", "o'reilly books", "union square hotel",
    "select committee report", "1 or 2 bedrooms", "and/or", "it's 5 o'clock", "50% off", "C# programming",
    "order by price", "table of contents", "sleep apnea", "a.b.c", "price > 100", "tom & jerry",
    "user@example.com", "100% cotton", "path/to/file", "version 1.0.1", "what is /etc used for",
    "don't stop", "rock 'n' roll", "5 = five", "insert coin", "update my address", "delete account help",
]


@pytest.fixture
def det(monkeypatch):
    d = _load(monkeypatch)
    d.table = FakeStateTable()
    return d


def rules(d):
    return [c.kwargs["Item"].get("rule") for c in d.table.put_item.call_args_list]


def blocked_ips(d):
    return [c.kwargs["Item"]["blocked_ip"] for c in d.table.put_item.call_args_list
            if c.kwargs["Item"].get("record_type") == "BLOCK"]


def envelope(log_group, messages):
    data = {"logGroup": log_group, "logEvents": [{"message": m} for m in messages]}
    return {"awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(data).encode())).decode()}}


# =====================================================================
# A. NE BO PHAT HIEN
# =====================================================================
@pytest.mark.parametrize("payload", EVASIONS)
def test_A1_every_evasion_variant_is_detected(mod, payload):
    assert mod.is_malicious_query(payload) is True


@pytest.mark.parametrize("query", BENIGN)
def test_A2_ordinary_searches_are_not_blocked(mod, query):
    assert mod.is_malicious_query(query) is False


def test_A3_double_encoded_payload_over_real_http_is_blocked(harness):
    r = harness.client.get("/search?q=%2527%2520OR%25201%253D1", **via_nginx(ATTACKER))
    assert r.status_code == 403 and harness.logs()[-1]["event_type"] == "SQL_INJECTION"
    assert harness.client.get("/health", **via_nginx(ATTACKER)).status_code == 403


def test_A4_injection_hidden_in_login_username_is_an_attack_not_a_typo(harness):
    r = harness.client.post("/login", data={"username": "admin' OR '1'='1", "password": "x"}, **via_nginx(ATTACKER))
    entry = harness.logs()[-1]
    assert r.status_code == 403 and entry["event_type"] == "SQL_INJECTION" and entry["field"] == "username"


def test_A5_injection_hidden_in_cognito_email_field(acct):
    r = post(acct, "/auth/login", {"email": "a@x.co' UNION SELECT 1--", "password": "x"}, ip=ATTACKER)
    assert r.status_code == 403 and acct.logs()[-1]["event_type"] == "SQL_INJECTION"


# =====================================================================
# B. VU OAN IP NGUOI VO TOI (bien SOAR thanh vu khi)
# =====================================================================
@pytest.mark.parametrize("header", ["X-Forwarded-For", "X-Real-IP", "Forwarded", "X-Client-IP", "True-Client-IP"])
def test_B1_attacker_cannot_make_soar_block_someone_else(harness, header):
    """Goi thang vao app (bo qua Nginx) kem header gia: IP bi ghi nhan van la IP that cua ke tan cong."""
    harness.client.get("/search?q=' OR 1=1 --", environ_base={"REMOTE_ADDR": ATTACKER}, headers={header: VICTIM})
    assert harness.logs()[-1]["client_ip"] == ATTACKER
    assert harness.client.get("/health", **via_nginx(VICTIM)).status_code == 200


@pytest.mark.parametrize("username", [
    'x","client_ip":"198.51.100.200","event_type":"SQL_INJECTION',
    'x\n{"event_type":"SQL_INJECTION","client_ip":"198.51.100.200"}',
    'x\r\n{"event_type":"MFA_BYPASS_ATTEMPT","client_ip":"198.51.100.200"}',
    'x {"event_type":"SQL_INJECTION","client_ip":"198.51.100.200"}',
])
def test_B2_log_injection_cannot_forge_events_for_another_ip(harness, env, username):
    """Ten dang nhap chua dau nhay / xuong dong: van chi la 1 dong log, 1 su kien, dung IP ke tan cong."""
    harness.client.post("/login", data={"username": username, "password": "x"}, **via_nginx(ATTACKER))
    raw = Path(env["APP_LOG_PATH"]).read_text(encoding="utf-8")
    # splitlines() tach ca theo U+2028/U+0085: kiem tra luon cac cong cu doc log "rong tay" hon CloudWatch Agent
    assert raw.count("\n") == 1 and len(raw.splitlines()) == 1 and raw.isascii()
    entry = json.loads(raw)
    assert entry["client_ip"] == ATTACKER and entry["event_type"] == "FAILED_LOGIN"
    assert entry["username"] == username[:64]   # du lieu duoc giu nguyen, chi la khong thoat ra khoi truong cua no


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "0.0.0.0", "169.254.169.254", "not-an-ip", "", None,
                                "1.2.3.4, 5.6.7.8", ["1.2.3.4"], {"ip": "1.2.3.4"}, "1.2.3.4;rm -rf", "999.1.1.1"])
def test_B3_forged_log_lines_cannot_block_infrastructure_or_garbage(det, ip):
    det.evaluate_webapp_log(json.dumps({"event_type": "SQL_INJECTION", "client_ip": ip}))
    assert blocked_ips(det) == []


def test_B4_admin_allowlist_survives_forged_attack_events(monkeypatch):
    d = _load(monkeypatch, allowlist="198.51.100.200/32")
    d.table = FakeStateTable()
    for event in ("SQL_INJECTION", "MFA_BYPASS_ATTEMPT"):
        d.evaluate_webapp_log(json.dumps({"event_type": event, "client_ip": VICTIM}))
    for _ in range(8):
        d.evaluate_webapp_log(json.dumps({"event_type": "FAILED_LOGIN", "client_ip": VICTIM, "username": "a"}))
    assert blocked_ips(d) == []


# =====================================================================
# C. DOAN MAT KHAU
# =====================================================================
def test_C1_fifth_wrong_password_blocks_immediately_without_waiting_for_lambda(harness):
    codes = [harness.client.post("/login", data={"username": "admin", "password": f"guess{i}"},
                                 **via_nginx(ATTACKER)).status_code for i in range(8)]
    assert codes == [401] * 5 + [403] * 3          # tu lan thu 6 bi chan tai cho
    assert harness.blocked == {}                    # Detector CHUA ghi gi vao DynamoDB
    assert sum(e["event_type"] == "FAILED_LOGIN" for e in harness.logs()) == 5


def test_C2_local_block_is_provisional_and_does_not_hit_other_ips(harness):
    for i in range(5):
        harness.client.post("/login", data={"username": "admin", "password": "x"}, **via_nginx(ATTACKER))
    assert harness.client.get("/health", **via_nginx(VICTIM)).status_code == 200
    harness.clock.t += 61   # Detector khong xac nhan (vd IP nam trong allowlist) -> tu mo lai
    assert harness.client.get("/health", **via_nginx(ATTACKER)).status_code == 200


def test_C3_guessing_cognito_passwords_and_setup_token_is_blocked_the_same_way(acct):
    acct.identity.add("a@x.co")
    codes = [post(acct, "/auth/login", {"email": "a@x.co", "password": f"g{i}"}, ip=ATTACKER).status_code
             for i in range(7)]
    assert codes == [401] * 5 + [403] * 2
    other = "203.0.113.67"
    codes = [acct.client.get(f"/setup-2fa?token=guess{i}", **via_nginx(other)).status_code for i in range(7)]
    assert codes == [404] * 5 + [403] * 2


def test_C4_distributed_brute_force_on_one_account_raises_one_alert_and_blocks_nobody(det):
    """25 IP, moi IP sai 1 lan vao 'admin': bo dem theo IP khong thay gi; bo dem theo tai khoan phai thay."""
    for i in range(25):
        det.evaluate_webapp_log(json.dumps({"event_type": "FAILED_LOGIN", "client_ip": f"203.0.113.{i + 1}",
                                            "username": "Admin"}))
    assert rules(det).count("ACCOUNT_UNDER_ATTACK") == 1 and "BRUTE_FORCE_DETECTED" not in rules(det)
    assert blocked_ips(det) == []
    incident = next(c.kwargs["Item"] for c in det.table.put_item.call_args_list
                    if c.kwargs["Item"].get("rule") == "ACCOUNT_UNDER_ATTACK")
    assert incident["details"]["username"] == "admin" and incident["details"]["attempt_count"] == 10


def test_C5_single_ip_brute_force_does_not_double_alert(det):
    for _ in range(20):
        det.evaluate_webapp_log(json.dumps({"event_type": "FAILED_LOGIN", "client_ip": ATTACKER, "username": "admin"}))
    assert rules(det).count("BRUTE_FORCE_DETECTED") == 1 and "ACCOUNT_UNDER_ATTACK" not in rules(det)


def test_C6_attacker_cannot_hide_by_rotating_usernames_per_ip(det):
    for i in range(6):
        det.evaluate_webapp_log(json.dumps({"event_type": "FAILED_LOGIN", "client_ip": ATTACKER,
                                            "username": f"user{i}"}))
    assert rules(det).count("BRUTE_FORCE_DETECTED") == 1 and blocked_ips(det) == [ATTACKER]


def _console_login(outcome="Failure", ip=ATTACKER, user_type="IAMUser", mfa="No"):
    return json.dumps({"eventName": "ConsoleLogin", "sourceIPAddress": ip,
                       "userIdentity": {"type": user_type, "userName": "dev"},
                       "additionalEventData": {"MFAUsed": mfa},
                       "responseElements": {"ConsoleLogin": outcome}})


def test_C7_failed_aws_console_login_is_not_mislabelled_as_login_without_mfa(det):
    det.evaluate_cloudtrail_log(_console_login("Failure"))
    assert rules(det) == []   # 1 lan go sai la binh thuong, khong phai su co


def test_C8_aws_console_password_guessing_raises_one_alert(det):
    for _ in range(9):
        det.evaluate_cloudtrail_log(_console_login("Failure"))
    assert rules(det) == ["CONSOLE_BRUTE_FORCE"] and blocked_ips(det) == []


def test_C9_successful_console_login_without_mfa_is_still_flagged(det):
    det.evaluate_cloudtrail_log(_console_login("Success"))
    assert rules(det) == ["CONSOLE_LOGIN_NO_MFA"]


def test_C10_failed_root_login_attempt_is_critical(det):
    det.evaluate_cloudtrail_log(_console_login("Failure", user_type="Root"))
    item = det.table.put_item.call_args.kwargs["Item"]
    assert item["rule"] == "ROOT_ACCOUNT_LOGIN" and item["severity"] == "CRITICAL"
    assert item["details"]["outcome"] == "Failure"


def test_C15_low_and_slow_guessing_is_caught_by_the_hourly_window(det, monkeypatch):
    """1 lan doan moi 61 giay ne duoc cua so 60s, nhung khong ne duoc cua so 1 gio (20 lan)."""
    now = [1_000_000]
    monkeypatch.setattr(det, "_now", lambda: now[0])
    for i in range(40):
        det.evaluate_webapp_log(json.dumps({"event_type": "FAILED_LOGIN", "client_ip": ATTACKER,
                                            "username": f"user{i}"}))
        now[0] += 61
    assert rules(det).count("SLOW_BRUTE_FORCE") == 1 and "BRUTE_FORCE_DETECTED" not in rules(det)
    assert blocked_ips(det) == [ATTACKER]


def test_C16_a_few_typos_per_hour_are_not_an_attack(det, monkeypatch):
    now = [1_000_000]
    monkeypatch.setattr(det, "_now", lambda: now[0])
    for _ in range(19):
        det.evaluate_webapp_log(json.dumps({"event_type": "FAILED_LOGIN", "client_ip": VICTIM, "username": "me"}))
        now[0] += 180
    assert "SLOW_BRUTE_FORCE" not in rules(det) and blocked_ips(det) == []


def test_C17_fast_attack_does_not_also_raise_the_slow_alert(det):
    for _ in range(60):
        det.evaluate_webapp_log(json.dumps({"event_type": "FAILED_LOGIN", "client_ip": ATTACKER, "username": "admin"}))
    assert rules(det).count("BRUTE_FORCE_DETECTED") == 1 and "SLOW_BRUTE_FORCE" not in rules(det)


# ---- leo thang quyen IAM / lam mu he thong ----
def _ct(name, params=None, **identity):
    return json.dumps({"eventName": name, "requestParameters": params, "sourceIPAddress": ATTACKER,
                       "userIdentity": {"userName": "intruder", **identity}})


@pytest.mark.parametrize("event,params,rule", [
    ("AttachRolePolicy", {"roleName": "app", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}, "IAM_POLICY_ATTACHED"),
    ("AttachGroupPolicy", {"groupName": "devs", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}, "IAM_POLICY_ATTACHED"),
    ("PutRolePolicy", {"roleName": "app", "policyName": "p"}, "IAM_INLINE_POLICY_PUT"),
    ("PutGroupPolicy", {"groupName": "devs", "policyName": "p"}, "IAM_INLINE_POLICY_PUT"),
    ("CreatePolicyVersion", {"policyArn": "arn:aws:iam::1:policy/x", "setAsDefault": True}, "IAM_POLICY_VERSION_CREATED"),
    ("UpdateAssumeRolePolicy", {"roleName": "app"}, "IAM_TRUST_POLICY_CHANGED"),
    ("CreateLoginProfile", {"userName": "victim"}, "IAM_LOGIN_PROFILE_CHANGED"),
    ("UpdateLoginProfile", {"userName": "victim"}, "IAM_LOGIN_PROFILE_CHANGED"),
    ("AddUserToGroup", {"userName": "intruder", "groupName": "Admins"}, "IAM_USER_ADDED_TO_GROUP"),
])
def test_C11_privilege_escalation_through_roles_groups_and_passwords_is_caught(det, event, params, rule):
    det.evaluate_cloudtrail_log(_ct(event, params))
    item = det.table.put_item.call_args.kwargs["Item"]
    assert item["rule"] == rule and item["severity"] == "HIGH" and item["details"]["actor"] == "intruder"


def test_C12_attaching_admin_policy_to_a_role_is_critical(det):
    det.evaluate_cloudtrail_log(_ct("AttachRolePolicy", {
        "roleName": "app", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    item = det.table.put_item.call_args.kwargs["Item"]
    assert item["severity"] == "CRITICAL" and item["details"]["target_role"] == "app"


def test_C13_escalation_via_cloudformation_is_reported_and_labelled(det):
    det.evaluate_cloudtrail_log(_ct("PutRolePolicy", {"roleName": "app", "policyName": "p"},
                                    invokedBy="cloudformation.amazonaws.com"))
    assert det.table.put_item.call_args.kwargs["Item"]["details"]["via_service"] == "cloudformation.amazonaws.com"


@pytest.mark.parametrize("event", ["ScheduleKeyDeletion", "DisableKey"])
def test_C14_disabling_the_log_encryption_key_is_critical(det, event):
    det.evaluate_cloudtrail_log(_ct(event, {"keyId": "abcd-1234"}))
    item = det.table.put_item.call_args.kwargs["Item"]
    assert item["rule"] == "KMS_KEY_TAMPERING" and item["severity"] == "CRITICAL"


# =====================================================================
# D. CHIEM PHIEN / LEO QUYEN TRONG CONSOLE
# =====================================================================
def _forged_cookie(mod_, secret, **data):
    from flask import Flask
    forger = Flask("forger")
    forger.secret_key = secret
    return forger.session_interface.get_signing_serializer(forger).dumps(data)


def test_D1_cookie_signed_with_a_guessed_secret_is_rejected(acct, mod):
    cookie = _forged_cookie(mod, "wrong-secret" * 4, user="evil", role="admin", auth="local", csrf="c")
    acct.client.set_cookie("ls_session", cookie, domain="localhost")
    assert get(acct, "/api/session").status_code == 401 and get(acct, "/api/overview").status_code == 401


def test_D2_editing_role_inside_a_real_cookie_invalidates_it(acct):
    acct.identity.add("a@x.co")           # vai tro: pending
    sign_in(acct, "a@x.co")
    real = acct.client.get_cookie("ls_session", domain="localhost").value
    # Dinh dang cookie Flask: [.]<payload base64>.<timestamp>.<chu ky>; dau "." dau tien = payload nen zlib
    body, timestamp, signature = real.rsplit(".", 2)
    compressed = body.startswith(".")
    data = base64.urlsafe_b64decode(body.lstrip(".") + "=" * (-len(body.lstrip(".")) % 4))
    if compressed:
        import zlib
        data = zlib.decompress(data)
    assert b'"pending"' in data
    data = data.replace(b'"pending"', b'"admin"')
    if compressed:
        data = zlib.compress(data)
    forged = ("." if compressed else "") + base64.urlsafe_b64encode(data).decode().rstrip("=")
    acct.client.set_cookie("ls_session", f"{forged}.{timestamp}.{signature}", domain="localhost")
    assert get(acct, "/api/session").status_code == 401 and get(acct, "/api/overview").status_code == 401


ADMIN_ONLY = [("post", "/api/unblock", {"ip": "203.0.113.5"}), ("get", "/api/users", None),
              ("post", "/api/users/approve", {"username": "uid-p"}), ("post", "/api/users/revoke", {"username": "uid-v"})]


@pytest.mark.parametrize("role", ["pending", "viewer"])
@pytest.mark.parametrize("method,path,body", ADMIN_ONLY)
def test_D3_non_admins_cannot_reach_admin_functions(acct, role, method, path, body):
    acct.identity.add("me@x.co", role=role)
    acct.identity.add("p@x.co")
    csrf = sign_in(acct, "me@x.co")
    r = post(acct, path, body, csrf=csrf) if method == "post" else get(acct, path)
    assert r.status_code == 403
    assert acct.identity.approved == [] and acct.identity.revoked == [] and acct.store.unblocked == []


def test_D4_user_cannot_approve_themselves(acct):
    acct.identity.add("me@x.co")
    csrf = sign_in(acct, "me@x.co")
    assert post(acct, "/api/users/approve", {"username": "uid-me"}, csrf=csrf).status_code == 403
    assert acct.identity.users["me@x.co"]["role"] == "pending"


def test_D5_mfa_step_cannot_be_skipped_or_replayed(acct):
    acct.identity.add("a@x.co", mfa=True, role="admin")
    post(acct, "/auth/login", {"email": "a@x.co", "password": STRONG})
    for path in ("/api/overview", "/api/users", "/api/account", "/api/session"):
        assert get(acct, path).status_code == 401          # co mat khau nhung chua co OTP
    assert post(acct, "/api/unblock", {"ip": "203.0.113.5"}, csrf="x").status_code == 401
    assert post(acct, "/auth/mfa", {"code": GOOD_TOTP}).status_code == 200
    assert post(acct, "/auth/mfa", {"code": GOOD_TOTP}).status_code == 401   # thu thach da dung xong


STATE_CHANGING = ["/api/logout", "/api/unblock", "/api/users/approve", "/api/users/revoke",
                  "/api/mfa/setup", "/api/mfa/enable", "/api/mfa/disable"]


@pytest.mark.parametrize("path", STATE_CHANGING)
def test_D6_cross_site_request_without_csrf_token_changes_nothing(acct, path):
    acct.identity.add("v@x.co", role="viewer")
    acct.identity.add("p@x.co")
    local_admin(acct)
    body = {"ip": "203.0.113.5", "username": "uid-p", "code": GOOD_TOTP, "password": STRONG}
    assert post(acct, path, body).status_code == 403
    assert post(acct, path, body, csrf="attacker-guess").status_code == 403
    assert acct.identity.approved == [] and acct.store.unblocked == []
    assert get(acct, "/api/session").status_code == 200   # van dang nhap: logout gia mao cung khong co tac dung


def test_D7_viewer_cannot_read_secrets_through_any_api(acct):
    acct.identity.add("v@x.co", role="viewer")
    sign_in(acct, "v@x.co")
    for path in ("/api/session", "/api/account", "/api/overview", "/api/config"):
        body = get(acct, path).get_data(as_text=True)
        for secret in ("S3cure-Pass", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "t" * 32, "s" * 48, "tok-v@x.co"):
            assert secret not in body, (path, secret)


def test_D8_stolen_cookie_is_dead_after_the_victim_logs_out(acct):
    csrf = local_admin(acct)
    stolen = acct.client.get_cookie("ls_session", domain="localhost").value
    assert post(acct, "/api/logout", csrf=csrf).status_code == 200
    acct.client.set_cookie("ls_session", stolen, domain="localhost")   # ke tan cong phat lai cookie cu
    assert get(acct, "/api/session").status_code == 401 and get(acct, "/api/overview").status_code == 401


def test_D9_logout_reaches_other_workers_through_the_shared_store(mod, env):
    """2 worker = 2 app dung chung DynamoDB. Dang xuat o worker A phai giet cookie o worker B trong <= 15 giay."""
    from .test_sample_app import Clock, GOOD_OTP

    class SharedStore:
        revoked = {}

        def recent_incidents(self, limit=50):
            return []

        def active_blocks(self, now):
            return []

        def revoke_session(self, sid, expires_at):
            self.revoked[sid] = expires_at

        def session_revoked(self, sid):
            return sid in self.revoked

    clock, store, cfg = Clock(), SharedStore(), mod.load_config_from_env(env)
    worker_a, worker_b = (mod.create_app(cfg, mod.BlockList(lambda ip: None, clock=clock), store, clock=clock)
                          .test_client() for _ in range(2))
    kw = via_nginx("198.51.100.70")
    assert worker_a.post("/login", data={"username": "admin", "password": "S3cure-Pass", "otp": GOOD_OTP},
                         **kw).status_code == 200
    cookie = worker_a.get_cookie("ls_session", domain="localhost").value
    csrf = worker_a.get("/api/session", **kw).get_json()["csrf"]

    worker_b.set_cookie("ls_session", cookie, domain="localhost")
    assert worker_b.get("/api/overview", **via_nginx("198.51.100.70")).status_code == 200   # B da nho "chua thu hoi"

    kw = via_nginx("198.51.100.70")
    kw["headers"]["X-CSRF-Token"] = csrf
    assert worker_a.post("/api/logout", **kw).status_code == 200
    assert len(store.revoked) == 1 and all(exp > clock.t for exp in store.revoked.values())

    clock.t += 16   # qua thoi gian B duoc phep nho ket qua cu
    worker_b.set_cookie("ls_session", cookie, domain="localhost")
    assert worker_b.get("/api/overview", **via_nginx("198.51.100.70")).status_code == 401


def test_D10_a_session_cannot_be_kept_alive_forever(acct):
    """Cookie duoc gia han moi request; khong co tran tuyet doi thi cookie bi danh cap song mai."""
    local_admin(acct)
    acct.clock.t += 7 * 3600
    assert get(acct, "/api/overview").status_code == 200
    acct.clock.t += 2 * 3600   # tong 9 gio > tran 8 gio cua tai khoan noi bo
    assert get(acct, "/api/overview").status_code == 401


def test_D11_revocation_store_outage_does_not_lock_everyone_out(mod, env):
    from .test_sample_app import Clock, GOOD_OTP

    class BrokenStore:
        def recent_incidents(self, limit=50):
            return []

        def active_blocks(self, now):
            return []

        def revoke_session(self, sid, expires_at):
            raise RuntimeError("dynamodb down")

        def session_revoked(self, sid):
            raise RuntimeError("dynamodb down")

    clock = Clock()
    client = mod.create_app(mod.load_config_from_env(env), mod.BlockList(lambda ip: None, clock=clock),
                            BrokenStore(), clock=clock).test_client()
    kw = via_nginx("198.51.100.72")
    client.post("/login", data={"username": "admin", "password": "S3cure-Pass", "otp": GOOD_OTP}, **kw)
    assert client.get("/api/overview", **via_nginx("198.51.100.72")).status_code == 200   # fail-open
    cookie = client.get_cookie("ls_session", domain="localhost").value
    csrf = client.get("/api/session", **via_nginx("198.51.100.72")).get_json()["csrf"]
    kw = via_nginx("198.51.100.72")
    kw["headers"]["X-CSRF-Token"] = csrf
    assert client.post("/api/logout", **kw).status_code == 200
    client.set_cookie("ls_session", cookie, domain="localhost")
    assert client.get("/api/overview", **via_nginx("198.51.100.72")).status_code == 401   # worker nay van thu hoi


# =====================================================================
# E. LAM SAP DICH VU / DO THONG TIN NOI BO
# =====================================================================
POST_ENDPOINTS = ["/login", "/auth/login", "/auth/register", "/auth/confirm", "/auth/resend", "/auth/forgot",
                  "/auth/reset", "/auth/mfa", "/api/logout", "/api/unblock", "/api/users/approve",
                  "/api/users/revoke", "/api/mfa/setup", "/api/mfa/enable", "/api/mfa/disable"]
GARBAGE = [b"", b"null", b"[]", b"123", b'"str"', b"{", b'{"email":{"$ne":null},"password":{"$gt":""}}',
           b'{"email":["a@x.co"],"password":["x"],"code":[1],"username":{"a":1},"ip":{"b":2}}',
           b'{"email":"' + b"A" * 9000 + b'@x.co"}', b"\xff\xfe\x00\x01", b'{"a":' * 500 + b"1" + b"}" * 500,
           b'{"email":"a@x.co\\u0000","password":"\\ud800","code":"\\n"}']


@pytest.mark.parametrize("path", POST_ENDPOINTS)
def test_E1_garbage_bodies_never_cause_a_500_or_leak_a_stack_trace(acct, path):
    csrf = local_admin(acct, ip="198.51.100.90")
    for i, body in enumerate(GARBAGE):
        for content_type in ("application/json", "application/x-www-form-urlencoded", "text/plain"):
            kw = via_nginx(f"198.51.{i}.{len(content_type)}")   # moi lan 1 IP: khong dinh gioi han toc do
            kw["headers"].update({"X-CSRF-Token": csrf, "Content-Type": content_type})
            r = acct.client.post(path, data=body, **kw)
            text = r.get_data(as_text=True)
            assert r.status_code < 500, (path, body[:40], content_type, r.status_code)
            assert "Traceback" not in text and "File \"" not in text and "arn:aws" not in text


@pytest.mark.parametrize("path", ["/static/../app.py", "/static/..%2fapp.py", "/static/%2e%2e/app.py",
                                  "/static/..%5capp.py", "/app.py", "/cognito_identity.py", "/.env",
                                  "/templates/console.html", "/static/../deploy/bootstrap.sh", "/deploy/nginx.conf"])
def test_E2_source_code_and_config_are_not_downloadable(harness, path):
    r = harness.client.get(path, **via_nginx("198.51.100.91"))
    assert r.status_code in (403, 404)
    assert "create_app" not in r.get_data(as_text=True) and "APP_ADMIN_PASSWORD" not in r.get_data(as_text=True)


@pytest.mark.parametrize("method,path", [("get", "/login"), ("get", "/auth/login"), ("put", "/api/unblock"),
                                         ("delete", "/api/users"), ("post", "/console"), ("post", "/health")])
def test_E3_wrong_http_method_is_405_not_500(harness, method, path):
    assert getattr(harness.client, method)(path, **via_nginx("198.51.100.92")).status_code == 405


@pytest.mark.parametrize("path,expected", [("/nope", 404), ("/login", 405), ("/api/overview", 401)])
def test_E4_security_headers_are_present_even_on_error_pages(harness, path, expected):
    r = harness.client.get(path, **via_nginx("198.51.100.93"))
    assert r.status_code == expected
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_E5_one_attacker_cannot_flood_alerts(harness):
    """Sau payload dau tien IP bi chan tai cho -> 200 request tiep theo khong sinh them su kien nao."""
    for _ in range(200):
        harness.client.get("/search?q=' OR 1=1 --", **via_nginx(ATTACKER))
    assert sum(e["event_type"] == "SQL_INJECTION" for e in harness.logs()) == 1


def test_E6_search_reflection_cannot_run_script_in_a_browser(harness):
    r = harness.client.get("/search?q=<script>alert(1)</script>", **via_nginx("198.51.100.94"))
    assert r.mimetype == "application/json" and r.headers["X-Content-Type-Options"] == "nosniff"


POISON = [
    '{"event_type":"SQL_INJECTION","client_ip":"203.0.113.9","x":NaN}',
    '{"event_type":"SQL_INJECTION","client_ip":"203.0.113.9","x":1e999}',
    '{"event_type":"SQL_INJECTION","client_ip":"203.0.113.9","x":' + "[" * 200 + "]" * 200 + "}",
    json.dumps({"event_type": "SQL_INJECTION", "client_ip": "203.0.113.9", "payload": "A" * 300_000}),
    json.dumps({"event_type": ["SQL_INJECTION"], "client_ip": {"a": 1}}),
    json.dumps({"event_type": "FAILED_LOGIN", "client_ip": ["x"], "username": {"a": [1, 2]}}),
    json.dumps({"event_type": "FAILED_LOGIN", "client_ip": "203.0.113.9", "username": "u" * 5000}),
    "not json at all", "", "[]", "null", '"string"', "{" * 1000,
]


def test_E7_poisoned_log_lines_cannot_crash_or_blind_the_detector(det):
    """Dong log doc dung truoc 1 cuoc tan cong that: Detector van phai xu ly cuoc tan cong do."""
    real_attack = json.dumps({"event_type": "SQL_INJECTION", "client_ip": VICTIM})
    result = det.handler(envelope("/logsentinel/sample-app", POISON + [real_attack]), None)
    assert result["statusCode"] == 200
    assert VICTIM in blocked_ips(det)


CLOUDTRAIL_POISON = [
    '{"eventName":"ConsoleLogin","userIdentity":"not-a-dict"}',
    '{"eventName":"ConsoleLogin","userIdentity":{"type":"Root"},"additionalEventData":"x"}',
    '{"eventName":"AttachRolePolicy","requestParameters":"str","userIdentity":{}}',
    '{"eventName":"ConsoleLogin","responseElements":[1,2]}',
    '{"eventName":["ConsoleLogin"]}', '{"eventName":null,"userIdentity":null}',
]


def test_E8_malformed_cloudtrail_records_do_not_hide_a_real_tampering_event(det):
    real = json.dumps({"eventName": "StopLogging", "userIdentity": {"userName": "intruder"}, "sourceIPAddress": "x"})
    result = det.handler(envelope("/logsentinel/cloudtrail", CLOUDTRAIL_POISON + [real]), None)
    assert result["statusCode"] == 200 and "CLOUDTRAIL_TAMPERING" in rules(det)


def test_E9_attacker_controlled_fields_are_truncated_before_storage(det):
    det.evaluate_webapp_log(json.dumps({"event_type": "SQL_INJECTION", "client_ip": ATTACKER,
                                        "payload": "A" * 300_000, "nested": {"k" * 500: ["B" * 9000] * 500}}))
    item = next(c.kwargs["Item"] for c in det.table.put_item.call_args_list if c.kwargs["Item"].get("rule") == "SQL_INJECTION")
    assert len(json.dumps(item, default=str)) < 100_000   # gioi han item DynamoDB la 400 KB


# =====================================================================
# F. BAT BIEN HA TANG
# =====================================================================
def test_F1_every_cloudtrail_rule_in_the_detector_is_actually_delivered_to_it(det):
    """Luat co trong Detector nhung ten su kien khong nam trong subscription filter = luat chet."""
    from log_sentinel.log_sentinel_stack import CLOUDTRAIL_WATCHED_EVENTS
    handled = set(det.IAM_PRIVILEGE_EVENTS) | set(det.KMS_TAMPER_EVENTS) | {
        "ConsoleLogin", "DeactivateMFADevice", "DeleteVirtualMFADevice", "StopLogging", "DeleteTrail"}
    assert handled <= set(CLOUDTRAIL_WATCHED_EVENTS), handled - set(CLOUDTRAIL_WATCHED_EVENTS)
    pattern = " ".join(f'?"{e}"' for e in CLOUDTRAIL_WATCHED_EVENTS)
    assert len(pattern) <= 1024   # gioi han do dai filter pattern cua CloudWatch Logs


def test_F2_every_watched_cloudtrail_event_has_a_rule(det):
    from log_sentinel.log_sentinel_stack import CLOUDTRAIL_WATCHED_EVENTS
    for name in CLOUDTRAIL_WATCHED_EVENTS:
        det.table.put_item.reset_mock()
        det.evaluate_cloudtrail_log(json.dumps({
            "eventName": name, "sourceIPAddress": "x", "requestParameters": {},
            "userIdentity": {"type": "IAMUser", "userName": "u"},
            "additionalEventData": {"MFAUsed": "No"}, "responseElements": {"ConsoleLogin": "Success"}}))
        assert det.table.put_item.called, f"{name} toi duoc Lambda nhung khong luat nao xu ly"


def test_F3_local_and_detector_brute_force_thresholds_agree(mod, det):
    assert mod.LOCAL_BRUTE_FORCE_THRESHOLD == det.BRUTE_FORCE_THRESHOLD


NGINX = (ROOT / "sample_app" / "deploy" / "nginx.conf").read_text(encoding="utf-8")


def test_F4_nginx_access_log_never_contains_query_strings():
    """/setup-2fa?token=<bi mat>: token khong duoc nam trong access log."""
    log_format = re.search(r"log_format\s+main\s+'([^']*)'", NGINX).group(1)
    assert "$uri" in log_format
    for leaky in ("$request ", '$request"', "$request_uri", "$args", "$query_string", "$http_referer"):
        assert leaky not in log_format, leaky


def test_F5_nginx_overwrites_client_ip_headers_for_every_location():
    assert "proxy_set_header X-Real-IP         $remote_addr;" in NGINX
    assert "proxy_set_header X-Forwarded-For   $remote_addr;" in NGINX
    assert "$proxy_add_x_forwarded_for" not in NGINX      # noi them = cho phep client chen IP gia
    # proxy_set_header chi duoc ke thua khi location KHONG khai bao lai lenh nay
    for block in re.findall(r"location[^{]*\{([^}]*)\}", NGINX):
        assert "proxy_set_header" not in block and "proxy_pass http://127.0.0.1:8080;" in block


def test_F6_nginx_rate_limits_credential_endpoints_harder_than_the_rest():
    assert re.search(r"zone=authperip:\d+m\s+rate=30r/m", NGINX)
    auth_block = re.search(r"location ~ \^/\(([^)]*)\)\s*\{([^}]*)\}", NGINX)
    assert set(auth_block.group(1).split("|")) == {"login", "setup-2fa", "auth/"}
    assert "zone=authperip" in auth_block.group(2)


DIRECT = (ROOT / "sample_app" / "deploy" / "nginx-listener-direct.conf").read_text(encoding="utf-8")
EDGE = (ROOT / "sample_app" / "deploy" / "nginx-listener-edge.conf").read_text(encoding="utf-8")
BOOTSTRAP = (ROOT / "sample_app" / "deploy" / "bootstrap.sh").read_text(encoding="utf-8")


def _directives(conf: str) -> str:
    return "\n".join(l for l in conf.splitlines() if not l.strip().startswith("#"))


def test_F7_direct_mode_is_tls_12_13_only_with_no_plain_http_listener():
    assert "include /etc/nginx/logsentinel-listener.conf;" in NGINX
    assert not re.search(r"^\s*listen\s", _directives(NGINX), re.M)   # cong vao chi nam trong file include
    assert "listen 443 ssl default_server;" in DIRECT and "ssl_protocols TLSv1.2 TLSv1.3;" in DIRECT
    assert "listen 80" not in _directives(DIRECT)


def test_F8_edge_mode_origin_only_answers_our_own_cloudfront():
    """Cong 80 chi mo cho CloudFront (security group) VA phai co header bi mat: distribution la khong goi duoc."""
    conf = _directives(EDGE)
    assert "listen 80 default_server;" in conf and "ssl" not in conf
    assert re.search(r'if \(\$http_x_origin_verify != "__ORIGIN_VERIFY_SECRET__"\) \{\s*return 403;', conf)


def test_F9_edge_mode_takes_client_ip_from_the_address_cloudfront_appended():
    """real_ip_recursive off = dia chi CUOI cua X-Forwarded-For (CloudFront them), khong phai phan client tu chen."""
    conf = _directives(EDGE)
    assert "real_ip_header X-Forwarded-For;" in conf and "real_ip_recursive off;" in conf
    assert "real_ip_recursive on" not in conf


def test_F10_origin_secret_never_lands_in_a_world_readable_file_or_the_repo():
    assert EDGE.count("__ORIGIN_VERIFY_SECRET__") == 1              # repo chi chua cho giu cho, dung 1 lan
    edge_branch = BOOTSTRAP.split('if [ "${EDGE_MODE:-false}" = "true" ]; then')[1].split("else")[0]
    assert "secretsmanager get-secret-value" in edge_branch and "umask 077" in edge_branch
    assert "*[!A-Za-z0-9]*" in edge_branch                           # gia tri la khong duoc chen vao lenh sed
    assert "echo \"$ORIGIN_SECRET\"" not in BOOTSTRAP and "set -x" not in BOOTSTRAP


def test_F11_web_server_uses_threaded_workers_so_slow_aws_calls_cannot_starve_it():
    unit = (ROOT / "sample_app" / "deploy" / "webapp.service").read_text(encoding="utf-8")
    assert "--worker-class gthread" in unit and "--threads 16" in unit and "--bind 127.0.0.1:8080" in unit


# =====================================================================
# G. DIEM YEU CON LAI - he thong CHUA chong duoc (xem docs/SECURITY_REVIEW.md muc 7)
# =====================================================================
@pytest.mark.xfail(strict=True, reason="Gioi han dang ky tinh theo IP; khong co CAPTCHA/gioi han toan cuc")
def test_G3_known_gap_botnet_can_exhaust_the_daily_email_quota(acct):
    """Cognito email mac dinh ~50 thu/ngay. 60 IP, moi IP dang ky 1 lan la du lam nguoi that khong nhan duoc ma."""
    accepted = sum(post(acct, "/auth/register", {"email": f"bot{i}@x.co", "password": STRONG},
                        ip=f"203.0.{i}.1").status_code == 200 for i in range(60))
    assert accepted < 50


@pytest.mark.xfail(strict=True, reason="SOAR khoa theo IP: nguoi dung chung NAT/Wi-Fi voi ke tan cong bi khoa oan 24h")
def test_G4_known_gap_innocent_user_behind_the_same_nat_is_blocked_too(harness):
    shared_nat = "203.0.113.80"
    harness.client.get("/search?q=' OR 1=1 --", **via_nginx(shared_nat))          # ke tan cong
    assert harness.client.get("/health", **via_nginx(shared_nat)).status_code == 200   # dong nghiep vo toi


@pytest.mark.xfail(strict=True, reason="May EC2 co quyen ghi log group cua chinh no: bi chiem thi gia duoc su kien")
def test_G5_known_gap_compromised_web_server_can_forge_events_to_block_any_ip(det):
    """Detector tin moi dong trong /logsentinel/sample-app. Ke chiem duoc may web co the khoa IP bat ky."""
    det.evaluate_webapp_log(json.dumps({"event_type": "SQL_INJECTION", "client_ip": VICTIM, "source": "forged"}))
    assert VICTIM not in blocked_ips(det)
