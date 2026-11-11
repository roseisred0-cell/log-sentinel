"""Tai khoan Console: dang ky + do manh mat khau, dang nhap Cognito, bat/tat 2FA, vai tro, duyet nguoi dung."""
import json
import types
from pathlib import Path

import pytest

pytest.importorskip("flask")

from .test_sample_app import APP_SRC, Clock, GOOD_OTP, env, mod, via_nginx  # noqa: E402,F401  (fixture dung chung)

STRONG = "Zebra!Lamp7Quiet"
GOOD_EMAIL_CODE, GOOD_TOTP = "111111", "654321"


class FakeIdentity:
    """Cung giao dien voi CognitoIdentity, luu tren RAM. Dung chinh cac loi nghiep vu that."""

    def __init__(self, cog):
        self.cog = cog
        self.users = {}       # email -> {password, confirmed, mfa, role, username}
        self.signups, self.resends, self.approved, self.revoked, self.resets_requested = [], [], [], [], []

    def add(self, email, password=STRONG, confirmed=True, mfa=False, role="pending"):
        self.users[email] = {"password": password, "confirmed": confirmed, "mfa": mfa, "role": role,
                             "username": "uid-" + email.split("@")[0]}

    def _by_token(self, token):
        email = token.removeprefix("tok-")
        if email not in self.users:
            raise self.cog.AuthFailed("expired")
        return email, self.users[email]

    def sign_up(self, email, password):
        self.signups.append((email, password))
        if email not in self.users:
            self.add(email, password, confirmed=False)

    def confirm_sign_up(self, email, code):
        if code != GOOD_EMAIL_CODE or email not in self.users:
            raise self.cog.CodeInvalid("CodeMismatchException")
        self.users[email]["confirmed"] = True

    def resend_code(self, email):
        self.resends.append(email)

    def forgot_password(self, email):
        self.resets_requested.append(email)

    def confirm_forgot_password(self, email, code, new_password):
        if code != GOOD_EMAIL_CODE or email not in self.users:
            raise self.cog.CodeInvalid("CodeMismatchException")
        self.users[email]["password"] = new_password

    def reauthenticate(self, email, password, code):
        res = self.login(email, password)
        if res.mfa_required:
            self.complete_mfa(res.mfa_session, res.username, code)

    def _result(self, email):
        u = self.users[email]
        return self.cog.LoginResult(email=email, role=u["role"], access_token="tok-" + email)

    def login(self, email, password):
        u = self.users.get(email)
        if not u or u["password"] != password:
            raise self.cog.AuthFailed("NotAuthorizedException")
        if not u["confirmed"]:
            raise self.cog.NotConfirmed("UserNotConfirmedException")
        if u["mfa"]:
            return self.cog.LoginResult(mfa_required=True, mfa_session="SESS", username=u["username"], email=email)
        return self._result(email)

    def complete_mfa(self, session, username, code):
        email = next(e for e, u in self.users.items() if u["username"] == username)
        if code != GOOD_TOTP:
            raise self.cog.CodeInvalid("CodeMismatchException")
        return self._result(email)

    def mfa_enabled(self, token):
        return self._by_token(token)[1]["mfa"]

    def begin_mfa_setup(self, token):
        self._by_token(token)
        return "JBSWY3DPEHPK3PXP"

    def confirm_mfa_setup(self, token, code):
        _, u = self._by_token(token)
        if code != GOOD_TOTP:
            raise self.cog.CodeInvalid("VerifyFailed")
        u["mfa"] = True

    def set_mfa_disabled(self, token):
        self._by_token(token)[1]["mfa"] = False

    def list_users(self):
        out = {"pending": [], "viewers": [], "admins": []}
        for email, u in self.users.items():
            if u["confirmed"]:
                bucket = {"pending": "pending", "viewer": "viewers", "admin": "admins"}[u["role"]]
                out[bucket].append({"username": u["username"], "email": email, "created": None})
        return out

    def approve(self, username):
        for email, u in self.users.items():
            if u["username"] == username and u["role"] == "pending" and u["confirmed"]:
                u["role"] = "viewer"
                self.approved.append(email)
                return email
        return None

    def revoke(self, username):
        for email, u in self.users.items():
            if u["username"] == username and u["role"] == "viewer":
                u["role"] = "pending"
                self.revoked.append(email)
                return email
        return None


@pytest.fixture
def acct(mod, env):
    import cognito_identity as cog  # sample_app da nam tren sys.path nho fixture `mod`
    clock, store_calls = Clock(), []
    identity = FakeIdentity(cog)

    class Store:
        unblocked = []

        def recent_incidents(self, limit=50):
            return []

        def active_blocks(self, now):
            return []

        def unblock(self, ip):
            self.unblocked.append(ip)

    store = Store()
    bl = mod.BlockList(lambda ip: None, clock=clock, negative_ttl=5)
    app = mod.create_app(mod.load_config_from_env(env), bl, store, identity=identity, clock=clock)
    log_path = Path(env["APP_LOG_PATH"])
    return types.SimpleNamespace(
        client=app.test_client(), identity=identity, clock=clock, store=store, bl=bl,
        logs=lambda: [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()])


IP = "198.51.100.60"


def post(a, path, body=None, csrf=None, ip=IP):
    kw = via_nginx(ip)
    if csrf:
        kw["headers"]["X-CSRF-Token"] = csrf
    return a.client.post(path, json=body or {}, **kw)


def get(a, path, ip=IP):
    return a.client.get(path, **via_nginx(ip))


def sign_in(a, email, password=STRONG, ip=IP):
    r = post(a, "/auth/login", {"email": email, "password": password}, ip=ip)
    assert r.status_code == 200, r.get_json()
    return get(a, "/api/session", ip=ip).get_json()["csrf"]


def local_admin(a, ip=IP):
    r = a.client.post("/login", data={"username": "admin", "password": "S3cure-Pass", "otp": GOOD_OTP}, **via_nginx(ip))
    assert r.status_code == 200
    return get(a, "/api/session", ip=ip).get_json()["csrf"]


# ----------------------------------------------------------- cau hinh
def test_config_reports_cognito_and_min_level(acct):
    assert get(acct, "/api/config").get_json() == {"cognito": True, "min_password_level": 2}


def test_without_cognito_registration_endpoints_do_not_exist(mod, env):
    app = mod.create_app(mod.load_config_from_env(env), mod.BlockList(lambda ip: None), object())
    c = app.test_client()
    assert c.get("/api/config", **via_nginx(IP)).get_json()["cognito"] is False
    for path in ("/auth/register", "/auth/login", "/auth/confirm", "/auth/resend", "/auth/mfa"):
        assert c.post(path, json={}, **via_nginx(IP)).status_code == 404


def test_cognito_ids_read_from_environment(mod, env):
    env.update(COGNITO_USER_POOL_ID="ap-southeast-1_abc", COGNITO_CLIENT_ID="cid")
    cfg = mod.load_config_from_env(env)
    assert (cfg.cognito_user_pool_id, cfg.cognito_client_id) == ("ap-southeast-1_abc", "cid")


# ------------------------------------------------------------ dang ky
@pytest.mark.parametrize("password", ["", "short1A", "password", "Password123!", "Abcd1234", "Hello12345"])
def test_register_rejects_weak_passwords_before_calling_cognito(acct, password):
    r = post(acct, "/auth/register", {"email": "new@x.co", "password": password})
    assert r.status_code == 400 and r.get_json()["error"] == "weak_password"
    assert acct.identity.signups == []


def test_register_rejects_password_containing_email_name(acct):
    r = post(acct, "/auth/register", {"email": "tuanpham@x.co", "password": "Tuanpham2024"})
    assert r.status_code == 400 and acct.identity.signups == []


@pytest.mark.parametrize("email", ["", "no-at-sign", "a@b", "a b@x.co", None, 123, "x" * 300 + "@x.co"])
def test_register_rejects_bad_email(acct, email):
    r = post(acct, "/auth/register", {"email": email, "password": STRONG})
    assert r.status_code == 400 and r.get_json()["error"] == "invalid_email"


def test_register_ok_never_logs_password_and_normalizes_email(acct):
    r = post(acct, "/auth/register", {"email": "  New@X.co ", "password": STRONG})
    assert r.status_code == 200
    assert acct.identity.signups == [("new@x.co", STRONG)]
    assert STRONG not in json.dumps(acct.logs()) and acct.logs()[-1]["event_type"] == "REGISTER_REQUEST"


def test_register_answer_is_identical_for_existing_email(acct):
    acct.identity.add("old@x.co")
    assert post(acct, "/auth/register", {"email": "old@x.co", "password": STRONG}).get_json() == {"ok": True}


def test_register_is_rate_limited_per_ip(acct):
    codes = [post(acct, "/auth/register", {"email": f"u{i}@x.co", "password": STRONG}).status_code for i in range(7)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429, 429]
    assert post(acct, "/auth/register", {"email": "z@x.co", "password": STRONG}, ip="198.51.100.61").status_code == 200
    acct.clock.t += 601
    assert post(acct, "/auth/register", {"email": "z2@x.co", "password": STRONG}).status_code == 200


def test_confirm_email_flow_and_wrong_code(acct):
    post(acct, "/auth/register", {"email": "new@x.co", "password": STRONG})
    assert post(acct, "/auth/login", {"email": "new@x.co", "password": STRONG}).get_json() == {"error": "not_confirmed"}
    assert post(acct, "/auth/confirm", {"email": "new@x.co", "code": "000000"}).status_code == 400
    assert post(acct, "/auth/confirm", {"email": "new@x.co", "code": GOOD_EMAIL_CODE}).status_code == 200
    assert acct.logs()[-1]["event_type"] == "REGISTER_CONFIRMED"


def test_confirm_code_guessing_is_rate_limited(acct):
    codes = [post(acct, "/auth/confirm", {"email": "new@x.co", "code": f"{i:06d}"}).status_code for i in range(12)]
    assert codes[:10] == [400] * 10 and codes[10:] == [429, 429]


def test_resend_is_generic_and_rate_limited(acct):
    assert post(acct, "/auth/resend", {"email": "ghost@x.co"}).get_json() == {"ok": True}
    assert post(acct, "/auth/resend", {"email": "garbage"}).status_code == 200  # khong lo dinh dang
    for _ in range(3):
        post(acct, "/auth/resend", {"email": "ghost@x.co"})
    assert post(acct, "/auth/resend", {"email": "ghost@x.co"}).status_code == 429


# ----------------------------------------------------------- dang nhap
def test_wrong_password_counts_toward_brute_force_rule(acct):
    acct.identity.add("a@x.co")
    assert post(acct, "/auth/login", {"email": "a@x.co", "password": "nope"}).status_code == 401
    entry = acct.logs()[-1]
    assert entry["event_type"] == "FAILED_LOGIN" and "nope" not in json.dumps(entry)


def test_unknown_user_looks_the_same_as_wrong_password(acct):
    r = post(acct, "/auth/login", {"email": "ghost@x.co", "password": "x"})
    assert r.status_code == 401 and r.get_json() == {"error": "unauthorized"}


@pytest.mark.parametrize("body", [{}, {"email": "a@x.co"}, {"email": "a@x.co", "password": ""},
                                  {"email": ["a@x.co"], "password": "x"}, {"email": "a@x.co", "password": "p" * 500}])
def test_malformed_login_is_401_not_500(acct, body):
    assert post(acct, "/auth/login", body).status_code == 401


def test_new_user_logs_in_as_pending_and_cannot_see_data(acct):
    acct.identity.add("a@x.co")
    sign_in(acct, "a@x.co")
    session = get(acct, "/api/session").get_json()
    assert session["role"] == "pending" and session["auth"] == "cognito"
    assert get(acct, "/api/overview").status_code == 403
    assert get(acct, "/api/users").status_code == 403


def test_access_token_never_sent_to_browser_body(acct):
    acct.identity.add("a@x.co")
    r = post(acct, "/auth/login", {"email": "a@x.co", "password": STRONG})
    assert "tok-a@x.co" not in r.get_data(as_text=True)


def test_mfa_login_has_no_session_until_otp_is_verified(acct):
    acct.identity.add("a@x.co", mfa=True, role="viewer")
    r = post(acct, "/auth/login", {"email": "a@x.co", "password": STRONG})
    assert r.get_json() == {"ok": True, "mfa_required": True}
    assert get(acct, "/api/session").status_code == 401 and get(acct, "/api/overview").status_code == 401
    assert post(acct, "/auth/mfa", {"code": GOOD_TOTP}).status_code == 200
    assert get(acct, "/api/overview").status_code == 200


def test_wrong_otp_is_critical_and_blocks_the_ip_like_admin_flow(acct):
    acct.identity.add("a@x.co", mfa=True, role="viewer")
    post(acct, "/auth/login", {"email": "a@x.co", "password": STRONG})
    r = post(acct, "/auth/mfa", {"code": "000000"})
    entry = acct.logs()[-1]
    assert r.status_code == 403 and entry["event_type"] == "MFA_BYPASS_ATTEMPT" and entry["severity"] == "CRITICAL"
    assert "000000" not in json.dumps(entry)
    assert get(acct, "/health").status_code == 403  # IP bi khoa ngay


def test_mfa_without_pending_login_or_after_expiry_is_401(acct):
    assert post(acct, "/auth/mfa", {"code": GOOD_TOTP}).status_code == 401
    acct.identity.add("a@x.co", mfa=True, role="viewer")
    post(acct, "/auth/login", {"email": "a@x.co", "password": STRONG})
    acct.clock.t += 171
    assert post(acct, "/auth/mfa", {"code": GOOD_TOTP}).status_code == 401


def test_cognito_session_is_absolute_30_minutes(acct):
    acct.identity.add("a@x.co", role="viewer")
    sign_in(acct, "a@x.co")
    assert get(acct, "/api/overview").status_code == 200
    acct.clock.t += 31 * 60  # dang hoat dong van phai dang nhap lai -> thu hoi quyen co hieu luc
    assert get(acct, "/api/overview").status_code == 401


# ------------------------------------------------------------------ 2FA
def test_user_can_enable_then_disable_2fa(acct):
    acct.identity.add("a@x.co", role="viewer")
    csrf = sign_in(acct, "a@x.co")
    assert get(acct, "/api/account").get_json()["mfa_enabled"] is False

    setup = post(acct, "/api/mfa/setup", csrf=csrf).get_json()
    assert setup["secret"] == "JBSWY3DPEHPK3PXP" and setup["otpauth_uri"].startswith("otpauth://totp/LogSentinel:")

    assert post(acct, "/api/mfa/enable", {"code": "000000"}, csrf=csrf).status_code == 400
    assert get(acct, "/api/account").get_json()["mfa_enabled"] is False
    assert post(acct, "/api/mfa/enable", {"code": GOOD_TOTP}, csrf=csrf).status_code == 200
    assert get(acct, "/api/account").get_json()["mfa_enabled"] is True
    assert acct.logs()[-1]["event_type"] == "MFA_ENABLED"

    assert post(acct, "/api/mfa/disable", {"password": STRONG, "code": GOOD_TOTP}, csrf=csrf).status_code == 200
    assert get(acct, "/api/account").get_json()["mfa_enabled"] is False
    assert acct.logs()[-1]["event_type"] == "MFA_DISABLED" and acct.logs()[-1]["username"] == "a@x.co"


def test_pending_user_can_manage_2fa_before_approval(acct):
    acct.identity.add("a@x.co")
    csrf = sign_in(acct, "a@x.co")
    assert post(acct, "/api/mfa/enable", {"code": GOOD_TOTP}, csrf=csrf).status_code == 200


@pytest.mark.parametrize("path", ["/api/mfa/setup", "/api/mfa/enable", "/api/mfa/disable"])
def test_mfa_changes_require_csrf_and_login(acct, path):
    assert post(acct, path).status_code == 401
    acct.identity.add("a@x.co", mfa=True, role="viewer")
    post(acct, "/auth/login", {"email": "a@x.co", "password": STRONG})
    post(acct, "/auth/mfa", {"code": GOOD_TOTP})
    body = {"password": STRONG, "code": GOOD_TOTP}  # day du thong tin xac minh nhung thieu CSRF
    assert post(acct, path, body).status_code == 403
    assert post(acct, path, body, csrf="wrong").status_code == 403
    assert acct.identity.users["a@x.co"]["mfa"] is True


# ----------------------------------------- tat 2FA phai xac minh lai
def _viewer_with_2fa(acct):
    acct.identity.add("a@x.co", mfa=True, role="viewer")
    post(acct, "/auth/login", {"email": "a@x.co", "password": STRONG})
    post(acct, "/auth/mfa", {"code": GOOD_TOTP})
    return get(acct, "/api/session").get_json()["csrf"]


@pytest.mark.parametrize("body", [{}, {"password": STRONG}, {"code": GOOD_TOTP}, {"password": "", "code": GOOD_TOTP},
                                  {"password": ["x"], "code": GOOD_TOTP}, {"password": "p" * 500, "code": GOOD_TOTP}])
def test_disable_2fa_needs_password_and_otp(acct, body):
    csrf = _viewer_with_2fa(acct)
    r = post(acct, "/api/mfa/disable", body, csrf=csrf)
    assert r.status_code == 400 and r.get_json()["error"] == "reauth_required"
    assert acct.identity.users["a@x.co"]["mfa"] is True


@pytest.mark.parametrize("password,code", [("wrong-Password-1", GOOD_TOTP), (STRONG, "000000")])
def test_disable_2fa_with_wrong_password_or_otp_is_refused_and_counted(acct, password, code):
    csrf = _viewer_with_2fa(acct)
    r = post(acct, "/api/mfa/disable", {"password": password, "code": code}, csrf=csrf)
    assert r.status_code == 403 and r.get_json()["error"] == "reauth_failed"
    assert acct.identity.users["a@x.co"]["mfa"] is True
    entry = acct.logs()[-1]
    assert entry["event_type"] == "FAILED_LOGIN" and entry["reason"] == "Invalid re-authentication"
    assert password not in json.dumps(entry) and code not in json.dumps(entry)
    assert get(acct, "/api/session").status_code == 200  # van dang nhap, chi bi tu choi thao tac


def test_repeated_failed_disable_attempts_feed_the_brute_force_rule(acct):
    csrf = _viewer_with_2fa(acct)
    for _ in range(5):
        post(acct, "/api/mfa/disable", {"password": STRONG, "code": "000000"}, csrf=csrf)
    failed = [e for e in acct.logs() if e["event_type"] == "FAILED_LOGIN"]
    assert len(failed) == 5  # Detector se dem 5 lan / 60s -> BRUTE_FORCE_DETECTED + khoa IP


def test_stolen_session_cannot_switch_2fa_off(acct):
    """Ke co cookie phien nhung khong co mat khau/OTP: khong tat duoc 2FA."""
    csrf = _viewer_with_2fa(acct)
    for body in ({"password": "guess", "code": GOOD_TOTP}, {"password": STRONG, "code": "123123"}):
        assert post(acct, "/api/mfa/disable", body, csrf=csrf).status_code == 403
    assert get(acct, "/api/account").get_json()["mfa_enabled"] is True


# ------------------------------------------------------ quen mat khau
def test_forgot_password_response_is_identical_for_known_and_unknown_email(acct):
    acct.identity.add("a@x.co")
    known = post(acct, "/auth/forgot", {"email": "a@x.co"})
    unknown = post(acct, "/auth/forgot", {"email": "ghost@x.co"})
    assert known.status_code == unknown.status_code == 200 and known.get_json() == unknown.get_json() == {"ok": True}


def test_forgot_password_ignores_garbage_email_without_calling_cognito(acct):
    assert post(acct, "/auth/forgot", {"email": "not-an-email"}).status_code == 200
    assert post(acct, "/auth/forgot", {"email": ["a@x.co"]}).status_code == 200
    assert acct.identity.resets_requested == []


def test_forgot_password_is_audited_and_normalizes_email(acct):
    post(acct, "/auth/forgot", {"email": "  A@X.co "})
    assert acct.identity.resets_requested == ["a@x.co"]
    assert acct.logs()[-1]["event_type"] == "PASSWORD_RESET_REQUEST"


def test_forgot_password_is_rate_limited_per_ip(acct):
    codes = [post(acct, "/auth/forgot", {"email": "a@x.co"}).status_code for _ in range(7)]
    assert codes == [200] * 5 + [429, 429]
    assert post(acct, "/auth/forgot", {"email": "a@x.co"}, ip="198.51.100.62").status_code == 200


def test_reset_password_with_code_lets_user_log_in_with_new_password(acct):
    acct.identity.add("a@x.co", password="Old-Password-1!x")
    new = "Brand!New7Quiet"
    r = post(acct, "/auth/reset", {"email": "a@x.co", "code": GOOD_EMAIL_CODE, "password": new})
    assert r.status_code == 200
    entry = acct.logs()[-1]
    assert entry["event_type"] == "PASSWORD_RESET_DONE" and new not in json.dumps(acct.logs())
    assert post(acct, "/auth/login", {"email": "a@x.co", "password": "Old-Password-1!x"}).status_code == 401
    assert post(acct, "/auth/login", {"email": "a@x.co", "password": new}).status_code == 200


def test_reset_with_wrong_code_does_not_change_password(acct):
    acct.identity.add("a@x.co")
    r = post(acct, "/auth/reset", {"email": "a@x.co", "code": "000000", "password": "Brand!New7Quiet"})
    assert r.status_code == 400 and r.get_json()["error"] == "invalid_code"
    assert acct.identity.users["a@x.co"]["password"] == STRONG


@pytest.mark.parametrize("password", ["", "short1A", "Password123!", "Hello12345", None, 42])
def test_reset_enforces_password_strength_server_side(acct, password):
    acct.identity.add("a@x.co")
    r = post(acct, "/auth/reset", {"email": "a@x.co", "code": GOOD_EMAIL_CODE, "password": password})
    assert r.status_code == 400 and r.get_json()["error"] == "weak_password"
    assert acct.identity.users["a@x.co"]["password"] == STRONG


@pytest.mark.parametrize("body", [{}, {"email": "a@x.co"}, {"code": "111111"}, {"email": "bad", "code": "111111"}])
def test_reset_missing_fields_is_invalid_code(acct, body):
    r = post(acct, "/auth/reset", {**body, "password": "Brand!New7Quiet"})
    assert r.status_code == 400 and r.get_json()["error"] == "invalid_code"


def test_reset_code_guessing_is_rate_limited(acct):
    acct.identity.add("a@x.co")
    codes = [post(acct, "/auth/reset", {"email": "a@x.co", "code": f"{i:06d}", "password": "Brand!New7Quiet"}).status_code
             for i in range(12)]
    assert codes[:10] == [400] * 10 and codes[10:] == [429, 429]


def test_reset_rejects_password_containing_email_name(acct):
    acct.identity.add("tuanpham@x.co")
    r = post(acct, "/auth/reset", {"email": "tuanpham@x.co", "code": GOOD_EMAIL_CODE, "password": "Tuanpham2024"})
    assert r.status_code == 400


def test_forgot_and_reset_do_not_exist_without_cognito(mod, env):
    app = mod.create_app(mod.load_config_from_env(env), mod.BlockList(lambda ip: None), object())
    for path in ("/auth/forgot", "/auth/reset"):
        assert app.test_client().post(path, json={}, **via_nginx(IP)).status_code == 404


def test_expired_access_token_forces_relogin(acct):
    acct.identity.add("a@x.co", role="viewer")
    csrf = sign_in(acct, "a@x.co")
    del acct.identity.users["a@x.co"]  # Cognito khong con chap nhan token
    assert post(acct, "/api/mfa/setup", csrf=csrf).status_code == 401
    assert get(acct, "/api/session").status_code == 401


def test_internal_admin_2fa_is_mandatory_and_not_togglable(acct):
    csrf = local_admin(acct)
    info = get(acct, "/api/account").get_json()
    assert info["auth"] == "local" and info["mfa_enabled"] is True
    for path in ("/api/mfa/setup", "/api/mfa/enable", "/api/mfa/disable"):
        r = post(acct, path, {"code": GOOD_TOTP}, csrf=csrf)
        assert r.status_code == 400 and r.get_json()["error"] == "mfa_managed_locally"


# --------------------------------------------------- vai tro & duyet
def test_viewer_sees_data_but_cannot_unblock_or_manage_users(acct):
    acct.identity.add("v@x.co", role="viewer")
    acct.identity.add("p@x.co")
    csrf = sign_in(acct, "v@x.co")
    assert get(acct, "/api/overview").status_code == 200
    assert post(acct, "/api/unblock", {"ip": "203.0.113.5"}, csrf=csrf).status_code == 403
    assert acct.store.unblocked == []
    assert get(acct, "/api/users").status_code == 403
    assert post(acct, "/api/users/approve", {"username": "uid-p"}, csrf=csrf).status_code == 403
    assert acct.identity.approved == []


def test_cognito_admin_can_unblock_and_list_users(acct):
    acct.identity.add("boss@x.co", role="admin")
    csrf = sign_in(acct, "boss@x.co")
    assert post(acct, "/api/unblock", {"ip": "203.0.113.5"}, csrf=csrf).status_code == 200
    assert get(acct, "/api/users").status_code == 200


def test_admin_approves_pending_user_and_it_is_audited(acct):
    acct.identity.add("p@x.co")
    csrf = local_admin(acct)
    assert [u["email"] for u in get(acct, "/api/users").get_json()["pending"]] == ["p@x.co"]
    assert post(acct, "/api/users/approve", {"username": "uid-p"}, csrf=csrf).status_code == 200
    audit = acct.logs()[-1]
    assert audit["event_type"] == "USER_APPROVED" and audit["target_user"] == "p@x.co" and audit["username"] == "admin"
    # lan dang nhap sau, nguoi do da la viewer
    other = "198.51.100.77"
    sign_in(acct, "p@x.co", ip=other)
    assert get(acct, "/api/session", ip=other).get_json()["role"] == "viewer"


def test_approve_requires_csrf_and_unknown_user_is_404(acct):
    acct.identity.add("p@x.co")
    csrf = local_admin(acct)
    assert post(acct, "/api/users/approve", {"username": "uid-p"}).status_code == 403
    assert post(acct, "/api/users/approve", {"username": "uid-ghost"}, csrf=csrf).status_code == 404
    assert post(acct, "/api/users/approve", {}, csrf=csrf).status_code == 404
    assert acct.identity.approved == []


def test_revoke_returns_user_to_pending(acct):
    acct.identity.add("v@x.co", role="viewer")
    csrf = local_admin(acct)
    assert post(acct, "/api/users/revoke", {"username": "uid-v"}, csrf=csrf).status_code == 200
    assert acct.logs()[-1]["event_type"] == "USER_REVOKED"
    assert acct.identity.users["v@x.co"]["role"] == "pending"


def test_internal_admin_keeps_full_access(acct):
    csrf = local_admin(acct)
    assert get(acct, "/api/session").get_json()["role"] == "admin"
    assert get(acct, "/api/overview").status_code == 200
    assert post(acct, "/api/unblock", {"ip": "203.0.113.5"}, csrf=csrf).status_code == 200


# -------------------------------------------------------- ma nguon giao dien
def test_new_scripts_never_use_innerhtml_or_eval():
    for name in ("console.js", "password-strength.js"):
        js = (Path(APP_SRC) / "static" / name).read_text(encoding="utf-8")
        code = "\n".join(l for l in js.splitlines() if not l.strip().startswith("//"))
        assert "innerHTML" not in code and "document.write" not in code and "eval(" not in code, name


def test_console_page_loads_scripts_from_own_origin(acct):
    html = get(acct, "/console").get_data(as_text=True)
    assert "/static/password-strength.js" in html and "/static/console.js" in html
    assert "http://" not in html and "https://" not in html  # khong nap tai nguyen ben ngoai (CSP default-src 'self')
