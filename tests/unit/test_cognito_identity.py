"""CognitoIdentity: anh xa loi Cognito -> loi nghiep vu, vai tro tu nhom, duyet nguoi dung. Khong can AWS/boto3."""
import base64
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "sample_app"
_spec = importlib.util.spec_from_file_location("cognito_identity_under_test", SRC / "cognito_identity.py")
ci = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci)


class AwsError(Exception):
    """Giong botocore ClientError: chi can thuoc tinh .response."""

    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def id_token(**claims):
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.sig"


class FakeClient:
    """Ghi lai loi goi; tra ve du lieu da dat san hoac nem loi da dat san."""

    def __init__(self):
        self.calls, self.results, self.errors = [], {}, {}

    def __getattr__(self, name):
        def call(**kwargs):
            self.calls.append((name, kwargs))
            if name in self.errors:
                raise AwsError(self.errors[name])
            return self.results.get(name, {})
        return call


@pytest.fixture
def pub():
    return FakeClient()


@pytest.fixture
def adm():
    return FakeClient()


@pytest.fixture
def idp(pub, adm):
    return ci.CognitoIdentity("pool-1", "client-1", "ap-southeast-1", public_client=pub, admin_client=adm)


# --------------------------------------------------------------- loi
@pytest.mark.parametrize("code,expected", [
    ("NotAuthorizedException", ci.AuthFailed), ("UserNotFoundException", ci.AuthFailed),
    ("UserNotConfirmedException", ci.NotConfirmed), ("CodeMismatchException", ci.CodeInvalid),
    ("ExpiredCodeException", ci.CodeInvalid), ("InvalidPasswordException", ci.PasswordRejected),
    ("TooManyRequestsException", ci.RateLimited), ("LimitExceededException", ci.RateLimited),
    ("InternalErrorException", ci.UpstreamError),
])
def test_cognito_errors_are_translated(idp, pub, code, expected):
    pub.errors["initiate_auth"] = code
    with pytest.raises(expected):
        idp.login("a@b.co", "pw")


def test_non_aws_exception_becomes_upstream_error_without_leaking(idp, pub):
    pub.errors = {}
    pub.initiate_auth = lambda **kw: (_ for _ in ()).throw(ConnectionError("secret-host.internal"))
    with pytest.raises(ci.UpstreamError) as err:
        idp.login("a@b.co", "pw")
    assert "secret-host" not in str(err.value)


# ------------------------------------------------------------ dang ky
def test_sign_up_sends_email_attribute_and_public_client_id(idp, pub):
    idp.sign_up("a@b.co", "Zebra!Lamp7")
    name, kw = pub.calls[-1]
    assert name == "sign_up" and kw["ClientId"] == "client-1" and kw["Username"] == "a@b.co"
    assert kw["UserAttributes"] == [{"Name": "email", "Value": "a@b.co"}]


def test_sign_up_existing_user_is_silent_to_prevent_email_enumeration(idp, pub):
    pub.errors["sign_up"] = "UsernameExistsException"
    idp.sign_up("a@b.co", "Zebra!Lamp7")  # khong nem loi


def test_resend_hides_unknown_or_confirmed_users_but_reports_throttling(idp, pub):
    for code in ("UserNotFoundException", "InvalidParameterException", "NotAuthorizedException"):
        pub.errors["resend_confirmation_code"] = code
        idp.resend_code("a@b.co")
    pub.errors["resend_confirmation_code"] = "LimitExceededException"
    with pytest.raises(ci.RateLimited):
        idp.resend_code("a@b.co")


# ----------------------------------------------------------- dang nhap
def test_login_returns_role_from_groups_in_id_token(idp, pub):
    pub.results["initiate_auth"] = {"AuthenticationResult": {
        "AccessToken": "AT", "IdToken": id_token(email="a@b.co", **{"cognito:groups": ["soc-viewers"]})}}
    res = idp.login("a@b.co", "pw")
    assert (res.email, res.role, res.access_token, res.mfa_required) == ("a@b.co", "viewer", "AT", False)
    assert pub.calls[-1][1]["AuthFlow"] == "USER_PASSWORD_AUTH"


@pytest.mark.parametrize("groups,role", [
    (None, "pending"), ([], "pending"), (["other"], "pending"),
    (["soc-viewers"], "viewer"), (["soc-admins"], "admin"), (["soc-viewers", "soc-admins"], "admin"),
])
def test_role_from_groups(groups, role):
    assert ci.role_from_groups(groups) == role


def test_garbage_id_token_means_pending_not_crash(idp, pub):
    pub.results["initiate_auth"] = {"AuthenticationResult": {"AccessToken": "AT", "IdToken": "not.a.jwt"}}
    assert idp.login("a@b.co", "pw").role == "pending"


def test_mfa_challenge_is_surfaced_with_session_and_username(idp, pub):
    pub.results["initiate_auth"] = {"ChallengeName": "SOFTWARE_TOKEN_MFA", "Session": "SESS",
                                    "ChallengeParameters": {"USER_ID_FOR_SRP": "uuid-1"}}
    res = idp.login("a@b.co", "pw")
    assert res.mfa_required and res.mfa_session == "SESS" and res.username == "uuid-1" and not res.access_token


def test_unsupported_challenge_is_rejected(idp, pub):
    pub.results["initiate_auth"] = {"ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": "S"}
    with pytest.raises(ci.UnsupportedChallenge):
        idp.login("a@b.co", "pw")


def test_complete_mfa_sends_totp_code(idp, pub):
    pub.results["respond_to_auth_challenge"] = {"AuthenticationResult": {
        "AccessToken": "AT", "IdToken": id_token(email="a@b.co")}}
    res = idp.complete_mfa("SESS", "uuid-1", "123456")
    kw = pub.calls[-1][1]
    assert kw["ChallengeName"] == "SOFTWARE_TOKEN_MFA" and kw["Session"] == "SESS"
    assert kw["ChallengeResponses"] == {"USERNAME": "uuid-1", "SOFTWARE_TOKEN_MFA_CODE": "123456"}
    assert res.access_token == "AT"


# ----------------------------------------------------------------- 2FA
def test_mfa_enabled_reads_user_mfa_settings(idp, pub):
    pub.results["get_user"] = {"UserMFASettingList": ["SOFTWARE_TOKEN_MFA"]}
    assert idp.mfa_enabled("AT") is True
    pub.results["get_user"] = {}
    assert idp.mfa_enabled("AT") is False


def test_mfa_setup_enable_and_disable_use_users_own_access_token(idp, pub):
    pub.results["associate_software_token"] = {"SecretCode": "ABCDEF"}
    assert idp.begin_mfa_setup("AT") == "ABCDEF"

    pub.results["verify_software_token"] = {"Status": "SUCCESS"}
    idp.confirm_mfa_setup("AT", "123456")
    assert pub.calls[-1][0] == "set_user_mfa_preference"
    assert pub.calls[-1][1]["SoftwareTokenMfaSettings"] == {"Enabled": True, "PreferredMfa": True}

    idp.set_mfa_disabled("AT")
    assert pub.calls[-1][1]["SoftwareTokenMfaSettings"] == {"Enabled": False, "PreferredMfa": False}
    assert all(kw["AccessToken"] == "AT" for _, kw in pub.calls)  # luon bang token cua chinh nguoi dung


def test_wrong_totp_during_setup_does_not_enable_mfa(idp, pub):
    pub.results["verify_software_token"] = {"Status": "ERROR"}
    with pytest.raises(ci.CodeInvalid):
        idp.confirm_mfa_setup("AT", "000000")
    assert all(name != "set_user_mfa_preference" for name, _ in pub.calls)


# ------------------------------------------------------ quan tri duyet
def _user(name, email, status="CONFIRMED", enabled=True):
    return {"Username": name, "UserStatus": status, "Enabled": enabled,
            "UserCreateDate": datetime(2026, 11, 11, tzinfo=timezone.utc),
            "Attributes": [{"Name": "email", "Value": email}]}


@pytest.fixture
def directory(adm):
    adm.results["list_users"] = {"Users": [
        _user("u-admin", "boss@x.co"), _user("u-view", "view@x.co"), _user("u-new", "new@x.co"),
        _user("u-unconf", "nc@x.co", status="UNCONFIRMED"), _user("u-off", "off@x.co", enabled=False)]}

    def in_group(**kw):
        adm.calls.append(("list_users_in_group", kw))
        return {"Users": {"soc-admins": [{"Username": "u-admin"}],
                          "soc-viewers": [{"Username": "u-view"}]}[kw["GroupName"]]}
    adm.list_users_in_group = in_group
    return adm


def test_list_users_buckets_and_skips_unconfirmed_or_disabled(idp, directory):
    out = idp.list_users()
    assert [u["email"] for u in out["pending"]] == ["new@x.co"]
    assert [u["email"] for u in out["viewers"]] == ["view@x.co"]
    assert [u["email"] for u in out["admins"]] == ["boss@x.co"]


def test_approve_adds_pending_user_to_viewers_group_only(idp, directory):
    assert idp.approve("u-new") == "new@x.co"
    name, kw = directory.calls[-1]
    assert name == "admin_add_user_to_group" and kw["GroupName"] == "soc-viewers" and kw["UserPoolId"] == "pool-1"


@pytest.mark.parametrize("username", ["u-admin", "u-view", "u-unconf", "u-ghost", ""])
def test_approve_refuses_anyone_not_pending(idp, directory, username):
    assert idp.approve(username) is None
    assert all(name != "admin_add_user_to_group" for name, _ in directory.calls)


def test_revoke_only_affects_viewers_never_admins(idp, directory):
    assert idp.revoke("u-view") == "view@x.co"
    assert directory.calls[-1][0] == "admin_remove_user_from_group"
    directory.calls.clear()
    assert idp.revoke("u-admin") is None and idp.revoke("u-new") is None
    assert all(name != "admin_remove_user_from_group" for name, _ in directory.calls)


# ------------------------------- xac dinh nguoi goi bang token (Lambda thuc thi phan quyen)
def test_whoami_reads_email_from_cognito_using_the_callers_own_token(idp, pub):
    pub.results["get_user"] = {"Username": "uid-a", "UserAttributes": [{"Name": "email", "Value": "A@X.co"}]}
    assert idp.whoami("tok-abc") == "a@x.co"
    assert pub.calls[-1] == ("get_user", {"AccessToken": "tok-abc"})


@pytest.mark.parametrize("code", ["NotAuthorizedException", "UserNotFoundException"])
def test_whoami_rejects_invalid_or_revoked_tokens(idp, pub, code):
    pub.errors["get_user"] = code
    with pytest.raises(ci.AuthFailed):
        idp.whoami("forged")


def test_whoami_without_email_attribute_is_auth_failure(idp, pub):
    pub.results["get_user"] = {"Username": "uid-a", "UserAttributes": []}
    with pytest.raises(ci.AuthFailed):
        idp.whoami("tok")


# ------------------------------------- phan quyen (sau khi du phieu, admin_governance)
def _writes(directory):
    return [(n, kw.get("GroupName"), kw["Username"]) for n, kw in directory.calls
            if n.startswith("admin_") and n != "admin_get_user"]


def test_promote_moves_viewer_into_admin_group_adding_before_removing(idp, directory):
    assert idp.promote("u-view") == "view@x.co"
    # them vao soc-admins TRUOC: neu lenh thu hai loi, nguoi do van co mot vai tro hop le (admin), khong bi treo
    assert _writes(directory) == [("admin_add_user_to_group", "soc-admins", "u-view"),
                                  ("admin_remove_user_from_group", "soc-viewers", "u-view")]


@pytest.mark.parametrize("username", ["u-admin", "u-new", "u-unconf", "u-ghost", ""])
def test_promote_refuses_anyone_not_a_viewer(idp, directory, username):
    assert idp.promote(username) is None and _writes(directory) == []


def test_demote_moves_admin_back_to_viewers(idp, directory):
    assert idp.demote("u-admin") == "boss@x.co"
    assert _writes(directory) == [("admin_add_user_to_group", "soc-viewers", "u-admin"),
                                  ("admin_remove_user_from_group", "soc-admins", "u-admin")]


@pytest.mark.parametrize("username", ["u-view", "u-new", "u-ghost"])
def test_demote_refuses_anyone_not_an_admin(idp, directory, username):
    assert idp.demote(username) is None and _writes(directory) == []


def test_disable_blocks_login_and_signs_out_everywhere(idp, directory):
    assert idp.disable("u-view") == "view@x.co"
    assert _writes(directory) == [("admin_disable_user", None, "u-view"), ("admin_user_global_sign_out", None, "u-view")]
    assert all(kw["UserPoolId"] == "pool-1" for n, kw in directory.calls if n.startswith("admin_"))


@pytest.mark.parametrize("username", ["u-ghost", "u-off", ""])
def test_disable_refuses_unknown_or_already_disabled_users(idp, directory, username):
    assert idp.disable(username) is None and _writes(directory) == []


def test_totp_uri_encodes_account_name():
    uri = ci.totp_uri("a+b@x.co", "SECRET")
    assert uri.startswith("otpauth://totp/LogSentinel:a%2Bb%40x.co?secret=SECRET")


# ------------------------------------------------------- quen mat khau
def test_forgot_password_uses_public_client_and_email(idp, pub):
    idp.forgot_password("a@b.co")
    name, kw = pub.calls[-1]
    assert name == "forgot_password" and kw == {"ClientId": "client-1", "Username": "a@b.co"}


def test_forgot_password_hides_unknown_or_unverified_users_but_reports_throttling_and_outages(idp, pub):
    for code in ("UserNotFoundException", "InvalidParameterException", "NotAuthorizedException"):
        pub.errors["forgot_password"] = code
        idp.forgot_password("a@b.co")  # im lang: khong lo email nao da dang ky
    pub.errors["forgot_password"] = "LimitExceededException"
    with pytest.raises(ci.RateLimited):
        idp.forgot_password("a@b.co")
    pub.errors["forgot_password"] = "InternalErrorException"
    with pytest.raises(ci.UpstreamError):  # su co that khong duoc nuot de nguoi dung biet ma khong toi
        idp.forgot_password("a@b.co")


def test_confirm_forgot_password_sends_code_and_new_password(idp, pub):
    idp.confirm_forgot_password("a@b.co", "123456", "Brand!New7Quiet")
    name, kw = pub.calls[-1]
    assert name == "confirm_forgot_password"
    assert kw == {"ClientId": "client-1", "Username": "a@b.co", "ConfirmationCode": "123456", "Password": "Brand!New7Quiet"}


@pytest.mark.parametrize("code,expected", [
    ("CodeMismatchException", ci.CodeInvalid), ("ExpiredCodeException", ci.CodeInvalid),
    ("UserNotFoundException", ci.AuthFailed), ("InvalidPasswordException", ci.PasswordRejected),
    ("TooManyFailedAttemptsException", ci.RateLimited),
])
def test_confirm_forgot_password_errors_are_translated(idp, pub, code, expected):
    pub.errors["confirm_forgot_password"] = code
    with pytest.raises(expected):
        idp.confirm_forgot_password("a@b.co", "123456", "Brand!New7Quiet")


# ----------------------------------------------- xac minh lai (tat 2FA)
def test_reauthenticate_with_2fa_checks_password_then_totp(idp, pub):
    pub.results["initiate_auth"] = {"ChallengeName": "SOFTWARE_TOKEN_MFA", "Session": "S",
                                    "ChallengeParameters": {"USER_ID_FOR_SRP": "uuid-1"}}
    pub.results["respond_to_auth_challenge"] = {"AuthenticationResult": {
        "AccessToken": "AT", "IdToken": id_token(email="a@b.co")}}
    idp.reauthenticate("a@b.co", "pw", "123456")
    assert [n for n, _ in pub.calls] == ["initiate_auth", "respond_to_auth_challenge"]
    assert pub.calls[-1][1]["ChallengeResponses"]["SOFTWARE_TOKEN_MFA_CODE"] == "123456"


def test_reauthenticate_wrong_totp_raises_code_invalid(idp, pub):
    pub.results["initiate_auth"] = {"ChallengeName": "SOFTWARE_TOKEN_MFA", "Session": "S",
                                    "ChallengeParameters": {"USER_ID_FOR_SRP": "uuid-1"}}
    pub.errors["respond_to_auth_challenge"] = "CodeMismatchException"
    with pytest.raises(ci.CodeInvalid):
        idp.reauthenticate("a@b.co", "pw", "000000")


def test_reauthenticate_wrong_password_never_reaches_the_totp_step(idp, pub):
    pub.errors["initiate_auth"] = "NotAuthorizedException"
    with pytest.raises(ci.AuthFailed):
        idp.reauthenticate("a@b.co", "bad", "123456")
    assert [n for n, _ in pub.calls] == ["initiate_auth"]
