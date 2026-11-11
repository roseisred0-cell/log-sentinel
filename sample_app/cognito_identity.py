"""
Cua so duy nhat toi Amazon Cognito (user pool) cho SOC Console.

Giao dien nho, che giau boto3 va ma loi cua Cognito:
    sign_up / confirm_sign_up / resend_code        - dang ky tai khoan, xac nhan email
    forgot_password / confirm_forgot_password      - quen mat khau (ma qua email)
    login / complete_mfa / reauthenticate          - dang nhap (co the yeu cau ma TOTP), xac minh lai truoc thao tac nhay cam
    mfa_enabled / begin_mfa_setup / confirm_mfa_setup / set_mfa_disabled   - bat/tat 2FA cua chinh nguoi dung
    list_users / approve / revoke                  - quan tri duyet nguoi dung (nhom Cognito)

Vai tro suy ra tu nhom Cognito:  soc-admins -> "admin",  soc-viewers -> "viewer",  khong nhom -> "pending".
Ngoai le cua module nay khong mang thong tin nhay cam; tang tren chi can biet LOAI loi.

Ghi chu bao mat:
  - Cac API dang ky/dang nhap cua Cognito la API cong khai (khong can chu ky IAM) -> dung client UNSIGNED,
    nen quyen IAM cua EC2 khong anh huong luong nguoi dung.
  - Chi cac thao tac quan tri (ListUsers, AdminAddUserToGroup...) dung quyen IAM cua EC2, gioi han theo user pool.
"""
import base64
import json
from dataclasses import dataclass
from typing import Optional

ADMIN_GROUP = "soc-admins"
VIEWER_GROUP = "soc-viewers"


# ------------------------------------------------------------------ errors
class IdentityError(Exception):
    """Goc cua moi loi nghiep vu. Khong chua mat khau / token."""


class AuthFailed(IdentityError):
    """Sai tai khoan/mat khau, token het han, hoac phien MFA het han."""


class NotConfirmed(IdentityError):
    """Tai khoan chua xac nhan email."""


class CodeInvalid(IdentityError):
    """Ma xac nhan email hoac ma TOTP sai/het han."""


class PasswordRejected(IdentityError):
    """Cognito tu choi mat khau (khong dat chinh sach)."""


class RateLimited(IdentityError):
    """Cognito gioi han toc do."""


class UnsupportedChallenge(IdentityError):
    """Thu thach dang nhap ma console chua ho tro (vd NEW_PASSWORD_REQUIRED)."""


class UpstreamError(IdentityError):
    """Loi khac tu Cognito / mang."""


_CODE_TO_ERROR = {
    "NotAuthorizedException": AuthFailed,
    "UserNotFoundException": AuthFailed,
    "PasswordResetRequiredException": AuthFailed,
    "UserNotConfirmedException": NotConfirmed,
    "CodeMismatchException": CodeInvalid,
    "ExpiredCodeException": CodeInvalid,
    "EnableSoftwareTokenMFAException": CodeInvalid,
    "InvalidPasswordException": PasswordRejected,
    "TooManyRequestsException": RateLimited,
    "LimitExceededException": RateLimited,
    "TooManyFailedAttemptsException": RateLimited,
}


# Ma loi ma ta nuot di khi nguoi dung chua dang nhap, de khong lo email nao da dang ky.
_SILENT_FOR_ENUMERATION = frozenset(("UserNotFoundException", "InvalidParameterException", "NotAuthorizedException"))


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


def _translate(exc: Exception) -> IdentityError:
    code = _error_code(exc)
    return _CODE_TO_ERROR.get(code, UpstreamError)(code or type(exc).__name__)


# ------------------------------------------------------------------ results
@dataclass(frozen=True)
class LoginResult:
    mfa_required: bool = False
    mfa_session: str = ""     # chi dung de tra loi thu thach MFA, het han sau ~3 phut
    username: str = ""        # dinh danh Cognito (UUID) dung cho thu thach MFA
    email: str = ""
    role: str = ""            # "admin" | "viewer" | "pending"
    access_token: str = ""


def _claims(id_token: str) -> dict:
    """Doc payload ID token. Token nhan TRUC TIEP tu Cognito qua TLS nen khong can kiem chu ky o day."""
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data if isinstance(data, dict) else {}
    except (IndexError, ValueError):
        return {}


def role_from_groups(groups) -> str:
    groups = set(groups or [])
    if ADMIN_GROUP in groups:
        return "admin"
    if VIEWER_GROUP in groups:
        return "viewer"
    return "pending"


def totp_uri(email: str, secret: str, issuer: str = "LogSentinel") -> str:
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(email)}?secret={secret}&issuer={quote(issuer)}"


# ------------------------------------------------------------------ gateway
class CognitoIdentity:
    def __init__(self, user_pool_id: str, client_id: str, region: str,
                 public_client=None, admin_client=None):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.region = region
        self._public = public_client
        self._admin = admin_client

    # boto3 import tre: test khong can boto3
    def _public_client(self):
        if self._public is None:
            import boto3
            from botocore import UNSIGNED
            from botocore.config import Config
            self._public = boto3.client("cognito-idp", region_name=self.region,
                                        config=Config(signature_version=UNSIGNED))
        return self._public

    def _admin_client(self):
        if self._admin is None:
            import boto3
            self._admin = boto3.client("cognito-idp", region_name=self.region)
        return self._admin

    @staticmethod
    def _call(fn, **kwargs):
        try:
            return fn(**kwargs)
        except IdentityError:
            raise
        except Exception as exc:  # botocore.exceptions.ClientError va loi mang
            raise _translate(exc) from None

    # ------------------------------------------------------------ dang ky
    def sign_up(self, email: str, password: str) -> None:
        """Ton tai roi -> im lang (khong lo email nao da dang ky)."""
        try:
            self._public_client().sign_up(
                ClientId=self.client_id, Username=email, Password=password,
                UserAttributes=[{"Name": "email", "Value": email}])
        except Exception as exc:
            if _error_code(exc) == "UsernameExistsException":
                return
            raise _translate(exc) from None

    def confirm_sign_up(self, email: str, code: str) -> None:
        self._call(self._public_client().confirm_sign_up,
                   ClientId=self.client_id, Username=email, ConfirmationCode=code)

    def resend_code(self, email: str) -> None:
        """Luon thanh cong ve mat hien thi (chong do email); chi bao loi khi bi gioi han toc do."""
        try:
            self._public_client().resend_confirmation_code(ClientId=self.client_id, Username=email)
        except Exception as exc:
            err = _translate(exc)
            if isinstance(err, RateLimited):
                raise err from None

    # ------------------------------------------------------ quen mat khau
    def forgot_password(self, email: str) -> None:
        """Gui ma dat lai mat khau qua email. Email la / chua xac nhan -> im lang (chong do email)."""
        try:
            self._public_client().forgot_password(ClientId=self.client_id, Username=email)
        except Exception as exc:
            if _error_code(exc) in _SILENT_FOR_ENUMERATION:
                return
            raise _translate(exc) from None

    def confirm_forgot_password(self, email: str, code: str, new_password: str) -> None:
        self._call(self._public_client().confirm_forgot_password,
                   ClientId=self.client_id, Username=email, ConfirmationCode=code, Password=new_password)

    # ---------------------------------------------------------- dang nhap
    def reauthenticate(self, email: str, password: str, code: str) -> None:
        """
        Xac minh lai nguoi dung truoc thao tac nhay cam (vd tat 2FA): dang nhap lai bang mat khau va,
        neu 2FA dang bat, tra loi thu thach TOTP. Cognito khong cho kiem tra rieng ma TOTP nen phai di
        qua luong dang nhap. Nem AuthFailed / CodeInvalid / NotConfirmed / RateLimited khi that bai.
        """
        res = self.login(email, password)
        if res.mfa_required:
            self.complete_mfa(res.mfa_session, res.username, code)

    def login(self, email: str, password: str) -> LoginResult:
        res = self._call(self._public_client().initiate_auth,
                         ClientId=self.client_id, AuthFlow="USER_PASSWORD_AUTH",
                         AuthParameters={"USERNAME": email, "PASSWORD": password})
        return self._result(res, fallback_email=email)

    def complete_mfa(self, mfa_session: str, username: str, code: str) -> LoginResult:
        res = self._call(self._public_client().respond_to_auth_challenge,
                         ClientId=self.client_id, ChallengeName="SOFTWARE_TOKEN_MFA", Session=mfa_session,
                         ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": code})
        return self._result(res, fallback_email="")

    def _result(self, res: dict, fallback_email: str) -> LoginResult:
        challenge = res.get("ChallengeName")
        if challenge == "SOFTWARE_TOKEN_MFA":
            params = res.get("ChallengeParameters") or {}
            return LoginResult(mfa_required=True, mfa_session=res.get("Session", ""),
                               username=params.get("USER_ID_FOR_SRP", ""), email=fallback_email)
        if challenge:
            raise UnsupportedChallenge(challenge)
        auth = res.get("AuthenticationResult") or {}
        if not auth.get("AccessToken"):
            raise UpstreamError("NoAuthenticationResult")
        claims = _claims(auth.get("IdToken", ""))
        return LoginResult(email=claims.get("email") or fallback_email,
                           role=role_from_groups(claims.get("cognito:groups")),
                           access_token=auth["AccessToken"])

    # --------------------------------------------------------------- 2FA
    def mfa_enabled(self, access_token: str) -> bool:
        res = self._call(self._public_client().get_user, AccessToken=access_token)
        return "SOFTWARE_TOKEN_MFA" in (res.get("UserMFASettingList") or [])

    def begin_mfa_setup(self, access_token: str) -> str:
        res = self._call(self._public_client().associate_software_token, AccessToken=access_token)
        secret = res.get("SecretCode", "")
        if not secret:
            raise UpstreamError("NoSecretCode")
        return secret

    def confirm_mfa_setup(self, access_token: str, code: str) -> None:
        res = self._call(self._public_client().verify_software_token,
                         AccessToken=access_token, UserCode=code, FriendlyDeviceName="LogSentinel")
        if res.get("Status") != "SUCCESS":
            raise CodeInvalid("VerifyFailed")
        self._call(self._public_client().set_user_mfa_preference, AccessToken=access_token,
                   SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True})

    def set_mfa_disabled(self, access_token: str) -> None:
        self._call(self._public_client().set_user_mfa_preference, AccessToken=access_token,
                   SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False})

    # ------------------------------------------------------- quan tri duyet
    def _users_in_group(self, group: str) -> set:
        names, token = set(), None
        for _ in range(10):
            kwargs = {"UserPoolId": self.user_pool_id, "GroupName": group, "Limit": 60}
            if token:
                kwargs["NextToken"] = token
            res = self._call(self._admin_client().list_users_in_group, **kwargs)
            names.update(u["Username"] for u in res.get("Users", []))
            token = res.get("NextToken")
            if not token:
                break
        return names

    def list_users(self) -> dict:
        admins, viewers = self._users_in_group(ADMIN_GROUP), self._users_in_group(VIEWER_GROUP)
        out = {"pending": [], "viewers": [], "admins": []}
        token = None
        for _ in range(10):
            kwargs = {"UserPoolId": self.user_pool_id, "Limit": 60}
            if token:
                kwargs["NextToken"] = token
            res = self._call(self._admin_client().list_users, **kwargs)
            for u in res.get("Users", []):
                if u.get("UserStatus") != "CONFIRMED" or not u.get("Enabled", True):
                    continue
                email = next((a["Value"] for a in u.get("Attributes", []) if a["Name"] == "email"), "")
                created = u.get("UserCreateDate")
                row = {"username": u["Username"], "email": email,
                       "created": created.isoformat() if hasattr(created, "isoformat") else None}
                bucket = "admins" if u["Username"] in admins else "viewers" if u["Username"] in viewers else "pending"
                out[bucket].append(row)
            token = res.get("NextToken")
            if not token:
                break
        return out

    def approve(self, username: str) -> Optional[str]:
        """Chi duyet nguoi dang CHO DUYET (khong tu y them ai do vao nhom). Tra ve email, hoac None."""
        match = next((u for u in self.list_users()["pending"] if u["username"] == username), None)
        if not match:
            return None
        self._call(self._admin_client().admin_add_user_to_group,
                   UserPoolId=self.user_pool_id, Username=username, GroupName=VIEWER_GROUP)
        return match["email"]

    def revoke(self, username: str) -> Optional[str]:
        """Chi thu hoi nguoi xem. Nhom admin chi doi duoc bang AWS CLI/Console, khong qua web app."""
        match = next((u for u in self.list_users()["viewers"] if u["username"] == username), None)
        if not match:
            return None
        self._call(self._admin_client().admin_remove_user_from_group,
                   UserPoolId=self.user_pool_id, Username=username, GroupName=VIEWER_GROUP)
        return match["email"]
