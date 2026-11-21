"""
Xac dinh nguoi goi cho Lambda chay sau web app (Lambda thuc thi phan quyen). EC2 la noi de bi tan cong nhat nen
Lambda khong tin danh tinh EC2 khai: chi tin token Cognito, do CHINH Cognito xac nhan.

    authenticate_caller(caller, identity, local_principal) -> "cognito:<email>" | local_principal
    cognito_principal(email)                               -> "cognito:<email>"

caller = {"access_token": "<token Cognito cua nguoi bam>"} | {"local": true} (admin noi bo, khong co token:
         Lambda phan quyen chi tin trong che do khoi tao).
"""
import cognito_identity as cognito


class Unauthenticated(Exception):
    pass


def cognito_principal(email: str) -> str:
    return f"cognito:{email}"


def authenticate_caller(caller, identity, local_principal: str) -> str:
    if not isinstance(caller, dict):
        raise Unauthenticated()
    token, local = caller.get("access_token"), caller.get("local")
    if local is True and token is None:
        return local_principal
    if isinstance(token, str) and token and local is None:
        try:
            return cognito_principal(identity.whoami(token))
        except cognito.AuthFailed:
            raise Unauthenticated() from None
    raise Unauthenticated()
