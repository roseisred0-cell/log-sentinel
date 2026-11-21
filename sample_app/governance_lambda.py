"""
Lambda thuc thi phan quyen (nhat ky 12/11 muc 4.D1). Chi Lambda nay duoc ghi vao nhom Cognito va vao ROLE_REQ#;
EC2 (noi chay web app, de bi tan cong nhat) chi goi Lambda va doc ket qua.

    execute(event, governance, identity) -> {"ok": True, "result": ...} | {"error": code, "http": n[, "outcome"]}
    handler(event, context)              -> diem vao AWS Lambda (dung Governance + CognitoIdentity + DynamoDB that)

event = {"op": "create" | "vote" | "approve_viewer" | "revoke_viewer", "caller": {...}, ...tham so}
caller = {"access_token": "<token Cognito cua nguoi bam>"}  - Lambda tu hoi Cognito chu token la ai
       | {"local": true}                                     - admin noi bo: chi duoc tin trong che do khoi tao

Moi truong danh tinh khac trong event (vd "principal") deu bi bo qua: EC2 bi chiem khong gia danh duoc ai.
Gioi han: EC2 bi chiem dung luc mot admin dang nhap thi lay duoc token cua admin do (xem SECURITY_REVIEW.md).
"""
import json
import os

import admin_governance as gm
import cognito_identity as cognito
from caller_auth import Unauthenticated, authenticate_caller


def _manage_viewer(governance, identity, caller: str, op: str, username) -> str:
    governance.ensure_may_manage_viewers(caller)
    if not isinstance(username, str) or not username:
        raise gm.RequestNotFound()
    email = identity.approve(username[:128]) if op == "approve_viewer" else identity.revoke(username[:128])
    if not email:
        raise gm.RequestNotFound()
    return email


def execute(event, governance, identity) -> dict:
    if not isinstance(event, dict):
        return {"error": "invalid_request", "http": 400}
    try:
        # admin noi bo ({"local": true}): Governance chi cho bo phieu trong che do khoi tao
        caller = authenticate_caller(event.get("caller"), identity, governance.local_principal)
    except Unauthenticated:
        return {"error": "unauthenticated", "http": 401}
    except cognito.IdentityError:
        return {"error": "upstream", "http": 502}
    op = event.get("op")
    try:
        if op == "create":
            result = governance.create_request(caller, event.get("action"), event.get("username"))
        elif op == "vote":
            if not isinstance(event.get("approve"), bool):
                raise gm.InvalidRequest()
            result = governance.vote(caller, event.get("request_id"), event["approve"])
        elif op in ("approve_viewer", "revoke_viewer"):
            result = _manage_viewer(governance, identity, caller, op, event.get("username"))
        else:
            raise gm.InvalidRequest()
    except gm.ChangeFailed as exc:
        return {"error": exc.code, "http": exc.http, "outcome": exc.outcome}
    except gm.GovernanceError as exc:
        return {"error": exc.code, "http": exc.http}
    except cognito.IdentityError:
        return {"error": "upstream", "http": 502}
    return {"ok": True, "result": result}


# ------------------------------------------------------------------ AWS Lambda
_deps = None


def _dependencies():
    global _deps
    if _deps is None:
        region = os.environ["AWS_REGION"]
        identity = cognito.CognitoIdentity(os.environ["COGNITO_USER_POOL_ID"], os.environ["COGNITO_CLIENT_ID"], region)
        store = gm.DynamoGovernanceStore(os.environ["INCIDENT_TABLE"], region)
        governance = gm.Governance(store, identity=identity,
                                   local_principal=os.environ.get("LOCAL_PRINCIPAL", "local:admin"))
        _deps = (governance, identity)
    return _deps


def handler(event, context):
    governance, identity = _dependencies()
    response = execute(event, governance, identity)
    # Dau vet kiem toan trong log group cua chinh Lambda (EC2 khong xoa / sua duoc). Khong ghi token.
    event = event if isinstance(event, dict) else {}
    caller = event.get("caller") if isinstance(event.get("caller"), dict) else {}
    result = response.get("result")
    status = response.get("error") or (result.get("status") if isinstance(result, dict) else "ok")
    print(json.dumps({"op": event.get("op"), "local": caller.get("local") is True, "status": status}))
    return response


# ------------------------------------------------------- phia EC2: goi Lambda
class InProcessExecutor:
    """Chay ngay trong web app (test, may dev khong co Lambda). Cung duong code voi Lambda that."""

    def __init__(self, governance, identity):
        self._governance, self._identity = governance, identity

    def __call__(self, event: dict) -> dict:
        return execute(event, self._governance, self._identity)


class LambdaExecutor:
    """Phia EC2 goi Lambda thuc thi phan quyen. Loi mang / Lambda loi -> upstream (khong bao gio coi la thanh
    cong)."""

    def __init__(self, function_name: str, region: str, client=None):
        self._name, self._region, self._client = function_name, region, client

    def _lambda(self):
        if self._client is None:
            import boto3  # import tre: test khong can boto3
            self._client = boto3.client("lambda", region_name=self._region)
        return self._client

    def __call__(self, event: dict) -> dict:
        try:
            res = self._lambda().invoke(FunctionName=self._name, InvocationType="RequestResponse",
                                        Payload=json.dumps(event).encode())
            if res.get("FunctionError"):
                raise RuntimeError(res["FunctionError"])
            body = json.loads(res["Payload"].read())
        except Exception as exc:
            print(f"[ERROR] Goi Lambda {self._name} loi: {type(exc).__name__}", flush=True)
            return {"error": "upstream", "http": 502}
        return body if isinstance(body, dict) and ("ok" in body or "error" in body) else {"error": "upstream", "http": 502}
