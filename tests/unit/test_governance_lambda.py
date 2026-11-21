"""Seam G: Lambda thuc thi phan quyen (sample_app/governance_lambda.py), nhat ky 12/11 muc 4.D1.

EC2 mat moi quyen ghi vao Cognito va vao ROLE_REQ#. Moi thao tac phan quyen di qua Lambda; Lambda tu xac dinh
nguoi goi bang token Cognito (khong tin danh tinh EC2 gui). Admin noi bo (khong co token) chi duoc tin trong che
do khoi tao (Q1 a) va khi da du 2 admin Cognito thi khong con duyet / thu hoi Nguoi xem (Q2 b).
"""
import pytest

pytest.importorskip("flask")

from .test_console_accounts import FakeIdentity  # noqa: E402
from .test_sample_app import mod  # noqa: E402,F401  (dua sample_app len sys.path)


@pytest.fixture
def env(mod):
    import admin_governance
    import cognito_identity as cog
    import governance_lambda
    identity = FakeIdentity(cog)
    store = admin_governance.MemoryGovernanceStore()
    clock = [1_000_000.0]
    gov = admin_governance.Governance(store, identity=identity, clock=lambda: clock[0], local_principal="local:admin")

    def call(**event):
        return governance_lambda.execute(event, gov, identity)

    return type("Env", (), {"identity": identity, "store": store, "call": staticmethod(call), "clock": clock})


def token(email):
    return {"access_token": f"tok-{email}"}


@pytest.fixture
def team(env):
    for email in ("a@x.co", "b@x.co"):
        env.identity.add(email, mfa=True, role="admin")
    env.identity.add("v@x.co", role="viewer")
    env.identity.add("p@x.co")
    return env


def role(env, email):
    return env.identity.users[email]["role"]


# ------------------------------------------------------- xac thuc nguoi goi
@pytest.mark.parametrize("caller", [{}, {"access_token": "tok-ghost@x.co"}, {"access_token": 42},
                                    {"access_token": "tok-a@x.co", "local": True}])
def test_caller_must_prove_identity_with_a_valid_token(team, caller):
    r = team.call(op="create", action="promote", username="uid-v", caller=caller)
    assert r == {"error": "unauthenticated", "http": 401}
    assert role(team, "v@x.co") == "viewer" and team.store.requests == {}


def test_identity_comes_from_cognito_not_from_the_event(team):
    """EC2 bi chiem gui kem 'principal' gia: Lambda bo qua, chi tin token."""
    r = team.call(op="create", action="promote", username="uid-v", caller=token("b@x.co"),
                  principal="cognito:a@x.co")
    assert r["ok"] and r["result"]["approvers"] == ["cognito:b@x.co"]


# ------------------------------------------------------- tao yeu cau & bo phieu
def test_two_admins_promote_through_the_lambda(team):
    r = team.call(op="create", action="promote", username="uid-v", caller=token("a@x.co"))
    assert r["ok"] and r["result"]["status"] == "pending" and role(team, "v@x.co") == "viewer"
    r = team.call(op="vote", request_id=r["result"]["id"], approve=True, caller=token("b@x.co"))
    assert r["result"]["status"] == "executed" and role(team, "v@x.co") == "admin"


def test_viewer_token_cannot_vote_or_create(team):
    r = team.call(op="create", action="promote", username="uid-v", caller=token("v@x.co"))
    assert r == {"error": "not_a_voter", "http": 403}


def test_rules_errors_are_returned_not_raised(team):
    r = team.call(op="create", action="demote", username="uid-b", caller=token("a@x.co"))
    assert r == {"error": "min_admins", "http": 409}


def test_cognito_failure_returns_the_outcome_for_the_audit_log(team):
    import cognito_identity as cog
    rid = team.call(op="create", action="promote", username="uid-v", caller=token("a@x.co"))["result"]["id"]
    team.identity.promote = lambda u: (_ for _ in ()).throw(cog.UpstreamError("boom"))
    r = team.call(op="vote", request_id=rid, approve=True, caller=token("b@x.co"))
    assert r["error"] == "upstream" and r["http"] == 502 and r["outcome"]["status"] == "failed"


@pytest.mark.parametrize("event", [{}, {"op": "explode"}, {"op": "vote", "request_id": "x", "approve": "yes"},
                                   {"op": "create", "action": "promote"}])
def test_malformed_events_are_rejected(team, event):
    r = team.call(**{"caller": token("a@x.co"), **event})
    assert r["http"] in (400, 404) and "error" in r


# ------------------------------------------- admin noi bo (khong co token)
def test_internal_admin_is_trusted_only_during_bootstrap(env):
    env.identity.add("v@x.co", role="viewer")
    r = env.call(op="create", action="promote", username="uid-v", caller={"local": True})
    assert r["result"]["status"] == "executed" and r["result"]["bootstrap"] is True


def test_internal_admin_has_no_say_once_two_cognito_admins_exist(team):
    r = team.call(op="create", action="promote", username="uid-v", caller={"local": True})
    assert r == {"error": "local_admin_no_vote", "http": 403}


# --------------------------------------------- duyet / thu hoi Nguoi xem
def test_cognito_admin_approves_and_revokes_viewers(team):
    assert team.call(op="approve_viewer", username="uid-p", caller=token("a@x.co")) == {"ok": True, "result": "p@x.co"}
    assert role(team, "p@x.co") == "viewer"
    assert team.call(op="revoke_viewer", username="uid-v", caller=token("a@x.co")) == {"ok": True, "result": "v@x.co"}
    assert role(team, "v@x.co") == "pending"


@pytest.mark.parametrize("op,username", [("approve_viewer", "uid-p"), ("revoke_viewer", "uid-v")])
def test_viewer_cannot_manage_viewers(team, op, username):
    assert team.call(op=op, username=username, caller=token("v@x.co")) == {"error": "not_admin", "http": 403}


@pytest.mark.parametrize("op,username", [("approve_viewer", "uid-p"), ("revoke_viewer", "uid-v")])
def test_internal_admin_cannot_manage_viewers_outside_bootstrap(team, op, username):
    """Q2 (b): may bi chiem gui {"local": true} khong tu duyet duoc tai khoan de doc du lieu."""
    r = team.call(op=op, username=username, caller={"local": True})
    assert r == {"error": "local_admin_restricted", "http": 403}
    assert role(team, "p@x.co") == "pending" and role(team, "v@x.co") == "viewer"


def test_internal_admin_manages_viewers_during_bootstrap(env):
    env.identity.add("p@x.co")
    assert env.call(op="approve_viewer", username="uid-p", caller={"local": True})["result"] == "p@x.co"


def test_unknown_user_is_not_found(team):
    assert team.call(op="approve_viewer", username="uid-ghost", caller=token("a@x.co")) == \
        {"error": "not_found", "http": 404}


# --------------------------------------------- phia EC2: goi Lambda that
class FakeLambda:
    def __init__(self, reply=None, function_error=None, raises=None):
        self.calls, self.reply, self.function_error, self.raises = [], reply, function_error, raises

    def invoke(self, **kw):
        import io
        import json
        self.calls.append(kw)
        if self.raises:
            raise self.raises
        res = {"Payload": io.BytesIO(json.dumps(self.reply).encode())}
        if self.function_error:
            res["FunctionError"] = self.function_error
        return res


def test_lambda_executor_sends_the_event_and_returns_the_reply(mod):
    import json
    import governance_lambda
    fake = FakeLambda(reply={"ok": True, "result": "p@x.co"})
    ex = governance_lambda.LambdaExecutor("ls-governance", "ap-southeast-1", client=fake)
    event = {"op": "approve_viewer", "username": "uid-p", "caller": {"access_token": "t"}}
    assert ex(event) == {"ok": True, "result": "p@x.co"}
    assert fake.calls[0]["FunctionName"] == "ls-governance" and fake.calls[0]["InvocationType"] == "RequestResponse"
    assert json.loads(fake.calls[0]["Payload"]) == event


@pytest.mark.parametrize("fake", [FakeLambda(reply={"ok": True}, function_error="Unhandled"),
                                  FakeLambda(raises=ConnectionError("down")),
                                  FakeLambda(reply="not a dict"), FakeLambda(reply={"surprise": 1})])
def test_lambda_executor_never_treats_failures_as_success(mod, fake):
    import governance_lambda
    ex = governance_lambda.LambdaExecutor("ls-governance", "ap-southeast-1", client=fake)
    assert ex({"op": "vote"}) == {"error": "upstream", "http": 502}
