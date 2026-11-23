"""Seam D: store cua muc Phan quyen. Cung mot bo test hop dong cho MemoryGovernanceStore va DynamoGovernanceStore.

Ban DynamoDB chay tren moto (DynamoDB gia lap trong RAM) voi dung schema cua IncidentTable trong CDK,
de kiem tra ghi co dieu kien (hai admin bo phieu cung luc chi mot ben duoc thuc thi) va tien to khoa
khop dieu kien IAM `dynamodb:LeadingKeys` (ADMIN_PIN#*, ROLE_REQ#*).
"""
import importlib.util
import sys
from pathlib import Path

import pytest

from .test_sample_app import mod  # noqa: F401  (fixture: nap sample_app/app.py voi pyotp gia)

SRC = Path(__file__).resolve().parents[2] / "sample_app"
if str(SRC) not in sys.path:  # admin_governance.py import caller_auth / cognito_identity cung thu muc
    sys.path.insert(0, str(SRC))
_spec = importlib.util.spec_from_file_location("admin_governance_under_test", SRC / "admin_governance.py")
gm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gm)

TABLE, REGION = "IncidentTable", "ap-southeast-1"


@pytest.fixture
def dynamo(monkeypatch):
    moto = pytest.importorskip("moto")
    import boto3
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        ddb = boto3.resource("dynamodb", region_name=REGION)
        table = ddb.create_table(  # giong log_sentinel_stack.py: IncidentTable + GSI by_type
            TableName=TABLE, BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "incident_id", "KeyType": "HASH"},
                       {"AttributeName": "timestamp", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"}
                                  for n in ("incident_id", "timestamp", "record_type")],
            GlobalSecondaryIndexes=[{"IndexName": "by_type", "Projection": {"ProjectionType": "ALL"},
                                     "KeySchema": [{"AttributeName": "record_type", "KeyType": "HASH"},
                                                   {"AttributeName": "timestamp", "KeyType": "RANGE"}]}])
        yield table


@pytest.fixture(params=["memory", "dynamo"])
def store(request):
    if request.param == "memory":
        return gm.MemoryGovernanceStore()
    request.getfixturevalue("dynamo")
    return gm.DynamoGovernanceStore(TABLE, REGION)


def _req(rid="r1", **kw):
    return {"id": rid, "action": "promote", "target_username": "uid-v", "target_email": "v@x.co",
            "initiator": "cognito:a@x.co", "approvals": ["cognito:a@x.co"], "status": "pending",
            "created_at": 1_000_000.5, **kw}


# ------------------------------------------------------------------- PIN
def test_pin_round_trip(store):
    assert store.pin_get("cognito:a@x.co") is None
    store.pin_create("cognito:a@x.co", "ab" * 32, "cd" * 16)
    rec = store.pin_get("cognito:a@x.co")
    assert (rec["hash"], rec["salt"], rec["failures"], rec["locked_until"]) == ("ab" * 32, "cd" * 16, 0, 0)


def test_pin_failures_count_up_and_lock_resets_them(store):
    store.pin_create("local:admin", "h", "s")
    assert [store.pin_fail("local:admin") for _ in range(3)] == [1, 2, 3]
    store.pin_lock("local:admin", 1_000_900.0)
    rec = store.pin_get("local:admin")
    assert rec["failures"] == 0 and rec["locked_until"] == 1_000_900.0
    store.pin_fail("local:admin")
    store.pin_clear_failures("local:admin")
    assert store.pin_get("local:admin")["failures"] == 0


def test_pin_create_never_overwrites_an_existing_pin(store):
    """Hai lan dat PIN lan dau cung luc: chi lan dau thanh cong."""
    assert store.pin_create("cognito:a@x.co", "h", "s") is True
    assert store.pin_create("cognito:a@x.co", "h2", "s2") is False
    assert store.pin_get("cognito:a@x.co")["hash"] == "h"


def test_new_pin_after_reset_starts_unlocked(store):
    store.pin_create("cognito:a@x.co", "h", "s")
    store.pin_lock("cognito:a@x.co", 2_000_000.0)
    store.pin_delete("cognito:a@x.co")  # admin khac dat lai
    assert store.pin_create("cognito:a@x.co", "h2", "s2") is True
    assert store.pin_get("cognito:a@x.co")["locked_until"] == 0


# ------------------------------------------------- khoa thuc thi dung chung
def test_execution_lock_is_exclusive_until_released_or_expired(store):
    assert store.lock_acquire("execute", 1_000.0, 30) is True
    assert store.lock_acquire("execute", 1_010.0, 30) is False   # worker khac dang giu
    store.lock_release("execute")
    assert store.lock_acquire("execute", 1_011.0, 30) is True
    assert store.lock_acquire("execute", 1_042.0, 30) is True    # het han 30s: worker giu khoa da chet


def test_pin_delete(store):
    store.pin_create("cognito:a@x.co", "h", "s")
    store.pin_delete("cognito:a@x.co")
    assert store.pin_get("cognito:a@x.co") is None
    store.pin_delete("cognito:ghost@x.co")  # khong loi


# ----------------------------------------------------------- yeu cau
def test_request_round_trip(store):
    store.req_put(_req())
    assert store.req_get("r1") == _req()
    assert store.req_get("nope") is None


def test_approvals_are_unique_and_returned(store):
    store.req_put(_req())
    assert sorted(store.req_add_approval("r1", "cognito:b@x.co")) == ["cognito:a@x.co", "cognito:b@x.co"]
    assert sorted(store.req_add_approval("r1", "cognito:b@x.co")) == ["cognito:a@x.co", "cognito:b@x.co"]
    assert sorted(store.req_get("r1")["approvals"]) == ["cognito:a@x.co", "cognito:b@x.co"]


def test_request_closes_exactly_once(store):
    """Hai worker cung thay du phieu: chi worker dong yeu cau thanh cong moi duoc thuc thi."""
    store.req_put(_req())
    assert store.req_finish("r1", "executed") is True
    assert store.req_finish("r1", "executed") is False
    assert store.req_finish("r1", "rejected") is False
    assert store.req_get("r1")["status"] == "executed"


def test_no_votes_after_close(store):
    store.req_put(_req())
    store.req_finish("r1", "rejected")
    assert store.req_add_approval("r1", "cognito:b@x.co") is None
    assert store.req_get("r1")["approvals"] == ["cognito:a@x.co"]


def test_request_list(store):
    store.req_put(_req("r1"))
    store.req_put(_req("r2", status="rejected"))
    assert sorted(r["id"] for r in store.req_list()) == ["r1", "r2"]


def test_request_list_returns_every_request_however_many_closed_ones_pile_up(store):
    # Yeu cau da dong duoc giu 7 ngay (TTL don rac). Id ngau nhien nen yeu cau dang cho co the nam o bat ky dau
    # trong ket qua: danh sach phai doc het, neu khong yeu cau cho duyet bien mat khoi muc Phan quyen.
    for i in range(205):
        store.req_put(_req(f"old{i:03d}", status="executed"))
    store.req_put(_req("zzz-pending"))
    ids = [r["id"] for r in store.req_list()]
    assert len(ids) == 206 and "zzz-pending" in ids


# ------------------------------------------------ rieng cho DynamoDB
def test_dynamo_keys_use_the_prefixes_iam_allows(dynamo):
    s = gm.DynamoGovernanceStore(TABLE, REGION)
    s.pin_create("cognito:a@x.co", "h", "s")
    s.req_put(_req())
    keys = sorted(i["incident_id"] for i in dynamo.scan()["Items"])
    assert keys == ["ADMIN_PIN#cognito:a@x.co", "ROLE_REQ#r1"]


def test_dynamo_request_list_ignores_incidents_and_blocks(dynamo):
    dynamo.put_item(Item={"incident_id": "INC#1", "timestamp": "2026-11-12T00:00:00Z", "record_type": "INCIDENT"})
    dynamo.put_item(Item={"incident_id": "BLOCKED_IP#1.2.3.4", "timestamp": "ACTIVE", "record_type": "BLOCK"})
    s = gm.DynamoGovernanceStore(TABLE, REGION)
    s.req_put(_req())
    assert [r["id"] for r in s.req_list()] == ["r1"]


def test_dynamo_requests_carry_a_cleanup_ttl(dynamo):
    s = gm.DynamoGovernanceStore(TABLE, REGION)
    s.req_put(_req())
    item = dynamo.get_item(Key={"incident_id": "ROLE_REQ#r1", "timestamp": "REQ"})["Item"]
    assert int(item["ttl"]) > 1_000_000 + 24 * 3600  # don rac sau khi het han; thoi han 24h kiem tra trong code


def test_user_wide_session_revocation_is_shared_through_dynamo(dynamo, mod):
    """Worker A ha quyen mot admin; worker B (cache rieng) thay trong <= 15 giay qua REVOKED_SESSION#user:..."""
    store = mod.DynamoIncidentStore(TABLE, REGION)
    t = [1_000.0]
    worker_a = mod.SessionRevocations(store, clock=lambda: t[0])
    worker_b = mod.SessionRevocations(store, clock=lambda: t[0])
    assert worker_b.user_revoked_at("cognito:c@x.co") == 0.0
    worker_a.revoke_user("cognito:c@x.co", 1_000.5)
    assert worker_a.user_revoked_at("cognito:c@x.co") == 1_000.5
    t[0] += 16  # het cache "chua thu hoi" cua worker B
    assert worker_b.user_revoked_at("cognito:c@x.co") == 1_000.5
    keys = [i["incident_id"] for i in dynamo.scan()["Items"]]
    assert keys == ["REVOKED_SESSION#user:cognito:c@x.co"]  # cung tien to IAM voi thu hoi phien


def test_governance_runs_end_to_end_on_dynamo(dynamo):
    """Mot vong nang quyen day du qua Governance voi store DynamoDB that (moto)."""
    class Directory:
        def __init__(self):
            self.roles = {"uid-a": ("a@x.co", "admin"), "uid-b": ("b@x.co", "admin"), "uid-v": ("v@x.co", "viewer")}

        def list_users(self):
            out = {"pending": [], "viewers": [], "admins": []}
            for name, (email, role) in self.roles.items():
                out[{"viewer": "viewers", "admin": "admins"}[role]].append({"username": name, "email": email})
            return out

        def promote(self, username):
            email, _ = self.roles[username]
            self.roles[username] = (email, "admin")
            return email

    directory = Directory()
    g = gm.Governance(gm.DynamoGovernanceStore(TABLE, REGION), identity=directory, clock=lambda: 1_000_000.0)
    out = g.create_request("cognito:a@x.co", "promote", "uid-v")
    assert out["status"] == "pending" and directory.roles["uid-v"][1] == "viewer"
    assert g.vote("cognito:b@x.co", out["id"], True)["status"] == "executed"
    assert directory.roles["uid-v"][1] == "admin"
