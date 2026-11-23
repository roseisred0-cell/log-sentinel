"""Seam 2: kho han muc luot hoi chatbot. Cung bo test cho MemoryChatQuota va DynamoChatQuota (moto)."""
import pytest

from .test_chat_assistant import ca
from .test_governance_store import REGION, TABLE, dynamo  # noqa: F401  (fixture IncidentTable tren moto)


@pytest.fixture(params=["memory", "dynamo"])
def quota(request):
    if request.param == "memory":
        return ca.MemoryChatQuota()
    request.getfixturevalue("dynamo")
    return ca.DynamoChatQuota(TABLE, REGION)


def test_counts_up_to_the_limit_per_user_and_day(quota):
    assert [quota.consume("cognito:a@x.co", "2026-11-19", 3) for _ in range(4)] == [True, True, True, False]
    assert quota.consume("cognito:b@x.co", "2026-11-19", 3) is True
    assert quota.consume("cognito:a@x.co", "2026-11-20", 3) is True


def test_release_gives_back_one_turn_and_never_goes_below_zero(quota):
    assert quota.consume("u", "d", 1) is True
    quota.release("u", "d")
    assert quota.consume("u", "d", 1) is True     # luot vua tra lai dung duoc
    assert quota.consume("u", "d", 1) is False
    quota.release("u", "d")
    quota.release("u", "d")                       # tra du: khong tao them luot "am"
    quota.release("other", "d")                   # chua dung luot nao: khong loi
    assert [quota.consume("u", "d", 1) for _ in range(2)] == [True, False]


def test_dynamo_key_uses_the_prefix_iam_allows_and_expires(dynamo):
    q = ca.DynamoChatQuota(TABLE, REGION)
    q.consume("cognito:a@x.co", "2026-11-19", 5)
    q.consume("cognito:a@x.co", "2026-11-19", 5)
    [item] = dynamo.scan()["Items"]
    assert (item["incident_id"], item["timestamp"], int(item["count"])) == ("CHAT_QUOTA#cognito:a@x.co", "2026-11-19", 2)
    assert int(item["ttl"]) > 0 and "record_type" not in item   # khong lot vao GSI by_type cua su co


def test_dynamo_two_workers_share_one_counter(dynamo):
    w1, w2 = ca.DynamoChatQuota(TABLE, REGION), ca.DynamoChatQuota(TABLE, REGION)
    assert [w1.consume("u", "d", 2), w2.consume("u", "d", 2), w1.consume("u", "d", 2)] == [True, True, False]
