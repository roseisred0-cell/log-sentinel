"""Test phan loi Detector (A): brute-force nguyen tu, SOAR block, allowlist, input xau."""
import base64
import gzip
import importlib
import json
import sys
import types
from decimal import Decimal
from pathlib import Path
from unittest import mock

import pytest

LAMBDA_SRC = str(Path(__file__).resolve().parents[2] / "lambda_src")


class ConditionalCheckFailed(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeStateTable:
    """Mo phong dung 2 ConditionExpression ma count_failed_login dung."""

    def __init__(self):
        self.items = {}
        self.put_item = mock.MagicMock()

    def update_item(self, Key, UpdateExpression, ConditionExpression, ExpressionAttributeValues, **_):
        k = (Key["incident_id"], Key["timestamp"])
        item = self.items.get(k)
        v = ExpressionAttributeValues
        if ConditionExpression == "window_start > :floor":
            if not item or item["window_start"] <= v[":floor"]:
                raise ConditionalCheckFailed()
            item["failure_count"] += 1
            return {"Attributes": {"failure_count": item["failure_count"]}}
        # nhanh mo cua so moi
        if item and item["window_start"] > v[":floor"]:
            raise ConditionalCheckFailed()
        self.items[k] = {"failure_count": 1, "window_start": v[":now"]}
        return {}


def _load(monkeypatch, allowlist=""):
    fake = types.ModuleType("boto3")
    fake.resource = lambda *a, **k: mock.MagicMock()
    fake.client = lambda *a, **k: mock.MagicMock()
    monkeypatch.setitem(sys.modules, "boto3", fake)
    monkeypatch.setenv("INCIDENT_TABLE", "t")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:sns")
    monkeypatch.setenv("SECRET_ARN", "")
    monkeypatch.setenv("BLOCK_ALLOWLIST_CIDRS", allowlist)
    monkeypatch.syspath_prepend(LAMBDA_SRC)
    sys.modules.pop("detector", None)
    d = importlib.import_module("detector")
    d.sns = mock.MagicMock()
    return d


@pytest.fixture
def det(monkeypatch):
    d = _load(monkeypatch)
    d.table = FakeStateTable()
    return d


def _failed(ip="198.51.100.7"):
    return json.dumps({"event_type": "FAILED_LOGIN", "client_ip": ip, "username": "admin"})


def _rules(det):
    return [c.kwargs["Item"].get("rule") for c in det.table.put_item.call_args_list]


# ------------------------------------------------------------ brute-force
def test_bruteforce_alerts_exactly_once_per_window(det):
    for _ in range(12):
        det.evaluate_webapp_log(_failed())
    assert _rules(det).count("BRUTE_FORCE_DETECTED") == 1
    assert _rules(det).count("ACTIVE_REMEDIATION_BLOCKED") == 1
    assert det.sns.publish.call_count == 1  # khong bao canh bao


def test_four_failures_do_not_alert(det):
    for _ in range(4):
        det.evaluate_webapp_log(_failed())
    det.table.put_item.assert_not_called()


def test_window_resets_after_60_seconds(det, monkeypatch):
    clock = [1_000_000]
    monkeypatch.setattr(det, "_now", lambda: clock[0])
    for _ in range(4):
        det.evaluate_webapp_log(_failed())
    clock[0] += 61  # cua so cu het han, 4 lan cu khong duoc cong don
    for _ in range(4):
        det.evaluate_webapp_log(_failed())
    det.table.put_item.assert_not_called()
    det.evaluate_webapp_log(_failed())  # lan thu 5 trong cua so moi
    assert "BRUTE_FORCE_DETECTED" in _rules(det)


def test_counters_are_per_ip(det):
    for i in range(5):
        det.evaluate_webapp_log(_failed(f"198.51.100.{i + 10}"))
    det.table.put_item.assert_not_called()


def test_lost_race_on_window_open_falls_back_to_increment(det):
    det.table.items[("STATE#FAILED_LOGIN#198.51.100.7", "WINDOW")] = {
        "failure_count": 2, "window_start": det._now()}
    assert det.count_failed_login("198.51.100.7") == 3


def test_non_conditional_dynamo_error_is_contained(det):
    det.table.update_item = mock.MagicMock(side_effect=RuntimeError("throttled"))
    det.evaluate_webapp_log(_failed())  # khong duoc nem loi


# -------------------------------------------------------------- SOAR block
def test_block_uses_fixed_key_and_24h_ttl(det):
    assert det.auto_block_attacker_ip("203.0.113.9", "test") is True
    item = det.table.put_item.call_args.kwargs["Item"]
    assert item["incident_id"] == "BLOCKED_IP#203.0.113.9" and item["timestamp"] == "ACTIVE"
    assert 86000 < item["ttl"] - det._now() <= 86400


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "0.0.0.0", "unknown", "", None, "1.2.3.4; DROP", "169.254.169.254"])
def test_unsafe_or_invalid_ips_never_blocked(det, ip):
    assert det.auto_block_attacker_ip(ip, "x") is False
    det.table.put_item.assert_not_called()


def test_allowlisted_admin_cidr_never_blocked(monkeypatch):
    d = _load(monkeypatch, allowlist="203.0.113.0/24, bad-cidr")
    d.table = mock.MagicMock()
    assert d.auto_block_attacker_ip("203.0.113.77", "x") is False
    assert d.auto_block_attacker_ip("198.51.100.1", "x") is True


def test_sqli_records_and_blocks(det):
    det.evaluate_webapp_log(json.dumps({"event_type": "SQL_INJECTION", "client_ip": "203.0.113.5",
                                        "payload": "' OR 1=1 --"}))
    assert _rules(det) == ["SQL_INJECTION", "ACTIVE_REMEDIATION_BLOCKED"]


def test_cloudtrail_events_never_auto_block(det):
    det.evaluate_cloudtrail_log(json.dumps({"eventName": "StopLogging", "sourceIPAddress": "203.0.113.5",
                                            "userIdentity": {"userName": "x"}}))
    assert _rules(det) == ["CLOUDTRAIL_TAMPERING"]


# ------------------------------------------------------------- input xau
def test_float_and_huge_fields_are_dynamodb_safe(det):
    det.evaluate_webapp_log(json.dumps({"event_type": "SQL_INJECTION", "client_ip": "203.0.113.5",
                                        "latency": 0.25, "payload": "A" * 100_000}))
    details = det.table.put_item.call_args_list[0].kwargs["Item"]["details"]
    assert details["latency"] == Decimal("0.25")
    assert len(details["payload"]) == det.MAX_FIELD_CHARS
    json.loads(det.sns.publish.call_args.kwargs["Message"].split("Chi tiết: ")[1].split("\nMã sự cố")[0])


@pytest.mark.parametrize("raw", ["", "null", "[]", "123", '"str"', "{bad", '{"userIdentity": null, "eventName": "ConsoleLogin"}'])
def test_garbage_lines_ignored(det, raw):
    det.evaluate_webapp_log(raw)
    det.evaluate_cloudtrail_log(raw)
    det.table.put_item.assert_not_called()


def _envelope(group, messages):
    payload = {"logGroup": group, "logEvents": [{"message": m} for m in messages]}
    return {"awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()}}


def test_one_crashing_event_does_not_drop_the_batch(det, monkeypatch):
    calls = []

    def flaky(msg):
        calls.append(msg)
        if msg == "boom":
            raise ValueError("x")

    monkeypatch.setattr(det, "_ROUTES", ((det.APP_LOG_GROUP, flaky),))
    res = det.handler(_envelope("/logsentinel/sample-app", ["a", "boom", "b"]), None)
    assert calls == ["a", "boom", "b"] and "1 bad" in res["body"]


def test_unknown_log_group_ignored(det):
    assert det.handler(_envelope("/other", ["x"]), None)["body"] == "IGNORED"


def test_incident_metric_emitted_in_emf(det, capsys):
    det.record_incident("SQL_INJECTION", "CRITICAL", {}, "raw")
    emf = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith('{"_aws"')]
    assert emf and emf[0]["IncidentsDetected"] == 1 and emf[0]["Severity"] == "CRITICAL"


# ------------------------------------------------------ bo sung v2.3
def _items(det):
    return [c.kwargs["Item"] for c in det.table.put_item.call_args_list]


def test_incident_and_block_carry_record_type_for_console_index(det):
    det.evaluate_webapp_log(json.dumps({"event_type": "SQL_INJECTION", "client_ip": "203.0.113.5"}))
    assert [i["record_type"] for i in _items(det)] == ["INCIDENT", "BLOCK"]


def test_root_console_login_is_critical_even_with_mfa(det):
    det.evaluate_cloudtrail_log(json.dumps({
        "eventName": "ConsoleLogin", "userIdentity": {"type": "Root"},
        "additionalEventData": {"MFAUsed": "Yes"}, "sourceIPAddress": "203.0.113.5"}))
    item = _items(det)[0]
    assert item["rule"] == "ROOT_ACCOUNT_LOGIN" and item["severity"] == "CRITICAL"
    assert len(_items(det)) == 1  # khong ghi trung voi CONSOLE_LOGIN_NO_MFA


def test_iam_user_login_with_mfa_is_not_an_incident(det):
    det.evaluate_cloudtrail_log(json.dumps({
        "eventName": "ConsoleLogin", "userIdentity": {"type": "IAMUser", "userName": "dev"},
        "additionalEventData": {"MFAUsed": "Yes"}}))
    det.table.put_item.assert_not_called()


def test_incident_records_are_kept_30_days_on_the_console(det, monkeypatch):
    monkeypatch.setattr(det, "_now", lambda: 1_000_000)
    det.evaluate_webapp_log(json.dumps({"event_type": "SQL_INJECTION", "client_ip": "198.51.100.7"}))
    incident = next(c.kwargs["Item"] for c in det.table.put_item.call_args_list
                    if c.kwargs["Item"].get("record_type") == "INCIDENT")
    assert incident["ttl"] == 1_000_000 + 30 * 24 * 3600
