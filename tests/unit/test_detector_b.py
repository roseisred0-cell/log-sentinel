"""Test phan B: Telegram + 3 luat CloudTrail IAM. Chay duoc ma khong can AWS that."""
import base64
import gzip
import importlib
import json
import sys
import types
import urllib.error
from pathlib import Path
from unittest import mock

import pytest

LAMBDA_SRC = str(Path(__file__).resolve().parents[2] / "lambda_src")


def _load_detector(monkeypatch):
    """Nap detector.py voi boto3 gia (khong goi AWS, khong can region)."""
    fake = types.ModuleType("boto3")
    fake.resource = lambda *a, **k: mock.MagicMock()
    fake.client = lambda *a, **k: mock.MagicMock()
    monkeypatch.setitem(sys.modules, "boto3", fake)
    monkeypatch.setenv("INCIDENT_TABLE", "t")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:sns")
    monkeypatch.setenv("SECRET_ARN", "arn:secret")
    monkeypatch.syspath_prepend(LAMBDA_SRC)
    sys.modules.pop("detector", None)
    return importlib.import_module("detector")


@pytest.fixture
def det(monkeypatch):
    d = _load_detector(monkeypatch)
    d.table = mock.MagicMock()
    d.sns = mock.MagicMock()
    d.secrets = mock.MagicMock()
    d._telegram_cache.update(cfg=None, fetched_at=0.0)
    d._telegram_failed_this_run = False
    return d


def _secret(det, token="123:ABC", chat="999"):
    det.secrets.get_secret_value.return_value = {
        "SecretString": json.dumps({"BOT_TOKEN": token, "CHAT_ID": chat})}


def _ct(name, params=None, user="dev-user", **extra):
    return json.dumps({"eventName": name, "requestParameters": params,
                       "userIdentity": {"userName": user}, "sourceIPAddress": "203.0.113.50", **extra})


def _incident(det):
    return det.table.put_item.call_args.kwargs["Item"]


# ---------------------------------------------------------- 3 luat IAM
def test_create_access_key_is_high(det):
    det.evaluate_cloudtrail_log(_ct("CreateAccessKey", {"userName": "bob"}))
    item = _incident(det)
    assert item["rule"] == "IAM_ACCESS_KEY_CREATED" and item["severity"] == "HIGH"
    assert item["details"]["target_user"] == "bob"


def test_attach_admin_policy_is_critical(det):
    det.evaluate_cloudtrail_log(_ct("AttachUserPolicy", {"policyArn": det.ADMIN_POLICY_ARN, "userName": "bob"}))
    item = _incident(det)
    assert item["rule"] == "IAM_POLICY_ATTACHED" and item["severity"] == "CRITICAL"


def test_attach_other_policy_is_high(det):
    det.evaluate_cloudtrail_log(_ct("AttachUserPolicy", {"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}))
    assert _incident(det)["severity"] == "HIGH"


def test_put_user_policy_is_high(det):
    det.evaluate_cloudtrail_log(_ct("PutUserPolicy", {"policyName": "x", "userName": "bob"}))
    item = _incident(det)
    assert item["rule"] == "IAM_INLINE_POLICY_PUT" and item["details"]["policy_name"] == "x"


@pytest.mark.parametrize("name", ["CreateAccessKey", "AttachUserPolicy", "PutUserPolicy"])
def test_null_request_parameters_do_not_crash(det, name):
    det.evaluate_cloudtrail_log(_ct(name, None))  # CloudTrail co the dat null
    det.table.put_item.assert_called_once()


def test_denied_attempt_still_recorded_with_error_code(det):
    det.evaluate_cloudtrail_log(_ct("CreateAccessKey", {"userName": "bob"}, errorCode="AccessDenied"))
    assert _incident(det)["details"]["error_code"] == "AccessDenied"


def test_actor_falls_back_when_no_username(det):
    raw = json.dumps({"eventName": "PutUserPolicy", "requestParameters": {},
                      "userIdentity": {"type": "AssumedRole", "arn": "arn:role"}})
    det.evaluate_cloudtrail_log(raw)
    assert _incident(det)["details"]["actor"] == "arn:role"


def test_unrelated_event_ignored(det):
    det.evaluate_cloudtrail_log(_ct("ListBuckets"))
    det.table.put_item.assert_not_called()


# ------------------------------------------------------------- Telegram
def test_telegram_sent_with_correct_url_and_payload(det):
    _secret(det)
    with mock.patch.object(det.urllib.request, "urlopen") as op:
        det.record_incident("SQL_INJECTION", "CRITICAL", {"client_ip": "1.2.3.4"}, "raw")
    req = op.call_args.args[0]
    assert req.full_url == "https://api.telegram.org/bot123:ABC/sendMessage"
    body = json.loads(req.data)
    assert body["chat_id"] == "999" and "SQL_INJECTION" in body["text"]
    assert op.call_args.kwargs["timeout"] == det.TELEGRAM_TIMEOUT_S


def test_telegram_skipped_when_placeholder(det):
    _secret(det, token="REPLACE_ME", chat="REPLACE_ME")
    with mock.patch.object(det.urllib.request, "urlopen") as op:
        det.record_incident("X", "HIGH", {}, "raw")
    op.assert_not_called()
    det.sns.publish.assert_called_once()  # email van gui


def test_telegram_failure_never_breaks_incident_flow(det):
    _secret(det)
    with mock.patch.object(det.urllib.request, "urlopen", side_effect=urllib.error.URLError("boom")):
        det.record_incident("X", "HIGH", {}, "raw")  # khong duoc nem loi
    det.table.put_item.assert_called_once()
    det.sns.publish.assert_called_once()


def test_telegram_error_log_does_not_leak_token(det, capsys):
    _secret(det, token="123:SUPERSECRET")
    with mock.patch.object(det.urllib.request, "urlopen",
                           side_effect=urllib.error.URLError("https://api.telegram.org/bot123:SUPERSECRET")):
        det.record_incident("X", "HIGH", {}, "raw")
    assert "SUPERSECRET" not in capsys.readouterr().out


def test_secret_cached_between_incidents(det):
    _secret(det)
    with mock.patch.object(det.urllib.request, "urlopen"):
        det.record_incident("A", "HIGH", {}, "raw")
        det.record_incident("B", "HIGH", {}, "raw")
    assert det.secrets.get_secret_value.call_count == 1


def test_secret_read_error_is_swallowed(det):
    det.secrets.get_secret_value.side_effect = RuntimeError("denied")
    with mock.patch.object(det.urllib.request, "urlopen") as op:
        det.record_incident("A", "HIGH", {}, "raw")
    op.assert_not_called()


def test_after_one_failure_rest_of_batch_skips_telegram(det):
    _secret(det)
    with mock.patch.object(det.urllib.request, "urlopen", side_effect=TimeoutError()) as op:
        for _ in range(5):
            det.record_incident("A", "HIGH", {}, "raw")
    assert op.call_count == 1  # khong cho 5 lan x 5 giay


def test_long_message_truncated_to_telegram_limit(det):
    _secret(det)
    with mock.patch.object(det.urllib.request, "urlopen") as op:
        det.record_incident("A", "HIGH", {"blob": "x" * 10000}, "raw")
    assert len(json.loads(op.call_args.args[0].data)["text"]) <= 4096


# ------------------------------------------------------- handler end-to-end
def test_handler_routes_cloudtrail_batch_and_survives_bad_json(det):
    events = [{"message": "not json"}, {"message": _ct("CreateAccessKey", {"userName": "bob"})}]
    payload = {"logGroup": "/logsentinel/cloudtrail", "logEvents": events}
    data = base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()
    res = det.handler({"awslogs": {"data": data}}, None)
    assert res["statusCode"] == 200
    det.table.put_item.assert_called_once()


def test_handler_raises_on_malformed_envelope_so_error_alarm_fires(det):
    # Truoc day handler tra ve 500 va nuot loi -> metric AWS/Lambda Errors luon = 0,
    # DetectorErrorsAlarm khong bao gio bat. Nay phai nem loi ra ngoai.
    with pytest.raises(Exception):
        det.handler({"bad": 1}, None)
