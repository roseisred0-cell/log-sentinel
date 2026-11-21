"""Seam E: Detector bien su kien muc Phan quyen cua web app thanh su co + canh bao, KHONG BAO GIO khoa IP
(IP nguon la cua chinh admin dang thao tac)."""
import json

import pytest

from .test_detector_core import FakeStateTable, _load
from .test_detector_spike import blocked_ips, incident, rules


@pytest.fixture
def det(monkeypatch):
    d = _load(monkeypatch)
    d.table = FakeStateTable()
    return d


def event(event_type, **fields):
    return json.dumps({"event_type": event_type, "client_ip": "203.0.113.20", "source": "sample-webapp",
                       "username": "a@x.co", **fields})


@pytest.mark.parametrize("event_type,fields", [
    ("ADMIN_ROLE_CHANGED", {"action": "promote", "target_user": "v@x.co", "approvers": ["cognito:a@x.co",
                                                                                     "cognito:b@x.co"]}),
    ("ADMIN_PIN_LOCKED", {"auth": "cognito"}),
    ("ADMIN_PIN_RESET", {"target_user": "b@x.co"}),
    ("ROLE_REQUEST_CREATED", {"action": "demote", "target_user": "c@x.co", "request_id": "r1"}),
    ("USER_DISABLED", {"action": "disable", "target_user": "v@x.co", "approvers": ["cognito:a@x.co"]}),
    ("ROLE_CHANGE_FAILED", {"action": "promote", "target_user": "v@x.co", "request_id": "r1"}),
])
def test_governance_events_become_high_incidents_without_blocking(det, event_type, fields):
    det.evaluate_webapp_log(event(event_type, **fields))
    assert rules(det) == [event_type]
    item = incident(det, event_type)
    assert item["severity"] == "HIGH"
    assert item["details"]["username"] == "a@x.co"
    assert blocked_ips(det) == []


def test_bootstrap_promotion_keeps_its_label_in_the_incident(det):
    det.evaluate_webapp_log(event("ADMIN_ROLE_CHANGED", action="promote", target_user="v@x.co", bootstrap=True))
    assert incident(det, "ADMIN_ROLE_CHANGED")["details"]["bootstrap"] is True


def test_severity_sent_by_the_web_app_is_ignored(det):
    """Muc do do Detector quyet dinh, khong lay tu dong log."""
    det.evaluate_webapp_log(event("ADMIN_PIN_LOCKED", severity="LOW"))
    assert incident(det, "ADMIN_PIN_LOCKED")["severity"] == "HIGH"


@pytest.mark.parametrize("event_type", ["ROLE_REQUEST_REJECTED", "USER_APPROVED", "USER_REVOKED"])
def test_audit_only_events_raise_nothing(det, event_type):
    det.evaluate_webapp_log(event(event_type))
    assert rules(det) == [] and blocked_ips(det) == []
