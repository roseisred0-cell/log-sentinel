"""Luat Spike cua Detector: tang dot bien dang nhap sai toan he thong, va do quet duong dan (404)."""
import json

import pytest

from .test_detector_core import FakeStateTable, _load


@pytest.fixture
def det(monkeypatch):
    d = _load(monkeypatch)
    d.table = FakeStateTable()
    return d


def rules(d):
    return [c.kwargs["Item"].get("rule") for c in d.table.put_item.call_args_list]


def blocked_ips(d):
    return [c.kwargs["Item"]["blocked_ip"] for c in d.table.put_item.call_args_list
            if c.kwargs["Item"].get("record_type") == "BLOCK"]


def incident(d, rule):
    return next(c.kwargs["Item"] for c in d.table.put_item.call_args_list if c.kwargs["Item"].get("rule") == rule)


def failed_login(ip, username):
    return json.dumps({"event_type": "FAILED_LOGIN", "client_ip": ip, "username": username})


def test_credential_stuffing_across_many_ips_and_accounts_raises_one_spike_alert(det):
    """Moi IP va moi tai khoan chi xuat hien 1 lan: bo dem theo IP va theo tai khoan deu khong thay gi."""
    for i in range(80):
        det.evaluate_webapp_log(failed_login(f"203.0.{i}.7", f"user{i}"))
    assert rules(det) == ["LOGIN_FAILURE_SPIKE"]
    assert blocked_ips(det) == []
    details = incident(det, "LOGIN_FAILURE_SPIKE")["details"]
    assert details["attempt_count"] == 51 and details["window_seconds"] == 300   # "vuot 50" = lan thu 51


def test_a_sustained_flood_raises_each_alert_only_once_per_window(det):
    """200 lan sai trong 1 cua so: van chi 1 canh bao brute-force va 1 canh bao spike, khong bao lien tuc."""
    for _ in range(200):
        det.evaluate_webapp_log(failed_login("203.0.113.9", "admin"))
    assert rules(det).count("BRUTE_FORCE_DETECTED") == 1 and rules(det).count("LOGIN_FAILURE_SPIKE") == 1


def not_found(ip, path):
    return json.dumps({"event_type": "NOT_FOUND", "client_ip": ip, "path": path, "status_code": 404})


def test_scanner_probing_many_missing_paths_is_blocked_once(det):
    for i in range(45):
        det.evaluate_webapp_log(not_found("203.0.113.9", f"/wp-admin/{i}.php"))
    assert rules(det).count("SCAN_DETECTED") == 1 and blocked_ips(det) == ["203.0.113.9"]
    item = incident(det, "SCAN_DETECTED")
    assert item["severity"] == "HIGH" and item["details"]["attempt_count"] == 30


def test_a_few_broken_links_are_not_a_scan(det):
    for i in range(29):
        det.evaluate_webapp_log(not_found("198.51.100.20", f"/old-page-{i}"))
    assert rules(det) == [] and blocked_ips(det) == []


def test_web_app_and_detector_agree_on_the_scan_threshold(det, monkeypatch):
    """Web app tu chan tai cho o cung nguong voi Detector; lech nhau thi mot ben chan ma ben kia khong bao."""
    import importlib
    import sys
    import types
    from pathlib import Path
    monkeypatch.setitem(sys.modules, "pyotp", types.SimpleNamespace(TOTP=object))
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "sample_app"))
    sys.modules.pop("app", None)
    app = importlib.import_module("app")
    assert app.LOCAL_SCAN_THRESHOLD == det.SCAN_THRESHOLD == 30


def test_spike_counts_every_failure_even_from_ips_that_already_tripped_brute_force(det):
    """Spec: 'tong so dang nhap sai tren toan he thong ... bat ke IP hay tai khoan nao'. 10 IP x 6 lan = 60 lan."""
    for i in range(10):
        for _ in range(6):
            det.evaluate_webapp_log(failed_login(f"203.0.113.{i + 1}", "admin"))
    assert rules(det).count("LOGIN_FAILURE_SPIKE") == 1
    assert rules(det).count("BRUTE_FORCE_DETECTED") == 10       # moi IP van bi canh bao + khoa nhu cu


def test_spike_fires_only_when_the_total_goes_over_50(det):
    """Spec: 'vuot 50 lan trong 5 phut' -> lan thu 51, khong phai lan thu 50."""
    for i in range(50):
        det.evaluate_webapp_log(failed_login(f"203.0.{i}.8", f"user{i}"))
    assert "LOGIN_FAILURE_SPIKE" not in rules(det)
    det.evaluate_webapp_log(failed_login("203.0.99.8", "user99"))
    assert rules(det) == ["LOGIN_FAILURE_SPIKE"]
