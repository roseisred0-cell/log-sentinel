"""The "System Health" cua SOC Console (chi Admin): trang thai alarm + so lan chay / loi cua Lambda, doc tu CloudWatch.

Seam 1: cloud_health.CloudHealth voi client CloudWatch gia (khong goi AWS).
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "sample_app"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
import cloud_health  # noqa: E402

NOW = datetime(2026, 11, 26, 10, 30, tzinfo=timezone.utc).timestamp()


def ts(h, m=0, day=26):
    return datetime(2026, 11, day, h, m, tzinfo=timezone.utc)


class FakeCloudWatch:
    def __init__(self):
        self.alarm_calls, self.metric_calls = [], []

    def describe_alarms(self, **kw):
        self.alarm_calls.append(kw)
        return {"MetricAlarms": [
            {"AlarmName": "LogSentinelStack-DetectorErrorsAlarm6C4B132B-JnA7S05zvTEr", "StateValue": "OK",
             "AlarmDescription": "Detector Lambda errors.", "StateUpdatedTimestamp": ts(9)},
            {"AlarmName": "LogSentinelStack-CriticalWebEventsAlarm1949B374-cvAytwrWMAwM", "StateValue": "ALARM",
             "AlarmDescription": "Critical web event.", "StateUpdatedTimestamp": ts(10, 5)},
            {"AlarmName": "LogSentinelStack-WafSyncErrorsAlarm3B3A1250-5UsCyzWGHxXr", "StateValue": "INSUFFICIENT_DATA",
             "AlarmDescription": "", "StateUpdatedTimestamp": ts(8)},
        ]}

    def get_metric_data(self, **kw):
        self.metric_calls.append(kw)
        out = []
        for q in kw["MetricDataQueries"]:
            if q["Id"] == "inv0":
                out.append({"Id": "inv0", "Timestamps": [ts(10), ts(9), ts(11, day=25)], "Values": [7.0, 3.0, 2.0]})
            elif q["Id"] == "err0":
                out.append({"Id": "err0", "Timestamps": [ts(10)], "Values": [1.0]})
            else:
                out.append({"Id": q["Id"], "Timestamps": [], "Values": []})
        return {"MetricDataResults": out}


def health(client=None, **kw):
    return cloud_health.CloudHealth(
        client or FakeCloudWatch(), alarm_prefix="LogSentinelStack-",
        functions={"Detector": "LogSentinelStack-AnomalyDetector-abc", "Governance": "LogSentinelStack-Gov-xyz"},
        region="ap-southeast-1", dashboard="LogSentinel-Overview", clock=lambda: NOW, **kw)


def test_alarms_are_read_by_stack_prefix_with_friendly_names_and_problems_first():
    cw = FakeCloudWatch()
    alarms = health(cw).summary("24h")["alarms"]
    assert cw.alarm_calls == [{"AlarmNamePrefix": "LogSentinelStack-"}]
    assert [(a["name"], a["state"]) for a in alarms] == [
        ("Critical Web Events", "ALARM"), ("WafSync Errors", "INSUFFICIENT_DATA"), ("Detector Errors", "OK")]
    assert alarms[0]["description"] == "Critical web event." and alarms[0]["updated"] == ts(10, 5).timestamp()


def test_lambda_invocations_and_errors_fill_hourly_slots_with_totals():
    cw = FakeCloudWatch()
    fns = health(cw).summary("24h")["functions"]
    q = cw.metric_calls[0]["MetricDataQueries"]
    assert {x["MetricStat"]["Metric"]["MetricName"] for x in q} == {"Invocations", "Errors"}
    assert all(x["MetricStat"]["Period"] == 3600 and x["MetricStat"]["Stat"] == "Sum" for x in q)
    detector = fns[0]
    assert detector["label"] == "Detector" and len(detector["invocations"]) == 24
    assert detector["invocations"][-1] == 7 and detector["invocations"][-2] == 3 and detector["invocations"][0] == 2
    assert (detector["total_invocations"], detector["total_errors"]) == (12, 1)
    assert fns[1]["label"] == "Governance" and fns[1]["total_invocations"] == 0


def test_seven_day_range_uses_daily_slots():
    cw = FakeCloudWatch()
    out = health(cw).summary("7d")
    assert out["slots"] == 7 and out["slot_seconds"] == 86400
    assert cw.metric_calls[0]["MetricDataQueries"][0]["MetricStat"]["Period"] == 86400


def test_result_is_cached_and_dashboard_link_points_to_the_region():
    cw = FakeCloudWatch()
    h = health(cw, cache_seconds=60)
    first = h.summary("24h")
    h.summary("24h")
    assert len(cw.alarm_calls) == 1 and len(cw.metric_calls) == 1
    assert first["dashboard_url"] == ("https://ap-southeast-1.console.aws.amazon.com/cloudwatch/home"
                                      "?region=ap-southeast-1#dashboards/dashboard/LogSentinel-Overview")


def test_unknown_range_is_rejected():
    with pytest.raises(ValueError):
        health().summary("1y")


# ------------------------------------------------ Seam 2: GET /api/health
pytest.importorskip("flask")
from .test_chat_route import build, viewer  # noqa: E402
from .test_console_accounts import get, local_admin  # noqa: E402
from .test_sample_app import env, mod  # noqa: E402,F401


def test_health_route_is_admin_only(mod, env):
    a = build(mod, env, None, system_health=health())
    assert get(a, "/api/health").status_code == 401
    viewer(a)
    assert get(a, "/api/health").status_code == 403          # nguoi xem khong thay thong tin van hanh


def test_admin_gets_alarms_lambda_metrics_and_dashboard_link(mod, env):
    a = build(mod, env, None, system_health=health())
    local_admin(a)
    body = get(a, "/api/health?range=7d&tz=420").get_json()
    assert body["slots"] == 7 and body["alarms"][0]["state"] == "ALARM"
    assert [f["label"] for f in body["functions"]] == ["Detector", "Governance"]
    assert body["dashboard_url"].endswith("#dashboards/dashboard/LogSentinel-Overview")
    assert get(a, "/api/health?range=1y").status_code == 400


def test_health_route_does_not_exist_when_not_configured_and_hides_aws_errors(mod, env):
    a = build(mod, env, None)
    local_admin(a)
    assert get(a, "/api/health").status_code == 404

    class Broken(FakeCloudWatch):
        def describe_alarms(self, **kw):
            raise RuntimeError("AccessDenied arn:aws:iam::123456789012:role/x")

    b = build(mod, env, None, system_health=health(Broken()))
    local_admin(b)
    r = get(b, "/api/health")
    assert r.status_code == 502 and "arn:" not in r.get_data(as_text=True)


def test_health_settings_are_read_from_the_environment(mod, env):
    env.update(HEALTH_ALARM_PREFIX="LogSentinelStack-", HEALTH_DASHBOARD="LogSentinel-Overview",
               HEALTH_FUNCTIONS="Detector=fn-det,Governance=fn-gov")
    cfg = mod.load_config_from_env(env)
    assert cfg.health_alarm_prefix == "LogSentinelStack-" and cfg.health_dashboard == "LogSentinel-Overview"
    assert cfg.health_functions == {"Detector": "fn-det", "Governance": "fn-gov"}


# ------------------------------------------- Seam 3: ha tang (CDK + file deploy)
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def template():
    aws_cdk = pytest.importorskip("aws_cdk")
    from aws_cdk import assertions
    from log_sentinel.log_sentinel_stack import LogSentinelStack
    app = aws_cdk.App(context={"alert_email": "ops@example.com"})
    return assertions.Template.from_stack(
        LogSentinelStack(app, "LogSentinelStack", env=aws_cdk.Environment(account="123456789012", region="ap-southeast-1")))


def _vm_statements(template):
    out = []
    for p in template.find_resources("AWS::IAM::Policy").values():
        if any(r.get("Ref", "").startswith("TargetVmRole") for r in p["Properties"].get("Roles", [])):
            out += p["Properties"]["PolicyDocument"]["Statement"]
    return out


def test_instance_may_only_read_cloudwatch_alarms_of_this_stack_and_lambda_metrics(template):
    stmts = [s for s in _vm_statements(template)
             if any(str(a).startswith("cloudwatch:") for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]]))]
    actions = {a for s in stmts for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])}
    assert actions == {"cloudwatch:DescribeAlarms", "cloudwatch:GetMetricData"}       # chi doc
    alarm_stmt = next(s for s in stmts if "cloudwatch:DescribeAlarms" in str(s["Action"]))
    assert "alarm:LogSentinelStack-*" in str(alarm_stmt["Resource"])


def test_health_settings_reach_the_instance(template):
    instance = str(template.find_resources("AWS::EC2::Instance"))
    assert "HEALTH_ALARM_PREFIX=LogSentinelStack-" in instance and "HEALTH_DASHBOARD=LogSentinel-Overview" in instance
    assert "HEALTH_FUNCTIONS=Detector=" in instance and ",Governance=" in instance
    bootstrap = (ROOT / "sample_app" / "deploy" / "bootstrap.sh").read_text(encoding="utf-8")
    for key in ("HEALTH_ALARM_PREFIX", "HEALTH_FUNCTIONS", "HEALTH_DASHBOARD"):
        assert f"{key}=${{{key}:-}}" in bootstrap


# ------------------------------------------------ Seam 4: giao dien (kiem tra tinh)
def test_console_has_an_admin_only_health_card_rendered_safely():
    html = (SRC / "templates" / "console.html").read_text(encoding="utf-8")
    js = (SRC / "static" / "console.js").read_text(encoding="utf-8")
    card = html.split('id="health-card"')[1].split("</section>")[0]
    assert html.split('id="health-card"')[1].split(">")[0].strip().endswith("hidden")   # an mac dinh
    for element_id in ("health-alarms", "health-functions", "health-note", "health-dashboard", "health-range"):
        assert f'id="{element_id}"' in card
    assert 'rel="noopener noreferrer"' in card and 'target="_blank"' in card
    assert '"/api/health?range="' in js and 'role === "admin"' in js
    assert "Open in CloudWatch" in card and "System Health" in card
    assert ".innerHTML" not in js
