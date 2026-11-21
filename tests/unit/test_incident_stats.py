"""The "Thong ke su co" trong SOC Console: cot xep chong theo muc do + ma tran luat x thoi gian.

Khoang: 24 gio (o theo gio), 7 ngay / 30 ngay (o theo ngay, ranh gioi ngay theo mui gio nguoi xem).
Seam 1: incident_stats.summarize(items, now, ...) voi ban ghi DynamoDB gia.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "sample_app"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
import incident_stats  # noqa: E402

NOW = datetime(2026, 11, 19, 15, 40, tzinfo=timezone.utc).timestamp()   # 15:40 UTC


def inc(rule, hh_mm, day=19, severity="HIGH"):
    h, m = map(int, hh_mm.split(":"))
    ts = datetime(2026, 11, day, h, m, tzinfo=timezone.utc).isoformat()
    return {"incident_id": f"INC#{rule}{day}{hh_mm}", "timestamp": ts, "rule": rule, "severity": severity}


def test_counts_incidents_per_hour_over_the_last_24_hours_oldest_first():
    s = incident_stats.summarize([inc("SQL_INJECTION", "15:05"), inc("SQL_INJECTION", "15:30"),
                                  inc("BRUTE_FORCE_DETECTED", "14:59"), inc("SCAN_DETECTED", "16:10", day=18)], NOW)
    assert s["window_start"] == datetime(2026, 11, 18, 16, 0, tzinfo=timezone.utc).timestamp()   # 24 o gio, o cuoi chua 15:40
    assert (s["slots"], s["slot_seconds"]) == (24, 3600)
    assert len(s["by_slot"]) == 24 and s["total"] == 4
    assert s["by_slot"][-1] == 2 and s["by_slot"][-2] == 1 and s["by_slot"][0] == 1


def test_matrix_has_one_row_per_rule_sorted_by_total_and_folds_the_tail_into_other():
    items = ([inc("SQL_INJECTION", "15:05")] * 3 + [inc("BRUTE_FORCE_DETECTED", "10:00")] * 2
             + [inc("SCAN_DETECTED", "09:00"), inc("ROOT_ACCOUNT_LOGIN", "09:30"), inc("MFA_TAMPERING", "08:00")])
    s = incident_stats.summarize(items, NOW, max_rules=3)
    assert [(r["rule"], r["total"]) for r in s["rules"]] == [
        ("SQL_INJECTION", 3), ("BRUTE_FORCE_DETECTED", 2), ("Khác", 3)]     # 2 luat dau + phan con lai
    sql = s["rules"][0]["counts"]
    assert len(sql) == 24 and sql[-1] == 3 and sum(sql) == 3
    assert s["max_cell"] == 3                                              # de to mau ma tran


def test_ignores_broken_records_and_incidents_older_than_the_window():
    items = [inc("SQL_INJECTION", "15:00"), inc("SQL_INJECTION", "15:00", day=17),
             {"rule": "X", "timestamp": "khong-phai-ngay"}, {"rule": "Y"}, {"timestamp": inc("A", "12:00")["timestamp"]}]
    s = incident_stats.summarize(items, NOW)
    assert s["total"] == 2
    assert {r["rule"] for r in s["rules"]} == {"SQL_INJECTION", "(không rõ)"}


def test_each_slot_is_split_by_severity_for_the_stacked_columns():
    items = [inc("SQL_INJECTION", "15:05", severity="CRITICAL"), inc("BRUTE_FORCE_DETECTED", "15:10"),
             inc("BRUTE_FORCE_DETECTED", "15:20"), inc("X", "15:30", severity="MEDIUM"), inc("Y", "14:00", severity=None)]
    s = incident_stats.summarize(items, NOW)
    assert list(s["series"]) == ["CRITICAL", "HIGH", "Khác"]              # thu tu xep chong co dinh
    assert [s["series"][k][-1] for k in ("CRITICAL", "HIGH", "Khác")] == [1, 2, 1]
    assert s["series"]["Khác"][-2] == 1 and s["max_slot"] == 4


def test_day_slots_follow_the_viewers_timezone_for_7_and_30_days():
    vn = 7 * 60                                                              # UTC+7
    items = [inc("A", "16:30", day=19),       # 23:30 ngay 19 gio VN
             inc("A", "17:30", day=19),       # 00:30 ngay 20 gio VN -> o cuoi
             inc("B", "18:00", day=13)]       # 01:00 ngay 14 gio VN
    now = datetime(2026, 11, 19, 18, 0, tzinfo=timezone.utc).timestamp()   # 01:00 ngay 20 gio VN
    s = incident_stats.summarize(items, now, slots=7, slot_seconds=86400, tz_minutes=vn)
    assert s["window_start"] == datetime(2026, 11, 13, 17, 0, tzinfo=timezone.utc).timestamp()  # 00:00 ngay 14 gio VN
    assert s["by_slot"] == [1, 0, 0, 0, 0, 1, 1] and s["slots"] == 7
    assert len(incident_stats.summarize([], now, slots=30, slot_seconds=86400)["by_slot"]) == 30


# ------------------------------------------------ Seam 2: GET /api/stats
import pytest  # noqa: E402

pytest.importorskip("flask")
from .test_chat_route import build, viewer  # noqa: E402
from .test_console_accounts import get, post, sign_in  # noqa: E402
from .test_sample_app import env, mod  # noqa: E402,F401


def test_stats_route_defaults_to_24_hourly_slots_for_viewers(mod, env):
    a = build(mod, env, None)
    viewer(a)
    r = get(a, "/api/stats")
    assert r.status_code == 200
    body = r.get_json()
    assert (body["range"], body["slots"], body["slot_seconds"], body["limit"]) == ("24h", 24, 3600, 1000)
    assert set(body["series"]) == {"CRITICAL", "HIGH", "Khác"} and "truncated" in body


def _spy(a):
    calls = []
    real = a.store.incidents_since
    a.store.incidents_since = lambda since, limit: calls.append((since, limit)) or real(since, limit)
    return calls


@pytest.mark.parametrize("rng,slots", [("7d", 7), ("30d", 30)])
def test_week_and_month_use_daily_slots_read_up_to_5000_and_are_cached_for_5_minutes(mod, env, rng, slots):
    a = build(mod, env, None)
    viewer(a)
    calls = _spy(a)
    body = get(a, f"/api/stats?range={rng}&tz=420").get_json()
    assert (body["range"], body["slots"], body["slot_seconds"], body["limit"]) == (rng, slots, 86400, 5000)
    assert calls[0][1] == 5000
    get(a, f"/api/stats?range={rng}&tz=420")
    assert len(calls) == 1                         # lan 2 trong 5 phut: dung ket qua da luu
    a.clock.t += 301
    get(a, f"/api/stats?range={rng}&tz=420")
    assert len(calls) == 2


@pytest.mark.parametrize("query", ["range=1y", "range=", "tz=abc", "tz=99999", "range=7d&tz=-9999"])
def test_bad_range_or_timezone_is_rejected(mod, env, query):
    a = build(mod, env, None)
    viewer(a)
    assert get(a, f"/api/stats?{query}").status_code == 400


def test_stats_route_requires_an_approved_role(mod, env):
    a = build(mod, env, None)
    assert get(a, "/api/stats").status_code == 401
    a.identity.add("moi@x.co", role="pending")
    sign_in(a, "moi@x.co")
    assert get(a, "/api/stats").status_code == 403


def test_dynamo_store_reads_only_incidents_inside_the_window_newest_first(monkeypatch):
    from .test_governance_store import REGION, TABLE
    moto = pytest.importorskip("moto")
    import boto3
    for k, v in {"AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)
    import app as app_mod
    with moto.mock_aws():
        t = boto3.resource("dynamodb", region_name=REGION).create_table(
            TableName=TABLE, BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "incident_id", "KeyType": "HASH"}, {"AttributeName": "timestamp", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("incident_id", "timestamp", "record_type")],
            GlobalSecondaryIndexes=[{"IndexName": "by_type", "Projection": {"ProjectionType": "ALL"},
                                     "KeySchema": [{"AttributeName": "record_type", "KeyType": "HASH"},
                                                   {"AttributeName": "timestamp", "KeyType": "RANGE"}]}])
        for i, ts in enumerate(["2026-11-18T10:00:00+00:00", "2026-11-19T01:00:00+00:00", "2026-11-19T15:00:00+00:00"]):
            t.put_item(Item={"incident_id": f"INC#{i}", "timestamp": ts, "record_type": "INCIDENT", "rule": "R"})
        t.put_item(Item={"incident_id": "BLOCKED_IP#1.2.3.4", "timestamp": "2026-11-19T15:30:00+00:00", "record_type": "BLOCK"})
        store = app_mod.DynamoIncidentStore(TABLE, REGION)
        got = store.incidents_since("2026-11-18T16:00:00+00:00", limit=10)
        assert [i["incident_id"] for i in got] == ["INC#2", "INC#1"]
        assert len(store.incidents_since("2026-11-18T00:00:00+00:00", limit=2)) == 2


def test_stats_route_hides_database_errors(mod, env):
    a = build(mod, env, None)
    viewer(a)
    a.store.incidents_since = lambda since, limit: (_ for _ in ()).throw(RuntimeError("AccessDenied arn:aws:iam::123"))
    r = get(a, "/api/stats")
    assert r.status_code == 502 and "arn:" not in r.get_data(as_text=True)


# ---------------------------------------------- Seam 3: giao dien (tinh + Node)
import json as _json  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402

STATIC = SRC / "static"


def test_console_has_the_stats_card_and_loads_the_chart_script_without_innerhtml():
    html = (SRC / "templates" / "console.html").read_text(encoding="utf-8")
    for element_id in ("stats-card", "stats-hourly", "stats-matrix", "stats-table", "stats-note", "viz-tip",
                       "stats-range", "stats-legend"):
        assert f'id="{element_id}"' in html
    for rng in ("24h", "7d", "30d"):
        assert f'data-range="{rng}"' in html
    assert '<script src="/static/incident-charts.js"></script>' in html
    js = (STATIC / "incident-charts.js").read_text(encoding="utf-8") + (STATIC / "console.js").read_text(encoding="utf-8")
    assert ".innerHTML" not in js and "insertAdjacentHTML" not in js
    assert '"/api/stats?range="' in js


@pytest.mark.skipif(shutil.which("node") is None, reason="can Node.js")
def test_heatmap_buckets_zero_apart_and_scale_counts_into_five_shades():
    script = ("const m = require(process.argv[1]);"
              "process.stdout.write(JSON.stringify([[0,9],[1,9],[2,10],[5,10],[10,10],[1,1],[3,0]].map(a => m.bucket(a[0], a[1]))));")
    out = subprocess.run(["node", "-e", script, str(STATIC / "incident-charts.js")],
                         capture_output=True, text=True, check=True)
    assert _json.loads(out.stdout) == [0, 1, 1, 3, 5, 5, 0]


def test_colours_are_the_validated_ones_severity_for_columns_and_amber_for_the_matrix():
    css = (STATIC / "console.css").read_text(encoding="utf-8")
    for hex_ in ("#d03b3b", "#ec835a",                                         # CRITICAL / HIGH (bang mau trang thai)
                 "#e0a030", "#c98500", "#a86c00", "#845200", "#5e3a00",        # ho phach nen sang
                 "#7d5000", "#9c6800", "#bd8200", "#dea023", "#f6c868"):       # ho phach nen toi
        assert hex_ in css
    js = (STATIC / "incident-charts.js").read_text(encoding="utf-8")
    assert "range=" in (STATIC / "console.js").read_text(encoding="utf-8") and "getTimezoneOffset" in (STATIC / "console.js").read_text(encoding="utf-8")
    assert '"CRITICAL", "HIGH"' in js                                            # thu tu xep chong co dinh
