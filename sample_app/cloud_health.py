"""The "System Health" cua SOC Console (chi Admin): doc CloudWatch bang role IAM cua EC2 (chi doc).

- Trang thai alarm cua stack (tim theo tien to ten stack: alarm do CDK sinh ra deu bat dau bang ten stack).
- So lan chay / loi cua cac Lambda theo gio (24 gio) hoac theo ngay (7 ngay).
Ket qua luu tam vai phut: nhieu admin mo Console cung luc chi ton 1 luot goi API CloudWatch.
Khong nhung (iframe) dashboard AWS: giu nguyen CSP cua Console, va du lieu van nam sau lop dang nhap.
"""
import re
import threading
import time
from datetime import datetime
from typing import Callable, Dict

from incident_stats import window_start

RANGES = {"24h": (24, 3600), "7d": (7, 86400)}
STATE_ORDER = {"ALARM": 0, "INSUFFICIENT_DATA": 1, "OK": 2}
_SERVICE_NAMES = (("Cloud Trail", "CloudTrail"), ("Waf Sync", "WafSync"), ("Dynamo DB", "DynamoDB"))
_HASH_SUFFIX = re.compile(r"(Alarm)?[0-9A-F]{8}(-[A-Za-z0-9]+)?$")


def _friendly(name: str, prefix: str) -> str:
    """'LogSentinelStack-DetectorErrorsAlarm6C4B132B-JnA7S05z' -> 'Detector Errors'."""
    short = name[len(prefix):] if name.startswith(prefix) else name
    short = _HASH_SUFFIX.sub("", short) or short
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", short)
    for split, name in _SERVICE_NAMES:   # giu nguyen ten dich vu: "CloudTrail", "WafSync"
        words = words.replace(split, name)
    return words


def _epoch(value) -> float:
    if isinstance(value, datetime):
        return value.timestamp()
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


class CloudHealth:
    def __init__(self, client, alarm_prefix: str, functions: Dict[str, str], region: str, dashboard: str = "",
                 clock: Callable[[], float] = time.time, cache_seconds: int = 120):
        self._client = client
        self._prefix = alarm_prefix
        self._functions = functions
        self._region = region
        self._dashboard = dashboard
        self._clock = clock
        self._ttl = cache_seconds
        self._cache = {}
        self._lock = threading.Lock()

    def _cw(self):
        if self._client is None:
            import boto3  # import tre: test khong can boto3
            self._client = boto3.client("cloudwatch", region_name=self._region)
        return self._client

    def summary(self, rng: str = "24h", tz_minutes: int = 0) -> dict:
        if rng not in RANGES:
            raise ValueError(rng)
        now = self._clock()
        key = (rng, tz_minutes)
        with self._lock:
            hit = self._cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
        slots, slot_seconds = RANGES[rng]
        start = window_start(now, slots, slot_seconds, tz_minutes)
        out = {"range": rng, "slots": slots, "slot_seconds": slot_seconds, "window_start": start,
               "alarms": self._alarms(), "functions": self._lambda_metrics(start, now, slots, slot_seconds),
               "dashboard_url": self._dashboard_url(), "checked_at": now}
        with self._lock:
            if len(self._cache) >= 16:
                self._cache.clear()
            self._cache[key] = (now + self._ttl, out)
        return out

    def _alarms(self) -> list:
        res = self._cw().describe_alarms(AlarmNamePrefix=self._prefix)
        alarms = [{"name": _friendly(a.get("AlarmName", ""), self._prefix),
                   "state": a.get("StateValue", "INSUFFICIENT_DATA"),
                   "description": str(a.get("AlarmDescription") or "")[:300],
                   "updated": _epoch(a.get("StateUpdatedTimestamp"))}
                  for a in res.get("MetricAlarms", [])]
        return sorted(alarms, key=lambda a: (STATE_ORDER.get(a["state"], 1), a["name"]))

    def _lambda_metrics(self, start: float, now: float, slots: int, slot_seconds: int) -> list:
        if not self._functions:
            return []
        labels = list(self._functions)
        queries = []
        for i, label in enumerate(labels):
            for metric, qid in (("Invocations", f"inv{i}"), ("Errors", f"err{i}")):
                queries.append({"Id": qid, "ReturnData": True, "MetricStat": {
                    "Metric": {"Namespace": "AWS/Lambda", "MetricName": metric,
                               "Dimensions": [{"Name": "FunctionName", "Value": self._functions[label]}]},
                    "Period": slot_seconds, "Stat": "Sum"}})
        res = self._cw().get_metric_data(MetricDataQueries=queries, StartTime=datetime.fromtimestamp(start).astimezone(),
                                         EndTime=datetime.fromtimestamp(now).astimezone())
        series = {r["Id"]: r for r in res.get("MetricDataResults", [])}

        def fill(qid):
            values = [0] * slots
            r = series.get(qid, {})
            for t, v in zip(r.get("Timestamps", []), r.get("Values", [])):
                slot = int(_epoch(t) - start) // slot_seconds
                if 0 <= slot < slots:
                    values[slot] += int(round(v))
            return values

        out = []
        for i, label in enumerate(labels):
            inv, err = fill(f"inv{i}"), fill(f"err{i}")
            out.append({"label": label, "invocations": inv, "errors": err,
                        "total_invocations": sum(inv), "total_errors": sum(err)})
        return out

    def _dashboard_url(self) -> str:
        if not self._dashboard:
            return ""
        return (f"https://{self._region}.console.aws.amazon.com/cloudwatch/home"
                f"?region={self._region}#dashboards/dashboard/{self._dashboard}")
