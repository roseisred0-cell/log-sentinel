"""Tong hop su co cho the "Thong ke su co" cua SOC Console.

- Cot xep chong: so su co moi o thoi gian, tach theo muc do (CRITICAL / HIGH / Khac).
- Ma tran: luat x o thoi gian.
O theo gio (24 gio qua) hoac theo ngay (7 / 30 ngay qua; ranh gioi ngay theo mui gio nguoi xem).
Tinh tren may chu de trinh duyet chi nhan vai chuc con so (khong tai ca nghin ban ghi).
"""
from datetime import datetime

OTHER = "Other"
UNKNOWN = "(unknown)"
SEVERITIES = ("CRITICAL", "HIGH")   # muc Detector sinh ra; muc khac (neu co) gop vao "Khac"


def _epoch(value):
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return None


def window_start(now: float, slots: int, slot_seconds: int, tz_minutes: int = 0) -> int:
    """Dau o dau tien; o cuoi cung chua `now`. Can theo gio dia phuong: ngay bat dau luc 00:00 cua nguoi xem."""
    shift = tz_minutes * 60
    return ((int(now) + shift) // slot_seconds - (slots - 1)) * slot_seconds - shift


def summarize(items, now: float, slots: int = 24, slot_seconds: int = 3600, tz_minutes: int = 0,
              max_rules: int = 8) -> dict:
    """Nhieu hon `max_rules` luat -> giu (max_rules - 1) luat nhieu nhat + "Khac"."""
    start = window_start(now, slots, slot_seconds, tz_minutes)
    series = {name: [0] * slots for name in SEVERITIES + (OTHER,)}
    per_rule = {}
    for item in items:
        ts = _epoch(item.get("timestamp"))
        if ts is None or ts < start:
            continue
        slot = int(ts - start) // slot_seconds
        if slot >= slots:
            continue
        severity = item.get("severity")
        series[severity if severity in SEVERITIES else OTHER][slot] += 1
        rule = str(item.get("rule") or UNKNOWN)[:64]
        per_rule.setdefault(rule, [0] * slots)[slot] += 1

    by_slot = [sum(series[name][i] for name in series) for i in range(slots)]
    ranked = sorted(per_rule.items(), key=lambda kv: (-sum(kv[1]), kv[0]))
    if len(ranked) > max_rules:
        head, tail = ranked[:max_rules - 1], ranked[max_rules - 1:]
        ranked = head + [(OTHER, [sum(counts[i] for _, counts in tail) for i in range(slots)])]
    rules = [{"rule": rule, "counts": counts, "total": sum(counts)} for rule, counts in ranked]
    return {"window_start": start, "slots": slots, "slot_seconds": slot_seconds,
            "by_slot": by_slot, "series": series, "total": sum(by_slot), "max_slot": max(by_slot, default=0),
            "rules": rules, "max_cell": max((c for r in rules for c in r["counts"]), default=0)}
