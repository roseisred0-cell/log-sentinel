"""
Dong bo IP dang bi SOAR khoa (DynamoDB) -> AWS WAF IP set gan vao CloudFront.

Vi sao can: lenh khoa trong web app chi tra 403 SAU KHI request da toi may. Dua IP len WAF thi request bi chan
ngay tai bien cua AWS, khong ton CPU cua may va khong the dung de lam nghen may.

Chay moi phut (EventBridge). La noi DUY NHAT ghi vao IP set, nen ba truong hop deu tu dung:
    Detector khoa IP moi      -> co mat tren WAF trong <= 1 phut (trong luc do web app van tu chan)
    Lenh khoa het han 24h     -> tu roi khoi WAF
    Quan tri go khoa o Console -> tu roi khoi WAF

    desired_addresses(now)  - doc DynamoDB, tra ve danh sach CIDR can co
    handler(event, context) - so voi IP set hien tai, chi goi UpdateIPSet khi khac nhau
"""
import ipaddress
import os
import time

import boto3

TABLE_NAME = os.environ.get("INCIDENT_TABLE", "")
IP_SET_NAME = os.environ.get("WAF_IP_SET_NAME", "")
IP_SET_ID = os.environ.get("WAF_IP_SET_ID", "")
WAF_SCOPE = "CLOUDFRONT"
MAX_ADDRESSES = 10_000   # gioi han cua 1 IP set
MAX_PAGES = 50

table = boto3.resource("dynamodb").Table(TABLE_NAME) if TABLE_NAME else None
# WAF cho CloudFront la tai nguyen toan cau, API luon o us-east-1.
waf = boto3.client("wafv2", region_name="us-east-1")


def _ipv4_cidr(raw):
    """Chi nhan IPv4 hop le (distribution tat IPv6; IP set khai bao IPV4). Mot dia chi sai dinh dang
    se lam WAF tu choi CA danh sach, nen loc tung muc o day."""
    try:
        ip = ipaddress.ip_address(str(raw).strip())
    except ValueError:
        return None
    if ip.version != 4 or ip.is_loopback or ip.is_unspecified or ip.is_link_local:
        return None
    return f"{ip}/32"


def desired_addresses(now: int) -> list:
    from boto3.dynamodb.conditions import Key

    found, start_key = {}, None
    for _ in range(MAX_PAGES):
        kwargs = {"IndexName": "by_type", "KeyConditionExpression": Key("record_type").eq("BLOCK"),
                  "ScanIndexForward": False}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        page = table.query(**kwargs)
        for item in page.get("Items", []):
            cidr = _ipv4_cidr(item.get("blocked_ip"))
            # DynamoDB co the tre toi 48h moi xoa item het han -> tu so ttl.
            if cidr and int(item.get("ttl", 0)) > now:
                found.setdefault(cidr, str(item.get("blocked_at", "")))
        start_key = page.get("LastEvaluatedKey")
        if not start_key:
            break
    # Qua gioi han: giu cac lenh khoa moi nhat.
    newest_first = sorted(found, key=lambda c: found[c], reverse=True)[:MAX_ADDRESSES]
    return sorted(newest_first)


def _is_lock_conflict(exc: Exception) -> bool:
    return getattr(exc, "response", {}).get("Error", {}).get("Code") == "WAFOptimisticLockException"


def handler(event, context):
    """Loi (DynamoDB / WAF) duoc NEM ra de metric Errors tang va alarm bao: WAF dang khong duoc cap nhat."""
    if not (table and IP_SET_NAME and IP_SET_ID):
        raise RuntimeError("Thieu INCIDENT_TABLE / WAF_IP_SET_NAME / WAF_IP_SET_ID")
    desired = desired_addresses(int(time.time()))

    for attempt in range(3):
        current = waf.get_ip_set(Name=IP_SET_NAME, Scope=WAF_SCOPE, Id=IP_SET_ID)
        if sorted(current["IPSet"].get("Addresses", [])) == desired:
            return {"changed": False, "count": len(desired)}
        try:
            waf.update_ip_set(Name=IP_SET_NAME, Scope=WAF_SCOPE, Id=IP_SET_ID,
                              Addresses=desired, LockToken=current["LockToken"])
        except Exception as exc:
            if _is_lock_conflict(exc) and attempt < 2:
                continue   # ai do vua sua IP set -> doc lai roi thu lai
            raise
        print(f"[WAF] Da cap nhat IP set: {len(desired)} dia chi")
        return {"changed": True, "count": len(desired)}
