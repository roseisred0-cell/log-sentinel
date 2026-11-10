"""
Bước 6 Kế hoạch: Kịch bản kiểm thử Luật Bảo mật CloudTrail (iam_tamper.py)
Giả lập 6 hành vi xâm nhập quản trị AWS (khớp 6 nhóm luật của Detector):
1. ConsoleLogin không có MFA (MFAUsed = No)
2. Gỡ thiết bị xác thực 2 yếu tố (DeactivateMFADevice)
3. Cố tình tắt ghi nhận nhật ký kiểm toán (StopLogging)
4-6. Leo thang đặc quyền IAM: CreateAccessKey, AttachUserPolicy (AdministratorAccess), PutUserPolicy
Account ID trong script là số mẫu (sanitized) - không dùng Account thật.
"""
from datetime import datetime, timezone
import json
import time
import boto3

LOG_GROUP = "/logsentinel/cloudtrail"
REGION = "ap-southeast-1"


def run_iam_tamper_suite():
    logs_client = boto3.client("logs", region_name=REGION)
    stream_name = f"iam-tamper-test-{int(time.time())}"
    logs_client.create_log_stream(logGroupName=LOG_GROUP, logStreamName=stream_name)

    attack_events = [
        {
            "eventVersion": "1.08",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": "compromised_dev_user"},
            "additionalEventData": {"MFAUsed": "No", "LoginResult": "Success"},
            "sourceIPAddress": "203.0.113.55",
        },
        {
            "eventVersion": "1.08",
            "eventName": "DeactivateMFADevice",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": "attacker_escalated"},
            "requestParameters": {"userName": "admin", "serialNumber": "arn:aws:iam::123456789012:mfa/AdminPhone"},
            "sourceIPAddress": "203.0.113.55",
        },
        {
            "eventVersion": "1.08",
            "eventName": "StopLogging",
            "eventSource": "cloudtrail.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": "attacker_escalated"},
            "requestParameters": {"name": "AccountActivityTrail"},
            "sourceIPAddress": "203.0.113.55",
        },
        {
            "eventVersion": "1.08",
            "eventName": "CreateAccessKey",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": "attacker_escalated"},
            "requestParameters": {"userName": "backdoor_user"},
            "sourceIPAddress": "203.0.113.55",
        },
        {
            "eventVersion": "1.08",
            "eventName": "AttachUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": "attacker_escalated"},
            "requestParameters": {"userName": "backdoor_user",
                                  "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            "sourceIPAddress": "203.0.113.55",
        },
        {
            "eventVersion": "1.08",
            "eventName": "PutUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "userName": "attacker_escalated"},
            "requestParameters": {"userName": "backdoor_user", "policyName": "inline-full-access"},
            "sourceIPAddress": "203.0.113.55",
        },
    ]
    started_at = datetime.now(timezone.utc).isoformat()

    log_entries = [
        {"timestamp": int(time.time() * 1000) + idx * 100, "message": json.dumps(ev)}
        for idx, ev in enumerate(attack_events)
    ]

    print(f"[+] Dang bom {len(log_entries)} su kien tan cong CloudTrail vao {LOG_GROUP}...")
    logs_client.put_log_events(
        logGroupName=LOG_GROUP,
        logStreamName=stream_name,
        logEvents=log_entries,
    )
    print("[OK] Da gui thanh cong! Cho 10 giay de Lambda phan tich va ghi vao DynamoDB...")
    time.sleep(10)

    cfn = boto3.client("cloudformation", region_name=REGION)
    stacks = cfn.describe_stacks(StackName="LogSentinelStack")["Stacks"][0]["Outputs"]
    table_name = next(o["OutputValue"] for o in stacks if o["OutputKey"] == "IncidentTableName")

    dynamodb = boto3.resource("dynamodb", region_name=REGION)
    table = dynamodb.Table(table_name)
    items, kwargs = [], {}
    while True:  # bang demo nho; scan het roi loc theo thoi diem chay script
        page = table.scan(**kwargs)
        items += page.get("Items", [])
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    items = [i for i in items if str(i.get("timestamp", "")) >= started_at and i.get("severity")]

    print(f"\n=== KET QUA KIEM TRA BANG DYNAMODB ({table_name}) ===")
    print(f"So su co moi tu lan chay nay: {len(items)} (ky vong 6)")
    for item in sorted(items, key=lambda x: x.get("timestamp", ""), reverse=True):
        print(f" - [{item.get('severity', 'HIGH')}] {item.get('timestamp')} | Rule: {item.get('rule')}")


if __name__ == "__main__":
    run_iam_tamper_suite()
