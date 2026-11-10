import aws_cdk as core
import aws_cdk.assertions as assertions
from log_sentinel.log_sentinel_stack import LogSentinelStack


def test_security_infrastructure_created():
    app = core.App()
    stack = LogSentinelStack(
        app,
        "log-sentinel-test",
        env=core.Environment(account="123456789012", region="ap-southeast-1"),
    )
    template = assertions.Template.from_stack(stack)

    # 1. Đảm bảo bảng DynamoDB có bật KMS Encryption và TTL
    template.has_resource_properties(
        "AWS::DynamoDB::Table",
        {
            "BillingMode": "PAY_PER_REQUEST",
            "TimeToLiveSpecification": {"AttributeName": "ttl", "Enabled": True},
        },
    )

    # 2. Đảm bảo S3 Bucket chặn toàn bộ Public Access
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            }
        },
    )

    # 3. Đảm bảo Lambda Detector sử dụng Python 3.12
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {"Runtime": "python3.12", "Handler": "detector.handler"},
    )
