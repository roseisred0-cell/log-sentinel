"""Test CloudWatch Alarm + kiem tra bao mat phan B (chay can aws-cdk-lib, giong test cua A)."""
import aws_cdk as core
import aws_cdk.assertions as assertions
import pytest
from log_sentinel.log_sentinel_stack import LogSentinelStack


@pytest.fixture(scope="module")
def template():
    app = core.App()
    stack = LogSentinelStack(app, "log-sentinel-b-test",
                             env=core.Environment(account="123456789012", region="ap-southeast-1"))
    return assertions.Template.from_stack(stack)


def test_three_alarms_exist_and_notify_sns(template):
    template.resource_count_is("AWS::CloudWatch::Alarm", 3)
    alarms = template.find_resources("AWS::CloudWatch::Alarm")
    for alarm in alarms.values():
        assert alarm["Properties"]["AlarmActions"], "moi alarm phai gan SNS action"
        assert alarm["Properties"]["TreatMissingData"] == "notBreaching"


def test_detector_error_alarm_watches_lambda_errors(template):
    template.has_resource_properties("AWS::CloudWatch::Alarm", {
        "MetricName": "Errors", "Namespace": "AWS/Lambda", "Threshold": 1})


def test_metric_filters_for_critical_events_and_trail_tampering(template):
    template.resource_count_is("AWS::Logs::MetricFilter", 2)
    template.has_resource_properties("AWS::Logs::MetricFilter", {
        "FilterPattern": assertions.Match.string_like_regexp("MFA_BYPASS_ATTEMPT.*SQL_INJECTION"),
        "MetricTransformations": [assertions.Match.object_like({"MetricName": "CriticalWebEvents"})]})
    template.has_resource_properties("AWS::Logs::MetricFilter", {
        "FilterPattern": assertions.Match.string_like_regexp("StopLogging.*DeleteTrail"),
        "MetricTransformations": [assertions.Match.object_like({"MetricName": "CloudTrailTampering"})]})


# ---- kiem tra bao mat bo sung
def test_kms_key_rotation_enabled(template):
    template.has_resource_properties("AWS::KMS::Key", {"EnableKeyRotation": True})


def test_s3_bucket_enforces_ssl(template):
    policies = template.find_resources("AWS::S3::BucketPolicy")
    assert any("aws:SecureTransport" in str(p) for p in policies.values())


def test_cloudtrail_logging_to_cloudwatch(template):
    template.has_resource_properties("AWS::CloudTrail::Trail", {
        "IsLogging": True,
        "CloudWatchLogsLogGroupArn": assertions.Match.any_value()})


def test_detector_can_read_telegram_secret(template):
    # Lambda phai co SECRET_ARN trong bien moi truong de gui Telegram
    template.has_resource_properties("AWS::Lambda::Function", {
        "Environment": {"Variables": assertions.Match.object_like({"SECRET_ARN": assertions.Match.any_value()})}})
