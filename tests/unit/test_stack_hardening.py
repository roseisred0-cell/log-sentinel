"""Test hardening ha tang (A). Can aws-cdk-lib: pip install -r requirements.txt."""
import aws_cdk as core
import aws_cdk.assertions as assertions
import pytest
from log_sentinel.log_sentinel_stack import LogSentinelStack

ENV = core.Environment(account="123456789012", region="ap-southeast-1")


def _template(**context):
    app = core.App(context=context)
    return assertions.Template.from_stack(LogSentinelStack(app, "hardening-test", env=ENV))


@pytest.fixture(scope="module")
def template():
    return _template(alert_email="soc@example.com", admin_cidr="203.0.113.10/32")


def test_only_https_443_is_open(template):
    sgs = template.find_resources("AWS::EC2::SecurityGroup")
    ingress = [r for sg in sgs.values() for r in sg["Properties"].get("SecurityGroupIngress", [])]
    assert ingress, "target SG phai co rule 443"
    assert all(r["FromPort"] == 443 and r["ToPort"] == 443 for r in ingress)


def test_ec2_imdsv2_and_encrypted_ebs(template):
    template.has_resource_properties("AWS::EC2::LaunchTemplate", {
        "LaunchTemplateData": assertions.Match.object_like({
            "MetadataOptions": assertions.Match.object_like({"HttpTokens": "required"})})})
    template.has_resource_properties("AWS::EC2::Instance", {
        "BlockDeviceMappings": [assertions.Match.object_like({
            "Ebs": assertions.Match.object_like({"Encrypted": True, "VolumeType": "gp3"})})]})


def test_trail_is_multi_region_global_kms_validated(template):
    template.has_resource_properties("AWS::CloudTrail::Trail", {
        "IsMultiRegionTrail": True,
        "IncludeGlobalServiceEvents": True,
        "EnableLogFileValidation": True,
        "KMSKeyId": assertions.Match.any_value()})


def test_kms_key_policy_allows_cloudtrail(template):
    keys = template.find_resources("AWS::KMS::Key")
    assert any("cloudtrail.amazonaws.com" in str(k) for k in keys.values())


def test_no_managed_policy_lets_vm_write_any_log_group(template):
    assert "CloudWatchAgentServerPolicy" not in str(template.to_json())


def test_detector_cannot_scan_or_delete_incidents(template):
    policies = str(template.find_resources("AWS::IAM::Policy"))
    for forbidden in ("dynamodb:Scan", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"):
        assert forbidden not in policies


def test_detector_gets_admin_allowlist(template):
    template.has_resource_properties("AWS::Lambda::Function", {
        "Environment": {"Variables": assertions.Match.object_like(
            {"BLOCK_ALLOWLIST_CIDRS": "203.0.113.10/32"})}})


def test_email_comes_from_context_not_source(template):
    template.has_resource_properties("AWS::SNS::Subscription", {"Protocol": "email", "Endpoint": "soc@example.com"})


def test_no_email_context_means_no_subscription():
    _template().resource_count_is("AWS::SNS::Subscription", 0)


def test_user_data_runs_bootstrap_from_asset(template):
    assert "deploy/bootstrap.sh" in str(template.find_resources("AWS::EC2::Instance"))
