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


def _statements(template, logical_id_prefix):
    policies = template.find_resources("AWS::IAM::Policy")
    return [st for name, p in policies.items() if name.startswith(logical_id_prefix)
            for st in p["Properties"]["PolicyDocument"]["Statement"]]


def _actions(statement):
    a = statement["Action"]
    return a if isinstance(a, list) else [a]


def test_nobody_can_scan_the_incident_table(template):
    assert "dynamodb:Scan" not in str(template.find_resources("AWS::IAM::Policy"))


def test_detector_cannot_delete_incidents(template):
    actions = [a for st in _statements(template, "AnomalyDetectorLambda") for a in _actions(st)]
    assert "dynamodb:PutItem" in actions
    assert not any(a in actions for a in ("dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:BatchWriteItem"))


def test_vm_can_only_delete_block_items(template):
    deletes = [st for st in _statements(template, "TargetVmRole") if "dynamodb:DeleteItem" in _actions(st)]
    assert len(deletes) == 1
    assert deletes[0]["Condition"] == {"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["BLOCKED_IP#*"]}}


def test_console_index_exists(template):
    template.has_resource_properties("AWS::DynamoDB::Table", {
        "GlobalSecondaryIndexes": [assertions.Match.object_like({"IndexName": "by_type"})]})


def test_app_logs_archived_to_s3_via_firehose():
    template = _template(enable_app_log_archive="true")
    template.resource_count_is("AWS::KinesisFirehose::DeliveryStream", 1)
    template.has_resource_properties("AWS::KinesisFirehose::DeliveryStream", {
        "ExtendedS3DestinationConfiguration": assertions.Match.object_like({"Prefix": "app-logs/!{timestamp:yyyy/MM/dd}/"})})
    # 1 filter -> Lambda (app), 1 -> Lambda (cloudtrail), 1 -> Firehose. Gioi han AWS: 2 filter / log group.
    template.resource_count_is("AWS::Logs::SubscriptionFilter", 3)


def test_firehose_archive_is_opt_in(template):
    template.resource_count_is("AWS::KinesisFirehose::DeliveryStream", 0)
    template.resource_count_is("AWS::Logs::SubscriptionFilter", 2)


def test_reserved_concurrency_is_opt_in():
    fn = lambda t: [f for f in t.find_resources("AWS::Lambda::Function").values()  # noqa: E731
                    if f["Properties"].get("Handler") == "detector.handler"][0]["Properties"]
    assert "ReservedConcurrentExecutions" not in fn(_template())
    assert fn(_template(detector_max_concurrency="5"))["ReservedConcurrentExecutions"] == 5


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


# ----------------------------------------------------------------- Cognito
def test_user_pool_allows_signup_with_optional_totp_only(template):
    template.has_resource_properties("AWS::Cognito::UserPool", {
        "MfaConfiguration": "OPTIONAL",
        "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],          # khong SMS: khong phat sinh chi phi / lo so dien thoai
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": False},
        "AutoVerifiedAttributes": ["email"],
        "UsernameAttributes": ["email"],
        "Policies": {"PasswordPolicy": assertions.Match.object_like({
            "MinimumLength": 8, "RequireLowercase": True, "RequireUppercase": True, "RequireNumbers": True})}})


def test_user_pool_client_is_public_without_secret_and_hides_user_existence(template):
    template.has_resource_properties("AWS::Cognito::UserPoolClient", {
        "GenerateSecret": False,
        "ExplicitAuthFlows": assertions.Match.array_with(["ALLOW_USER_PASSWORD_AUTH"]),
        "PreventUserExistenceErrors": "ENABLED",
        "EnableTokenRevocation": True})


def test_roles_are_cognito_groups(template):
    template.resource_count_is("AWS::Cognito::UserPoolGroup", 2)
    for name in ("soc-viewers", "soc-admins"):
        template.has_resource_properties("AWS::Cognito::UserPoolGroup", {"GroupName": name})


def test_vm_cognito_permissions_are_scoped_to_the_pool_and_exclude_destructive_calls(template):
    stmts = [st for st in _statements(template, "TargetVmRole") if any(a.startswith("cognito-idp:") for a in _actions(st))]
    assert len(stmts) == 1
    assert sorted(_actions(stmts[0])) == sorted([
        "cognito-idp:ListUsers", "cognito-idp:ListUsersInGroup",
        "cognito-idp:AdminAddUserToGroup", "cognito-idp:AdminRemoveUserFromGroup"])
    assert stmts[0]["Resource"] != "*" and "ConsoleUserPool" in str(stmts[0]["Resource"])


def test_web_app_receives_cognito_ids_via_user_data(template):
    instance = str(template.find_resources("AWS::EC2::Instance"))
    assert "COGNITO_USER_POOL_ID=" in instance and "COGNITO_CLIENT_ID=" in instance
    template.has_output("UserPoolId", {})
    template.has_output("UserPoolClientId", {})
