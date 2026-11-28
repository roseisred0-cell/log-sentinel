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


def _vm_write_prefixes(template, action):
    """Tien to khoa ma EC2 duoc `action`. Moi lenh ghi deu PHAI co dieu kien LeadingKeys (khong ghi tu do)."""
    prefixes = set()
    for st in _statements(template, "TargetVmRole"):
        if action in _actions(st):
            cond = st.get("Condition", {}).get("ForAllValues:StringLike", {}).get("dynamodb:LeadingKeys")
            assert cond, f"{action} khong co dieu kien LeadingKeys: {st}"
            prefixes.update(cond)
    return prefixes


def test_vm_can_only_delete_block_and_pin_items(template):
    # go khoa IP, dat lai PIN admin. Ban ghi su co (bang chung) va yeu cau phan quyen (dau vet) khong xoa duoc.
    assert _vm_write_prefixes(template, "dynamodb:DeleteItem") == {"BLOCKED_IP#*", "ADMIN_PIN#*"}


def test_vm_writes_are_limited_to_session_and_pin_keys(template):
    # ROLE_REQ# (yeu cau + phieu bau) chi Lambda thuc thi phan quyen ghi duoc: may bi chiem khong gia phieu.
    assert _vm_write_prefixes(template, "dynamodb:PutItem") == {"REVOKED_SESSION#*", "ADMIN_PIN#*"}
    assert _vm_write_prefixes(template, "dynamodb:UpdateItem") == {"ADMIN_PIN#*"}
    vm_actions = {a for st in _statements(template, "TargetVmRole") for a in _actions(st)}
    assert not vm_actions & {"dynamodb:BatchWriteItem", "dynamodb:*", "dynamodb:PartiQLUpdate", "dynamodb:Scan"}


def test_console_index_exists(template):
    template.has_resource_properties("AWS::DynamoDB::Table", {
        "GlobalSecondaryIndexes": [assertions.Match.object_like({"IndexName": "by_type"})]})


def test_no_firehose_delivery_stream(template):
    """Da go Firehose (12/11): khong co duong nao chep log web app ra ngoai CloudWatch."""
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
    # EC2 chi doc danh ba. Moi thay doi nhom / vo hieu hoa di qua Lambda thuc thi phan quyen (nhat ky 12/11, D1).
    assert sorted(_actions(stmts[0])) == sorted(["cognito-idp:ListUsers", "cognito-idp:ListUsersInGroup"])
    assert stmts[0]["Resource"] != "*" and "ConsoleUserPool" in str(stmts[0]["Resource"])


# ---------------------------------------- Lambda thuc thi phan quyen (D1)
def _governance_fn(template):
    fns = template.find_resources("AWS::Lambda::Function")
    return next(v for k, v in fns.items() if k.startswith("GovernanceExecutor"))


def test_governance_lambda_runs_the_shared_governance_module(template):
    props = _governance_fn(template)["Properties"]
    assert props["Handler"] == "governance_lambda.handler" and props["Runtime"] == "python3.12"
    env = props["Environment"]["Variables"]
    assert {"INCIDENT_TABLE", "COGNITO_USER_POOL_ID", "COGNITO_CLIENT_ID", "LOCAL_PRINCIPAL"} <= set(env)
    assert env["LOCAL_PRINCIPAL"] == "local:admin"


def test_only_the_governance_lambda_may_change_cognito_groups(template):
    stmts = [st for st in _statements(template, "GovernanceExecutor") if any(a.startswith("cognito-idp:") for a in _actions(st))]
    assert len(stmts) == 1
    assert sorted(_actions(stmts[0])) == sorted([
        "cognito-idp:ListUsers", "cognito-idp:ListUsersInGroup",
        "cognito-idp:AdminAddUserToGroup", "cognito-idp:AdminRemoveUserFromGroup",
        "cognito-idp:AdminDisableUser", "cognito-idp:AdminUserGlobalSignOut"])
    assert "ConsoleUserPool" in str(stmts[0]["Resource"])
    # Khong bao gio: xoa / tao user, dat mat khau, sua thuoc tinh, tat MFA cua nguoi khac.
    everything = str(template.find_resources("AWS::IAM::Policy"))
    for forbidden in ("AdminDeleteUser", "AdminCreateUser", "AdminSetUserPassword", "AdminSetUserMFAPreference",
                      "AdminUpdateUserAttributes"):
        assert forbidden not in everything


def test_governance_lambda_writes_only_role_request_keys(template):
    writes = [st for st in _statements(template, "GovernanceExecutor")
              if any(a in _actions(st) for a in ("dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"))]
    assert writes and all(st["Condition"] == {"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["ROLE_REQ#*"]}}
                          for st in writes)
    assert not any("dynamodb:DeleteItem" in _actions(st) for st in writes)


def test_vm_may_invoke_only_the_governance_lambda(template):
    invokes = [st for st in _statements(template, "TargetVmRole") if "lambda:InvokeFunction" in _actions(st)]
    assert len(invokes) == 1 and "GovernanceExecutor" in str(invokes[0]["Resource"])


def test_nothing_may_call_bedrock(template):
    """Da go tro ly AI (12/11): khong role nao co quyen goi model tren Bedrock."""
    policies = str(template.find_resources("AWS::IAM::Policy"))
    assert "bedrock" not in policies.lower()


def test_web_app_learns_the_governance_function_name_via_user_data(template):
    assert "GOVERNANCE_FUNCTION=" in str(template.find_resources("AWS::EC2::Instance"))


def test_web_app_receives_cognito_ids_via_user_data(template):
    instance = str(template.find_resources("AWS::EC2::Instance"))
    assert "COGNITO_USER_POOL_ID=" in instance and "COGNITO_CLIENT_ID=" in instance
    template.has_output("UserPoolId", {})
    template.has_output("UserPoolClientId", {})


# ------------------------------------------------------------------ Athena
def _athena_table(template):
    tables = template.find_resources("AWS::Glue::Table")
    assert len(tables) == 1
    return list(tables.values())[0]["Properties"]["TableInput"]


def test_athena_table_reads_cloudtrail_logs_from_the_archive_bucket(template):
    table = _athena_table(template)
    storage = table["StorageDescriptor"]
    assert table["Name"] == "cloudtrail_logs" and table["TableType"] == "EXTERNAL_TABLE"
    # CloudTrail ghi vao  s3://<bucket>/AWSLogs/<account>/CloudTrail/<region>/yyyy/MM/dd/
    location = str(storage["Location"])
    assert "LogArchiveBucket" in location and "/AWSLogs/123456789012/CloudTrail/" in location
    # Dinh dang theo tai lieu AWS "Create the table for CloudTrail logs in Athena using partition projection".
    assert storage["SerdeInfo"]["SerializationLibrary"] == "org.apache.hive.hcatalog.data.JsonSerDe"
    assert storage["InputFormat"] == "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    assert storage["OutputFormat"] == "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    columns = {c["Name"] for c in storage["Columns"]}
    assert {"eventtime", "eventname", "eventsource", "sourceipaddress", "useridentity", "errorcode"} <= columns


def test_athena_finds_new_days_and_regions_without_manual_partition_commands(template):
    """Partition projection: khong can ALTER TABLE / crawler. Su kien IAM toan cau nam o us-east-1."""
    table = _athena_table(template)
    params = table["Parameters"]
    assert [k["Name"] for k in table["PartitionKeys"]] == ["region", "day"]
    assert params["projection.enabled"] == "true" and params["projection.day.format"] == "yyyy/MM/dd"
    assert params["projection.day.range"].endswith(",NOW")
    regions = params["projection.region.values"].split(",")
    assert "us-east-1" in regions and "ap-southeast-1" in regions
    template_path = str(params["storage.location.template"])
    assert "/AWSLogs/123456789012/CloudTrail/${region}/${day}" in template_path
    assert "Fn::Sub" not in template_path          # ${region} phai den Athena nguyen van, khong bi CloudFormation thay


def test_athena_workgroup_caps_cost_per_query_and_keeps_results_in_the_archive_bucket(template):
    template.has_resource_properties("AWS::Athena::WorkGroup", {
        "Name": "logsentinel",
        "WorkGroupConfiguration": assertions.Match.object_like({
            "EnforceWorkGroupConfiguration": True,                 # nguoi dung khong tu doi noi luu ket qua
            "BytesScannedCutoffPerQuery": 1073741824,              # 1 GB ~ 0,005 USD: 1 cau truy van sai khong ton tien
            "ResultConfiguration": assertions.Match.object_like({
                "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"}}),
        })})
    workgroup = list(template.find_resources("AWS::Athena::WorkGroup").values())[0]
    location = str(workgroup["Properties"]["WorkGroupConfiguration"]["ResultConfiguration"]["OutputLocation"])
    assert "LogArchiveBucket" in location and "/athena-results/" in location


def test_ready_made_athena_queries_cover_the_report_and_use_partitions(template):
    """Truy van mau cho bao cao / dieu tra. Moi cau phai loc theo `day`, neu khong se quet toan bo lich su."""
    queries = [q["Properties"] for q in template.find_resources("AWS::Athena::NamedQuery").values()]
    assert len(queries) >= 4
    for q in queries:
        sql = q["QueryString"].lower()
        assert q["Database"] == "logsentinel" and q["WorkGroup"] == "logsentinel"
        assert "from cloudtrail_logs" in sql and "day >=" in sql, q["Name"]
        assert ";" not in sql.rstrip().rstrip(";")           # 1 cau lenh moi truy van
    text = " ".join(q["QueryString"] for q in queries)
    for topic in ("ConsoleLogin", "errorcode", "sourceipaddress", "iam.amazonaws.com"):
        assert topic in text
    # ten tieng Anh, khop huong dan workshop (5.7: Saved queries -> "Recent IAM changes")
    assert "LogSentinel - Recent IAM changes" in {q["Name"] for q in queries}


def test_analyst_policy_can_query_but_cannot_change_or_delete_evidence(template):
    """Policy gan cho nguoi lam bao cao (nguoi C): chi doc log va chay truy van trong workgroup nay."""
    policies = template.find_resources("AWS::IAM::ManagedPolicy")
    assert len(policies) == 1
    statements = list(policies.values())[0]["Properties"]["PolicyDocument"]["Statement"]
    actions = [a for st in statements for a in _actions(st)]
    for needed in ("athena:StartQueryExecution", "athena:GetQueryResults", "glue:GetTable", "s3:GetObject", "kms:Decrypt"):
        assert needed in actions, needed
    for forbidden in ("s3:DeleteObject", "s3:*", "glue:DeleteTable", "glue:*", "athena:*", "athena:DeleteWorkGroup",
                      "athena:UpdateWorkGroup", "kms:*", "dynamodb:Scan", "*"):
        assert forbidden not in actions, forbidden
    assert all(st["Resource"] != "*" for st in statements)
    writes = [st for st in statements if "s3:PutObject" in _actions(st)]
    assert len(writes) == 1 and "athena-results/" in str(writes[0]["Resource"]) and "AWSLogs" not in str(writes[0]["Resource"])


# ------------------------------------------------------- thoi gian luu log
def test_every_log_group_keeps_30_days_for_late_investigations(template):
    """Tan cong phat hien muon hon 1 tuan van con log de dieu tra; khop voi 30 ngay cua log CloudTrail tren S3."""
    groups = template.find_resources("AWS::Logs::LogGroup")
    names = {str(g["Properties"].get("LogGroupName")): g["Properties"].get("RetentionInDays") for g in groups.values()}
    for name in ("/logsentinel/sample-app", "/logsentinel/cloudtrail", "/logsentinel/detector"):
        assert names[name] == 30, (name, names[name])
    assert all(days == 30 for days in names.values()), names
