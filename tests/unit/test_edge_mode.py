"""Che do edge: CloudFront + WAF truoc may, dong bo IP bi khoa len WAF, canh bao chi phi."""
import importlib
import sys
import types
from pathlib import Path
from unittest import mock

import aws_cdk as core
import aws_cdk.assertions as assertions
import pytest

from log_sentinel.edge_stack import AUTH_PATHS, CONSOLE_PATHS, LogSentinelEdgeStack
from log_sentinel.log_sentinel_stack import LogSentinelStack, console_cidrs, edge_enabled

ACCOUNT = "123456789012"
ENV = core.Environment(account=ACCOUNT, region="ap-southeast-1")
EDGE_ENV = core.Environment(account=ACCOUNT, region="us-east-1")
LAMBDA_SRC = str(Path(__file__).resolve().parents[2] / "lambda_src")
Match = assertions.Match


def _synth(console=(), **context):
    app = core.App(context=context)
    edge = LogSentinelEdgeStack(app, "edge-test", console_cidrs=console, env=EDGE_ENV, cross_region_references=True)
    main = LogSentinelStack(app, "main-test", edge=edge, env=ENV, cross_region_references=True)
    return assertions.Template.from_stack(main), assertions.Template.from_stack(edge)


@pytest.fixture(scope="module")
def stacks():
    return _synth(alert_email="soc@example.com", admin_cidr="203.0.113.10/32")


@pytest.fixture(scope="module")
def main(stacks):
    return stacks[0]


@pytest.fixture(scope="module")
def edge(stacks):
    return stacks[1]


def _statements(template, logical_id_prefix):
    policies = template.find_resources("AWS::IAM::Policy")
    return [st for name, p in policies.items() if name.startswith(logical_id_prefix)
            for st in p["Properties"]["PolicyDocument"]["Statement"]]


def _actions(statement):
    a = statement["Action"]
    return a if isinstance(a, list) else [a]


def _rules(edge_template):
    acl = list(edge_template.find_resources("AWS::WAFv2::WebACL").values())[0]
    return {r["Name"]: r for r in acl["Properties"]["Rules"]}


# ------------------------------------------------------------ cong tac
@pytest.mark.parametrize("value,expected", [("true", True), ("1", True), ("yes", True), ("TRUE", True),
                                            ("false", False), ("", False), (None, False)])
def test_edge_is_opt_in(value, expected):
    app = core.App(context={} if value is None else {"enable_edge": value})
    assert edge_enabled(app) is expected


def test_console_cidrs_parsed_from_context():
    app = core.App(context={"console_cidrs": " 203.0.113.0/24, 198.51.100.7/32 ,"})
    assert console_cidrs(app) == ["203.0.113.0/24", "198.51.100.7/32"]


def test_default_mode_creates_no_edge_resources():
    template = assertions.Template.from_stack(LogSentinelStack(core.App(), "plain-test", env=ENV))
    for kind in ("AWS::CloudFront::Distribution", "AWS::Events::Rule"):
        template.resource_count_is(kind, 0)
    assert "waf_sync.handler" not in str(template.to_json()) and "EDGE_MODE" not in str(template.to_json())


# ------------------------------------------------------- may sau CloudFront
def test_origin_accepts_only_cloudfront_on_port_80_and_nothing_from_the_internet(main):
    sgs = main.find_resources("AWS::EC2::SecurityGroup")
    # Gom ca luat khai bao long trong SG lan luat la tai nguyen rieng (CDK dung dang rieng cho prefix list).
    ingress = [r for sg in sgs.values() for r in sg["Properties"].get("SecurityGroupIngress", [])]
    ingress += [r["Properties"] for r in main.find_resources("AWS::EC2::SecurityGroupIngress").values()]
    assert len(ingress) == 1
    rule = ingress[0]
    assert rule["FromPort"] == 80 and rule["ToPort"] == 80 and "SourcePrefixListId" in rule
    assert "CidrIp" not in rule and "CidrIpv6" not in rule       # khong con 0.0.0.0/0


def test_cloudfront_forces_https_never_caches_and_carries_the_secret_header(main):
    main.has_resource_properties("AWS::CloudFront::Distribution", {"DistributionConfig": Match.object_like({
        "IPV6Enabled": False,
        "WebACLId": Match.any_value(),
        "DefaultCacheBehavior": Match.object_like({
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",          # Managed-CachingDisabled
            "AllowedMethods": Match.array_with(["POST", "DELETE"]),
        }),
        "Origins": [Match.object_like({
            "CustomOriginConfig": Match.object_like({"OriginProtocolPolicy": "http-only", "HTTPPort": 80}),
            "OriginCustomHeaders": [Match.object_like({"HeaderName": "X-Origin-Verify"})],
        })],
    })})


def test_origin_secret_is_generated_and_only_its_arn_reaches_user_data(main):
    main.has_resource_properties("AWS::SecretsManager::Secret", {"GenerateSecretString": Match.object_like({
        "ExcludePunctuation": True, "PasswordLength": 48})})
    instance = str(main.find_resources("AWS::EC2::Instance"))
    assert "EDGE_MODE=true" in instance and "ORIGIN_SECRET_ARN=" in instance
    assert "resolve:secretsmanager" not in instance              # gia tri bi mat khong nam trong UserData


def test_public_urls_point_at_cloudfront_not_the_instance_ip(main):
    outputs = main.find_outputs("*")
    for name in ("SocConsoleUrl", "TargetVmAttackUrl"):
        value = str(outputs[name]["Value"])
        assert "DomainName" in value and "PublicIp" not in value


# ---------------------------------------------------------------- WAF
def test_waf_is_for_cloudfront_and_allows_by_default(edge):
    edge.has_resource_properties("AWS::WAFv2::WebACL", {"Scope": "CLOUDFRONT", "DefaultAction": {"Allow": {}}})
    edge.has_resource_properties("AWS::WAFv2::IPSet", {
        "Name": "LogSentinel-Blocked", "Scope": "CLOUDFRONT", "IPAddressVersion": "IPV4", "Addresses": []})


def test_waf_rule_order_blocks_listed_ips_before_anything_else(edge):
    rules = _rules(edge)
    assert rules["BlockListedIps"]["Priority"] == 0 and rules["BlockListedIps"]["Action"] == {"Block": {}}
    assert "IPSetReferenceStatement" in rules["BlockListedIps"]["Statement"]
    priorities = [r["Priority"] for r in rules.values()]
    assert len(priorities) == len(set(priorities))               # WAF tu choi ACL co 2 luat trung thu tu


def test_waf_rate_limits_credential_paths_harder_than_everything_else(edge):
    rules = _rules(edge)
    auth, everything = (rules[n]["Statement"]["RateBasedStatement"] for n in ("RateLimitAuth", "RateLimitAll"))
    assert auth["Limit"] < everything["Limit"] and auth["AggregateKeyType"] == "IP"
    paths = [s["ByteMatchStatement"]["SearchString"] for s in auth["ScopeDownStatement"]["OrStatement"]["Statements"]]
    assert paths == list(AUTH_PATHS) and "ScopeDownStatement" not in everything


def test_waf_does_not_block_sqli_itself_so_the_detector_still_sees_attacks(edge):
    """Neu WAF chan SQLi thi web app khong con ghi SQL_INJECTION -> Detector mu, SOAR khong khoa IP."""
    managed = [r["Statement"]["ManagedRuleGroupStatement"]["Name"] for r in _rules(edge).values()
               if "ManagedRuleGroupStatement" in r["Statement"]]
    assert managed == ["AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesKnownBadInputsRuleSet"]
    assert not any("SQLi" in name or "CommonRuleSet" in name for name in managed)


def test_waf_names_and_descriptions_use_only_characters_waf_accepts():
    """WAF tu choi mo ta co dau ngoac... -> deploy that bai. Mau lay tu schema CloudFormation cua WAFv2."""
    import re
    description = re.compile(r"^[a-zA-Z0-9=:#@/\-,.][a-zA-Z0-9+=:#@/\-,.\s]+[a-zA-Z0-9+=:#@/\-,.]{1,256}$")
    name = re.compile(r"^[0-9A-Za-z_-]{1,128}$")
    _, edge_template = _synth(console=["203.0.113.0/24"])
    resources = {**edge_template.find_resources("AWS::WAFv2::WebACL"), **edge_template.find_resources("AWS::WAFv2::IPSet")}
    assert len(resources) == 3
    for logical_id, resource in resources.items():
        props = resource["Properties"]
        assert description.match(props["Description"]), (logical_id, props["Description"])
        assert name.match(props["Name"]), (logical_id, props["Name"])
    for rule in _rules(edge_template).values():
        assert name.match(rule["Name"]) and name.match(rule["VisibilityConfig"]["MetricName"])


def test_no_console_allowlist_rule_unless_cidrs_are_given(edge):
    assert "ConsoleAllowlist" not in _rules(edge)
    edge.resource_count_is("AWS::WAFv2::IPSet", 1)


def test_console_allowlist_blocks_console_paths_from_everyone_else():
    _, edge_template = _synth(console=["203.0.113.0/24"])
    rule = _rules(edge_template)["ConsoleAllowlist"]
    paths_stmt, not_stmt = rule["Statement"]["AndStatement"]["Statements"]
    paths = [s["ByteMatchStatement"]["SearchString"] for s in paths_stmt["OrStatement"]["Statements"]]
    assert rule["Action"] == {"Block": {}} and paths == list(CONSOLE_PATHS)
    assert "IPSetReferenceStatement" in not_stmt["NotStatement"]["Statement"]
    assert "/search" not in paths                                 # ung dung cong khai van mo cho khach
    edge_template.has_resource_properties("AWS::WAFv2::IPSet", {
        "Name": "LogSentinel-ConsoleAllow", "Addresses": ["203.0.113.0/24"]})


# -------------------------------------------------------- dong bo WAF
def test_waf_sync_runs_every_minute_with_least_privilege(main):
    main.has_resource_properties("AWS::Lambda::Function", {"Handler": "waf_sync.handler"})
    main.has_resource_properties("AWS::Events::Rule", {"ScheduleExpression": "rate(1 minute)"})
    actions = sorted(a for st in _statements(main, "WafSyncLambda") for a in _actions(st))
    assert "wafv2:GetIPSet" in actions and "wafv2:UpdateIPSet" in actions and "dynamodb:Query" in actions
    for forbidden in ("dynamodb:Scan", "dynamodb:PutItem", "dynamodb:DeleteItem", "wafv2:UpdateWebACL",
                      "wafv2:DeleteIPSet", "wafv2:*"):
        assert forbidden not in actions
    waf_stmt = [st for st in _statements(main, "WafSyncLambda") if "wafv2:UpdateIPSet" in _actions(st)][0]
    assert waf_stmt["Resource"] != "*"


def test_waf_sync_failure_raises_an_alarm(main):
    main.has_resource_properties("AWS::CloudWatch::Alarm", {
        "AlarmDescription": Match.string_like_regexp("WAF"), "MetricName": "Errors", "Threshold": 3})


# ------------------------------------------------- canh bao chi phi
def test_budget_alerts_on_actual_and_forecast_spend(main):
    main.has_resource_properties("AWS::Budgets::Budget", {
        "Budget": Match.object_like({"BudgetType": "COST", "TimeUnit": "MONTHLY",
                                     "BudgetLimit": {"Amount": 20, "Unit": "USD"}}),
        "NotificationsWithSubscribers": [
            Match.object_like({"Notification": Match.object_like({"NotificationType": "ACTUAL", "Threshold": 80}),
                               "Subscribers": [{"SubscriptionType": "EMAIL", "Address": "soc@example.com"}]}),
            Match.object_like({"Notification": Match.object_like({"NotificationType": "FORECASTED", "Threshold": 100})}),
        ]})


@pytest.mark.parametrize("context", [{"alert_email": "soc@example.com", "monthly_budget_usd": "0"},
                                     {"monthly_budget_usd": "50"}, {}])
def test_budget_needs_an_email_and_can_be_switched_off(context):
    template = assertions.Template.from_stack(LogSentinelStack(core.App(context=context), "b-test", env=ENV))
    template.resource_count_is("AWS::Budgets::Budget", 0)


def test_budget_amount_is_configurable():
    template = assertions.Template.from_stack(LogSentinelStack(
        core.App(context={"alert_email": "a@b.co", "monthly_budget_usd": "75"}), "b2-test", env=ENV))
    template.has_resource_properties("AWS::Budgets::Budget", {
        "Budget": Match.object_like({"BudgetLimit": {"Amount": 75, "Unit": "USD"}})})


# ------------------------------------------- thu hoi phien (quyen IAM)
def test_vm_may_write_session_revocation_items_and_every_put_is_key_scoped(main):
    # Danh sach khoa day du (REVOKED_SESSION#, ADMIN_PIN#, ROLE_REQ#): test_stack_hardening.py
    puts = [st for st in _statements(main, "TargetVmRole") if "dynamodb:PutItem" in _actions(st)]
    prefixes = [p for st in puts for p in st["Condition"]["ForAllValues:StringLike"]["dynamodb:LeadingKeys"]]
    assert "REVOKED_SESSION#*" in prefixes and all(p.endswith("#*") for p in prefixes)


# =====================================================================
# Lambda waf_sync (khong can AWS)
# =====================================================================
class LockConflict(Exception):
    response = {"Error": {"Code": "WAFOptimisticLockException"}}


@pytest.fixture
def sync(monkeypatch):
    fake = types.ModuleType("boto3")
    fake.resource = lambda *a, **k: mock.MagicMock()
    fake.client = lambda *a, **k: mock.MagicMock()
    conditions = types.ModuleType("boto3.dynamodb.conditions")
    conditions.Key = lambda name: types.SimpleNamespace(eq=lambda value: (name, value))
    monkeypatch.setitem(sys.modules, "boto3", fake)
    monkeypatch.setitem(sys.modules, "boto3.dynamodb", types.ModuleType("boto3.dynamodb"))
    monkeypatch.setitem(sys.modules, "boto3.dynamodb.conditions", conditions)
    monkeypatch.setenv("INCIDENT_TABLE", "t")
    monkeypatch.setenv("WAF_IP_SET_NAME", "LogSentinel-Blocked")
    monkeypatch.setenv("WAF_IP_SET_ID", "set-1")
    monkeypatch.syspath_prepend(LAMBDA_SRC)
    sys.modules.pop("waf_sync", None)
    module = importlib.import_module("waf_sync")
    module.table = mock.MagicMock()
    module.waf = mock.MagicMock()
    monkeypatch.setattr(module.time, "time", lambda: 1_000_000)
    return module


def _block(ip, ttl=1_000_500, at="2026-11-11T08:00:00"):
    return {"blocked_ip": ip, "ttl": ttl, "blocked_at": at, "record_type": "BLOCK"}


def _current(sync, addresses, token="tok-1"):
    sync.waf.get_ip_set.return_value = {"IPSet": {"Addresses": addresses}, "LockToken": token}


def test_sync_pushes_active_blocks_and_drops_expired_ones(sync):
    sync.table.query.return_value = {"Items": [_block("8.8.8.8"), _block("1.1.1.1"), _block("9.9.9.9", ttl=999_999)]}
    _current(sync, ["9.9.9.9/32"])
    assert sync.handler({}, None) == {"changed": True, "count": 2}
    kw = sync.waf.update_ip_set.call_args.kwargs
    assert kw["Addresses"] == ["1.1.1.1/32", "8.8.8.8/32"] and kw["LockToken"] == "tok-1"
    assert kw["Scope"] == "CLOUDFRONT" and kw["Id"] == "set-1" and kw["Name"] == "LogSentinel-Blocked"


def test_sync_reads_only_block_records_through_the_index(sync):
    sync.table.query.return_value = {"Items": []}
    _current(sync, [])
    sync.handler({}, None)
    kw = sync.table.query.call_args.kwargs
    assert kw["IndexName"] == "by_type" and kw["KeyConditionExpression"] == ("record_type", "BLOCK")
    sync.table.scan.assert_not_called()


def test_sync_does_nothing_when_waf_already_matches(sync):
    sync.table.query.return_value = {"Items": [_block("8.8.8.8")]}
    _current(sync, ["8.8.8.8/32"])
    assert sync.handler({}, None) == {"changed": False, "count": 1}
    sync.waf.update_ip_set.assert_not_called()


def test_admin_unblock_empties_the_waf_set(sync):
    sync.table.query.return_value = {"Items": []}
    _current(sync, ["8.8.8.8/32"])
    sync.handler({}, None)
    assert sync.waf.update_ip_set.call_args.kwargs["Addresses"] == []


@pytest.mark.parametrize("bad", ["not-an-ip", "", None, "127.0.0.1", "0.0.0.0", "169.254.169.254",
                                 "2001:db8::1", "8.8.8.8/0", "0.0.0.0/0", "8.8.8.8, 1.1.1.1", ["8.8.8.8"]])
def test_one_malformed_block_record_cannot_poison_or_widen_the_waf_set(sync, bad):
    """Mot dia chi sai lam WAF tu choi ca danh sach; mot CIDR rong (/0) se chan ca Internet."""
    sync.table.query.return_value = {"Items": [_block(bad), _block("8.8.8.8")]}
    _current(sync, [])
    sync.handler({}, None)
    assert sync.waf.update_ip_set.call_args.kwargs["Addresses"] == ["8.8.8.8/32"]


def test_sync_follows_pagination(sync):
    sync.table.query.side_effect = [{"Items": [_block("8.8.8.8")], "LastEvaluatedKey": {"k": 1}},
                                    {"Items": [_block("1.1.1.1")]}]
    _current(sync, [])
    sync.handler({}, None)
    assert sync.waf.update_ip_set.call_args.kwargs["Addresses"] == ["1.1.1.1/32", "8.8.8.8/32"]
    assert sync.table.query.call_args_list[1].kwargs["ExclusiveStartKey"] == {"k": 1}


def test_sync_keeps_newest_blocks_when_over_the_waf_limit(sync, monkeypatch):
    monkeypatch.setattr(sync, "MAX_ADDRESSES", 2)
    sync.table.query.return_value = {"Items": [_block("8.8.8.8", at="2026-11-11T08:00:00"),
                                               _block("1.1.1.1", at="2026-11-11T09:00:00"),
                                               _block("9.9.9.9", at="2026-11-11T10:00:00")]}
    _current(sync, [])
    sync.handler({}, None)
    assert sync.waf.update_ip_set.call_args.kwargs["Addresses"] == ["1.1.1.1/32", "9.9.9.9/32"]


def test_sync_retries_after_a_lock_conflict(sync):
    sync.table.query.return_value = {"Items": [_block("8.8.8.8")]}
    sync.waf.get_ip_set.side_effect = [{"IPSet": {"Addresses": []}, "LockToken": "old"},
                                       {"IPSet": {"Addresses": []}, "LockToken": "new"}]
    sync.waf.update_ip_set.side_effect = [LockConflict(), None]
    assert sync.handler({}, None)["changed"] is True
    assert sync.waf.update_ip_set.call_args.kwargs["LockToken"] == "new"


@pytest.mark.parametrize("where", ["query", "get_ip_set", "update_ip_set"])
def test_sync_errors_are_raised_so_the_alarm_can_fire(sync, where):
    sync.table.query.return_value = {"Items": [_block("8.8.8.8")]}
    _current(sync, [])
    target = sync.table.query if where == "query" else getattr(sync.waf, where)
    target.side_effect = RuntimeError("AccessDenied")
    with pytest.raises(RuntimeError):
        sync.handler({}, None)


def test_sync_refuses_to_run_half_configured(sync, monkeypatch):
    monkeypatch.setattr(sync, "IP_SET_ID", "")
    with pytest.raises(RuntimeError):
        sync.handler({}, None)
    sync.waf.update_ip_set.assert_not_called()
