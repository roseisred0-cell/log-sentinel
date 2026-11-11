"""
Lop bien cua LogSentinel: AWS WAF cho CloudFront. WAF pham vi CLOUDFRONT bat buoc tao o us-east-1,
nen nam trong stack rieng; stack chinh (ap-southeast-1) tham chieu sang bang cross-region reference.

Thu tu luat (so nho chay truoc):
    0  BlockListedIps     IP dang bi SOAR khoa (lambda waf_sync dong bo tu DynamoDB moi phut)
    1  ConsoleAllowlist   (tuy chon) chi cac CIDR cho phep moi vao duoc Console / dang nhap
    2  RateLimitAuth      100 request / 5 phut / IP vao cac duong dan dang nhap, dang ky, quen mat khau
    3  RateLimitAll       2000 request / 5 phut / IP cho moi duong dan
    4  AWS IP reputation  danh sach IP xau do AWS duy tri (botnet, scanner)
    5  Known bad inputs   chu ky khai thac da biet (Log4Shell, ...)

Co y KHONG bat bo luat SQLi do AWS quan ly o che do chan: neu WAF chan het thi web app khong con ghi
SQL_INJECTION, Detector khong thay gi va SOAR khong khoa IP. Phat hien SQLi van la viec cua ung dung.
"""
from aws_cdk import CfnOutput, Stack, aws_wafv2 as wafv2
from constructs import Construct

# Duong dan can bao ve chat hon (Console va moi diem nhap thong tin dang nhap).
AUTH_PATHS = ("/auth/", "/login", "/setup-2fa")
CONSOLE_PATHS = ("/console", "/api/") + AUTH_PATHS


def _visibility(name: str) -> dict:
    return {"cloudWatchMetricsEnabled": True, "metricName": name, "sampledRequestsEnabled": True}


def _path_starts_with(path: str) -> dict:
    return {"byteMatchStatement": {
        "searchString": path,
        "fieldToMatch": {"uriPath": {}},
        "positionalConstraint": "STARTS_WITH",
        "textTransformations": [{"priority": 0, "type": "NONE"}],
    }}


def _any_path(paths) -> dict:
    return {"orStatement": {"statements": [_path_starts_with(p) for p in paths]}}


def _managed(priority: int, name: str) -> dict:
    return {
        "name": name, "priority": priority,
        "overrideAction": {"none": {}},
        "statement": {"managedRuleGroupStatement": {"vendorName": "AWS", "name": name}},
        "visibilityConfig": _visibility(name),
    }


class LogSentinelEdgeStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, console_cidrs=(), **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Dia chi do lambda waf_sync quan ly luc chay; CloudFormation chi tao danh sach rong.
        self.blocked_ip_set = wafv2.CfnIPSet(
            self, "BlockedIpSet",
            name="LogSentinel-Blocked",
            # WAF chi nhan chu, so, khoang trang va + = : # @ / - , . trong mo ta (khong co dau ngoac).
            description="IP dang bi LogSentinel SOAR khoa, dong bo tu DynamoDB",
            scope="CLOUDFRONT", ip_address_version="IPV4", addresses=[],
        )

        rules = [{
            "name": "BlockListedIps", "priority": 0,
            "action": {"block": {}},
            "statement": {"ipSetReferenceStatement": {"arn": self.blocked_ip_set.attr_arn}},
            "visibilityConfig": _visibility("BlockListedIps"),
        }]

        console_cidrs = [c for c in console_cidrs if c]
        if console_cidrs:
            allow_set = wafv2.CfnIPSet(
                self, "ConsoleAllowIpSet",
                name="LogSentinel-ConsoleAllow",
                description="CIDR duoc phep vao SOC Console",
                scope="CLOUDFRONT", ip_address_version="IPV4", addresses=console_cidrs,
            )
            rules.append({
                "name": "ConsoleAllowlist", "priority": 1,
                "action": {"block": {}},
                "statement": {"andStatement": {"statements": [
                    _any_path(CONSOLE_PATHS),
                    {"notStatement": {"statement": {"ipSetReferenceStatement": {"arn": allow_set.attr_arn}}}},
                ]}},
                "visibilityConfig": _visibility("ConsoleAllowlist"),
            })

        rules += [
            {
                "name": "RateLimitAuth", "priority": 2,
                "action": {"block": {}},
                "statement": {"rateBasedStatement": {
                    "limit": 100, "evaluationWindowSec": 300, "aggregateKeyType": "IP",
                    "scopeDownStatement": _any_path(AUTH_PATHS)}},
                "visibilityConfig": _visibility("RateLimitAuth"),
            },
            {
                "name": "RateLimitAll", "priority": 3,
                "action": {"block": {}},
                "statement": {"rateBasedStatement": {
                    "limit": 2000, "evaluationWindowSec": 300, "aggregateKeyType": "IP"}},
                "visibilityConfig": _visibility("RateLimitAll"),
            },
            _managed(4, "AWSManagedRulesAmazonIpReputationList"),
            _managed(5, "AWSManagedRulesKnownBadInputsRuleSet"),
        ]

        self.web_acl = wafv2.CfnWebACL(
            self, "WebAcl",
            name="LogSentinel-Edge",
            description="LogSentinel: chan IP bi khoa, gioi han toc do, IP xau",
            scope="CLOUDFRONT",
            default_action={"allow": {}},
            rules=rules,
            visibility_config=_visibility("LogSentinelEdge"),
        )

        CfnOutput(self, "WebAclArn", value=self.web_acl.attr_arn)
        CfnOutput(self, "BlockedIpSetId", value=self.blocked_ip_set.attr_id)
