"""Cau tieng Anh de doc cho cot Doi tuong / Chi tiet cua bang su co (static/incident-text.js).

Thiet ke chot 11/11: moi luat mot cau, du lieu goc thu vao nut "Xem du lieu goc".
Seam 1: IncidentText.describe(incident) -> {subject, sentence}, chay bang Node.js.
Seam 2: moi luat Detector co the sinh ra deu co cau mo ta.
Seam 3: trang Console nap script, khong dung innerHTML.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
JS = ROOT / "sample_app" / "static" / "incident-text.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="can Node.js de chay incident-text.js")


def describe_all(incidents):
    """Goi IncidentText.describe cho ca danh sach trong mot lan chay node."""
    script = ("const m = require(process.argv[1]);"
              "const items = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              "process.stdout.write(JSON.stringify(items.map(m.describe)));")
    out = subprocess.run(["node", "-e", script, str(JS)], input=json.dumps(incidents),
                         capture_output=True, text=True, encoding="utf-8", check=True)
    return json.loads(out.stdout)


def describe(rule, ip=None, actor=None, **details):
    return describe_all([{"rule": rule, "ip": ip, "actor": actor, "details": details}])[0]


# ------------------------------------------------------- Seam 1: tung luat
def test_brute_force():
    d = describe("BRUTE_FORCE_DETECTED", ip="203.0.113.9", actor="admin",
                 client_ip="203.0.113.9", username="admin", attempt_count=5, window_seconds=60)
    assert d == {"subject": "IP 203.0.113.9 · account admin",
                 "sentence": "Wrong password 5 times within 60 seconds. The IP was blocked for 24 hours."}


WEB_APP = [
    (dict(rule="SLOW_BRUTE_FORCE", ip="203.0.113.9", actor="admin",
          details={"client_ip": "203.0.113.9", "username": "admin", "attempt_count": 20, "window_seconds": 3600}),
     "IP 203.0.113.9 · account admin",
     "Wrong password 20 times within 1 hour, spread out to avoid the fast brute-force rule. The IP was blocked for 24 hours."),
    (dict(rule="ACCOUNT_UNDER_ATTACK", ip=None, actor="bob",
          details={"username": "bob", "attempt_count": 10, "window_seconds": 300, "last_ip": "198.51.100.4"}),
     "account bob",
     "Wrong password 10 times within 5 minutes from many different IPs (latest 198.51.100.4). "
     "No IP was blocked automatically."),
    (dict(rule="LOGIN_FAILURE_SPIKE", ip=None, actor=None,
          details={"attempt_count": 51, "window_seconds": 300, "last_ip": "198.51.100.4", "last_username": "x"}),
     "Whole system",
     "51 failed sign-ins within 5 minutes, from many IPs against many accounts. Leaked passwords may be being tried in bulk."),
    (dict(rule="SCAN_DETECTED", ip="203.0.113.7", actor=None,
          details={"client_ip": "203.0.113.7", "path": "/wp-admin/setup.php", "attempt_count": 30, "window_seconds": 60}),
     "IP 203.0.113.7",
     "Requested 30 paths that do not exist within 60 seconds (latest: /wp-admin/setup.php). The IP was blocked for 24 hours."),
    (dict(rule="SQL_INJECTION", ip="203.0.113.5", actor=None,
          details={"client_ip": "203.0.113.5", "payload": "' OR 1=1 --"}),
     "IP 203.0.113.5",
     "Malicious code injected into the search box: ' OR 1=1 --. The IP was blocked for 24 hours."),
    (dict(rule="SQL_INJECTION", ip="203.0.113.5", actor="admin' --",
          details={"client_ip": "203.0.113.5", "username": "admin' --", "payload": "admin' --", "field": "username"}),
     "IP 203.0.113.5",
     "Malicious code injected into the sign-in form: admin' --. The IP was blocked for 24 hours."),
    (dict(rule="MFA_BYPASS_ATTEMPT", ip="203.0.113.8", actor="a@x.co",
          details={"client_ip": "203.0.113.8", "username": "a@x.co", "otp_length": 6}),
     "IP 203.0.113.8 · account a@x.co",
     "Correct password but wrong OTP code: the password may have leaked, change it now. The IP was blocked for 24 hours."),
]


@pytest.mark.parametrize("incident,subject,sentence", WEB_APP, ids=[f"{c[0]['rule']}-{n}" for n, c in enumerate(WEB_APP)])
def test_web_app_rules(incident, subject, sentence):
    assert describe_all([incident])[0] == {"subject": subject, "sentence": sentence}


def ct(rule, **details):
    """Su co tu CloudTrail: _incident_view lay ip tu details.ip, doi tuong tu details.user."""
    return dict(rule=rule, ip=details.get("ip"), actor=details.get("user"), details=details)


CLOUDTRAIL = [
    (ct("ROOT_ACCOUNT_LOGIN", user="root", ip="198.51.100.20", mfa_used="No", outcome="Success"),
     "AWS root account",
     "AWS Console sign-in with the root account from IP 198.51.100.20 without MFA. "
     "The root account should not be used day to day: check whether this was you."),
    (ct("ROOT_ACCOUNT_LOGIN", user="root", ip="198.51.100.20", mfa_used="Yes", outcome="Success"),
     "AWS root account",
     "AWS Console sign-in with the root account from IP 198.51.100.20 with MFA. "
     "The root account should not be used day to day: check whether this was you."),
    (ct("ROOT_ACCOUNT_LOGIN", user="root", ip="198.51.100.20", mfa_used="No", outcome="Failure"),
     "AWS root account",
     "AWS Console sign-in with the root account from IP 198.51.100.20 (failed). "
     "The root account should not be used day to day: check whether this was you."),
    (ct("CONSOLE_LOGIN_NO_MFA", user="alice", ip="198.51.100.21"),
     "AWS user alice",
     "Successful AWS Console sign-in from IP 198.51.100.21 without MFA. Turn on MFA for this user."),
    (ct("CONSOLE_BRUTE_FORCE", user="alice", ip="198.51.100.22", attempt_count=5, window_seconds=300),
     "IP 198.51.100.22 · AWS user alice",
     "Failed AWS Console sign-in 5 times within 5 minutes. The system cannot block IPs on the AWS Console."),
    (ct("MFA_TAMPERING", action="DeactivateMFADevice", user="alice", ip="198.51.100.23"),
     "AWS user alice",
     "MFA device deactivated from IP 198.51.100.23."),
    (ct("MFA_TAMPERING", action="DeleteVirtualMFADevice", user="alice", ip="198.51.100.23"),
     "AWS user alice",
     "Virtual MFA device deleted from IP 198.51.100.23."),
    (ct("CLOUDTRAIL_TAMPERING", action="StopLogging", user="mallory", ip="198.51.100.24"),
     "AWS user mallory",
     "Stopped the audit log (CloudTrail) from IP 198.51.100.24: a sign of covering tracks."),
    (ct("CLOUDTRAIL_TAMPERING", action="DeleteTrail", user="mallory", ip="198.51.100.24"),
     "AWS user mallory",
     "Deleted the audit log (CloudTrail) from IP 198.51.100.24: a sign of covering tracks."),
    (ct("KMS_KEY_TAMPERING", action="ScheduleKeyDeletion", user="mallory", ip="198.51.100.25", key_id="k-123"),
     "KMS key k-123",
     "mallory scheduled deletion of the encryption key from IP 198.51.100.25. Urgent: losing the key means losing all logs and the incident table."),
    (ct("KMS_KEY_TAMPERING", action="DisableKey", user="mallory", ip="198.51.100.25", key_id="k-123"),
     "KMS key k-123",
     "mallory disabled the encryption key from IP 198.51.100.25. Urgent: losing the key means losing all logs and the incident table."),
]


@pytest.mark.parametrize("incident,subject,sentence", CLOUDTRAIL,
                         ids=[f"{c[0]['rule']}-{n}" for n, c in enumerate(CLOUDTRAIL)])
def test_cloudtrail_rules(incident, subject, sentence):
    assert describe_all([incident])[0] == {"subject": subject, "sentence": sentence}


def iam(rule, action, **extra):
    details = {"action": action, "actor": "alice", "target_user": None, "ip": "198.51.100.30", **extra}
    return dict(rule=rule, ip=details["ip"], actor="alice", details=details)


IAM = [
    (iam("IAM_ACCESS_KEY_CREATED", "CreateAccessKey", target_user="bob"),
     "AWS user bob", "alice created an access key for AWS user bob."),
    (iam("IAM_ACCESS_KEY_CREATED", "CreateAccessKey"),
     "AWS user alice", "alice created an access key for themselves."),
    (iam("IAM_POLICY_ATTACHED", "AttachRolePolicy", target_role="DeployRole",
         policy_arn="arn:aws:iam::aws:policy/AdministratorAccess", via_service="cloudformation.amazonaws.com"),
     "role DeployRole",
     "alice attached policy AdministratorAccess to role DeployRole. This is the highest privilege. "
     "Done through CloudFormation (cdk deploy)."),
    (iam("IAM_POLICY_ATTACHED", "AttachUserPolicy", target_user="bob",
         policy_arn="arn:aws:iam::123456789012:policy/ReadLogs", error_code="AccessDenied"),
     "AWS user bob", "alice attached policy ReadLogs to AWS user bob. Denied (AccessDenied)."),
    (iam("IAM_INLINE_POLICY_PUT", "PutGroupPolicy", target_group="ops", policy_name="AllowAll"),
     "group ops", "alice put inline policy AllowAll on group ops."),
    (iam("IAM_POLICY_VERSION_CREATED", "CreatePolicyVersion", policy_arn="arn:aws:iam::123456789012:policy/AppPolicy"),
     "policy AppPolicy", "alice changed the content of policy AppPolicy (new version)."),
    (iam("IAM_TRUST_POLICY_CHANGED", "UpdateAssumeRolePolicy", target_role="DeployRole"),
     "role DeployRole",
     "alice changed the trust policy of role DeployRole: who can assume this role may have changed."),
    (iam("IAM_LOGIN_PROFILE_CHANGED", "CreateLoginProfile", target_user="bob"),
     "AWS user bob", "alice set an AWS Console password for AWS user bob."),
    (iam("IAM_LOGIN_PROFILE_CHANGED", "UpdateLoginProfile", target_user="bob"),
     "AWS user bob", "alice changed the AWS Console password of AWS user bob."),
    (iam("IAM_USER_ADDED_TO_GROUP", "AddUserToGroup", target_user="bob", target_group="admins"),
     "group admins", "alice added AWS user bob to group admins."),
]


@pytest.mark.parametrize("incident,subject,sentence", IAM, ids=[f"{c[0]['rule']}-{n}" for n, c in enumerate(IAM)])
def test_iam_rules(incident, subject, sentence):
    assert describe_all([incident])[0] == {"subject": subject, "sentence": sentence}


def gov(rule, **details):
    """Su kien muc Phan quyen: username = nguoi thao tac (cot doi tuong cu), target_user = nguoi bi tac dong."""
    details = {"client_ip": "203.0.113.40", "username": "a@x.co", **details}
    return dict(rule=rule, ip=details["client_ip"], actor=details["username"], details=details)


GOVERNANCE = [
    (gov("ROLE_REQUEST_CREATED", action="promote", target_user="v@x.co", request_id="r1"),
     "v@x.co", "a@x.co proposed to promote v@x.co to Admin. Other administrators should vote in the Roles section."),
    (gov("ROLE_REQUEST_CREATED", action="disable", target_user="v@x.co", request_id="r1"),
     "v@x.co", "a@x.co proposed to disable the account v@x.co. Other administrators should vote in the Roles section."),
    (gov("ADMIN_ROLE_CHANGED", action="promote", target_user="v@x.co", bootstrap=False,
         approvers=["cognito:a@x.co", "cognito:b@x.co"]),
     "v@x.co", "v@x.co was promoted to Admin, approved by a@x.co, b@x.co."),
    (gov("ADMIN_ROLE_CHANGED", action="demote", target_user="c@x.co", bootstrap=False,
         approvers=["cognito:a@x.co", "cognito:b@x.co"]),
     "c@x.co", "c@x.co was demoted to Viewer, approved by a@x.co, b@x.co."),
    (gov("ADMIN_ROLE_CHANGED", username="admin", action="promote", target_user="v@x.co", bootstrap=True,
         approvers=["local:admin"]),
     "v@x.co", "v@x.co was promoted to Admin by the internal admin (bootstrap mode)."),
    (gov("USER_DISABLED", action="disable", target_user="v@x.co", approvers=["cognito:a@x.co", "cognito:b@x.co"]),
     "v@x.co", "Account v@x.co was disabled, approved by a@x.co, b@x.co."),
    (gov("ROLE_CHANGE_FAILED", action="promote", target_user="v@x.co", request_id="r1"),
     "v@x.co", "Enough votes to promote v@x.co to Admin, but Cognito failed so it was not applied. "
               "Click Approve on that request again to retry."),
    (gov("ADMIN_PIN_LOCKED", auth="cognito"),
     "account a@x.co", "Wrong Roles PIN entered 5 times; the PIN is locked for 15 minutes. "
                         "If this was not the account owner, the session may have been hijacked."),
    (gov("ADMIN_PIN_RESET", target_user="b@x.co"),
     "b@x.co", "a@x.co reset the Roles PIN of b@x.co."),
]


@pytest.mark.parametrize("incident,subject,sentence", GOVERNANCE,
                         ids=[f"{c[0]['rule']}-{n}" for n, c in enumerate(GOVERNANCE)])
def test_governance_events(incident, subject, sentence):
    assert describe_all([incident])[0] == {"subject": subject, "sentence": sentence}


def test_unknown_rule_falls_back_without_hiding_the_data():
    d = describe("SOMETHING_NEW", ip="203.0.113.50", actor="eve", foo="bar")
    assert d == {"subject": "IP 203.0.113.50 · account eve",
                 "sentence": "No description for this rule yet. Click “Show raw data” for details."}


def rule_names():
    """Danh sach ten luat ma incident-text.js khai bao (de chay cac kiem tra chung cho moi luat)."""
    out = subprocess.run(["node", "-e", "process.stdout.write(JSON.stringify(require(process.argv[1]).RULES))",
                          str(JS)], capture_output=True, text=True, encoding="utf-8", check=True)
    return json.loads(out.stdout)


@pytest.mark.parametrize("details", [{}, None, {"attempt_count": None, "approvers": "not-a-list", "payload": None}])
def test_missing_or_odd_fields_never_show_undefined_or_crash(details):
    """Ban ghi cu / thieu truong: cau van doc duoc, khong hien 'undefined' hay 'null'."""
    rules = rule_names()
    results = describe_all([{"rule": r, "ip": None, "actor": None, "details": details} for r in rules]
                           + [None, {}, {"rule": None}])
    for rule, d in zip(rules + ["<none>", "<empty>", "<null rule>"], results):
        assert isinstance(d["subject"], str) and isinstance(d["sentence"], str) and d["sentence"], rule
        for bad in ("undefined", "null", "NaN", "[object"):
            assert bad not in d["subject"] + d["sentence"], (rule, d)


# ------------------------------------- Seam 2: moi luat cua Detector deu co cau
def detector_rules():
    """Ten luat Detector co the ghi: record_incident("..."), IAM_PRIVILEGE_EVENTS, GOVERNANCE_EVENTS."""
    import ast
    tree = ast.parse((ROOT / "lambda_src" / "detector.py").read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "record_incident" \
                and node.args and isinstance(node.args[0], ast.Constant):
            names.add(node.args[0].value)
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "IAM_PRIVILEGE_EVENTS" for t in node.targets):
            names.update(ast.literal_eval(node.value).values())
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "GOVERNANCE_EVENTS" for t in node.targets):
            names.update(ast.literal_eval(node.value.args[0]))
    return names


def test_every_detector_rule_has_a_readable_sentence():
    rules = detector_rules()
    assert len(rules) >= 26  # 20 luat + 6 su kien phan quyen (12/11): bat loi neu doc ma nguon sai
    assert sorted(rules - set(rule_names())) == []


def test_long_payload_is_shortened():
    d = describe("SQL_INJECTION", ip="203.0.113.5", client_ip="203.0.113.5", payload="UNION SELECT " + "x" * 300)
    assert d["sentence"] == "Malicious code injected into the search box: UNION SELECT " + "x" * 67 + "…. The IP was blocked for 24 hours."
