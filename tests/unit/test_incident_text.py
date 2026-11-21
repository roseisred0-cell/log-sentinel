"""Cau tieng Viet de doc cho cot Doi tuong / Chi tiet cua bang su co (static/incident-text.js).

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
    assert d == {"subject": "IP 203.0.113.9 · tài khoản admin",
                 "sentence": "Đoán sai mật khẩu 5 lần trong 60 giây. IP đã bị khóa 24 giờ."}


WEB_APP = [
    (dict(rule="SLOW_BRUTE_FORCE", ip="203.0.113.9", actor="admin",
          details={"client_ip": "203.0.113.9", "username": "admin", "attempt_count": 20, "window_seconds": 3600}),
     "IP 203.0.113.9 · tài khoản admin",
     "Đoán sai mật khẩu 20 lần trong 1 giờ, rải đều để né luật đoán nhanh. IP đã bị khóa 24 giờ."),
    (dict(rule="ACCOUNT_UNDER_ATTACK", ip=None, actor="bob",
          details={"username": "bob", "attempt_count": 10, "window_seconds": 300, "last_ip": "198.51.100.4"}),
     "tài khoản bob",
     "Bị đoán sai mật khẩu 10 lần trong 5 phút từ nhiều IP khác nhau (gần nhất 198.51.100.4). "
     "Không IP nào bị khóa tự động."),
    (dict(rule="LOGIN_FAILURE_SPIKE", ip=None, actor=None,
          details={"attempt_count": 51, "window_seconds": 300, "last_ip": "198.51.100.4", "last_username": "x"}),
     "Toàn hệ thống",
     "51 lần đăng nhập sai trong 5 phút, từ nhiều IP vào nhiều tài khoản. Có thể đang bị thử mật khẩu hàng loạt."),
    (dict(rule="SCAN_DETECTED", ip="203.0.113.7", actor=None,
          details={"client_ip": "203.0.113.7", "path": "/wp-admin/setup.php", "attempt_count": 30, "window_seconds": 60}),
     "IP 203.0.113.7",
     "Gọi 30 đường dẫn không tồn tại trong 60 giây (gần nhất: /wp-admin/setup.php). IP đã bị khóa 24 giờ."),
    (dict(rule="SQL_INJECTION", ip="203.0.113.5", actor=None,
          details={"client_ip": "203.0.113.5", "payload": "' OR 1=1 --"}),
     "IP 203.0.113.5",
     "Chèn mã độc vào ô tìm kiếm: ' OR 1=1 --. IP đã bị khóa 24 giờ."),
    (dict(rule="SQL_INJECTION", ip="203.0.113.5", actor="admin' --",
          details={"client_ip": "203.0.113.5", "username": "admin' --", "payload": "admin' --", "field": "username"}),
     "IP 203.0.113.5",
     "Chèn mã độc vào ô đăng nhập: admin' --. IP đã bị khóa 24 giờ."),
    (dict(rule="MFA_BYPASS_ATTEMPT", ip="203.0.113.8", actor="a@x.co",
          details={"client_ip": "203.0.113.8", "username": "a@x.co", "otp_length": 6}),
     "IP 203.0.113.8 · tài khoản a@x.co",
     "Mật khẩu đúng nhưng mã OTP sai: mật khẩu có thể đã bị lộ, nên đổi ngay. IP đã bị khóa 24 giờ."),
]


@pytest.mark.parametrize("incident,subject,sentence", WEB_APP, ids=[f"{c[0]['rule']}-{n}" for n, c in enumerate(WEB_APP)])
def test_web_app_rules(incident, subject, sentence):
    assert describe_all([incident])[0] == {"subject": subject, "sentence": sentence}


def ct(rule, **details):
    """Su co tu CloudTrail: _incident_view lay ip tu details.ip, doi tuong tu details.user."""
    return dict(rule=rule, ip=details.get("ip"), actor=details.get("user"), details=details)


CLOUDTRAIL = [
    (ct("ROOT_ACCOUNT_LOGIN", user="root", ip="198.51.100.20", mfa_used="No", outcome="Success"),
     "tài khoản root AWS",
     "Đăng nhập AWS Console bằng tài khoản root từ IP 198.51.100.20, không dùng MFA. "
     "Root không nên dùng hằng ngày: kiểm tra có phải bạn không."),
    (ct("ROOT_ACCOUNT_LOGIN", user="root", ip="198.51.100.20", mfa_used="Yes", outcome="Success"),
     "tài khoản root AWS",
     "Đăng nhập AWS Console bằng tài khoản root từ IP 198.51.100.20, có dùng MFA. "
     "Root không nên dùng hằng ngày: kiểm tra có phải bạn không."),
    (ct("ROOT_ACCOUNT_LOGIN", user="root", ip="198.51.100.20", mfa_used="No", outcome="Failure"),
     "tài khoản root AWS",
     "Đăng nhập AWS Console bằng tài khoản root từ IP 198.51.100.20 thất bại. "
     "Root không nên dùng hằng ngày: kiểm tra có phải bạn không."),
    (ct("CONSOLE_LOGIN_NO_MFA", user="alice", ip="198.51.100.21"),
     "người dùng AWS alice",
     "Đăng nhập AWS Console thành công từ IP 198.51.100.21 mà không dùng MFA. Nên bật MFA cho người dùng này."),
    (ct("CONSOLE_BRUTE_FORCE", user="alice", ip="198.51.100.22", attempt_count=5, window_seconds=300),
     "IP 198.51.100.22 · người dùng AWS alice",
     "Đăng nhập AWS Console sai 5 lần trong 5 phút. Hệ thống không khóa được IP ở AWS Console."),
    (ct("MFA_TAMPERING", action="DeactivateMFADevice", user="alice", ip="198.51.100.23"),
     "người dùng AWS alice",
     "Tắt thiết bị MFA từ IP 198.51.100.23."),
    (ct("MFA_TAMPERING", action="DeleteVirtualMFADevice", user="alice", ip="198.51.100.23"),
     "người dùng AWS alice",
     "Xóa thiết bị MFA ảo từ IP 198.51.100.23."),
    (ct("CLOUDTRAIL_TAMPERING", action="StopLogging", user="mallory", ip="198.51.100.24"),
     "người dùng AWS mallory",
     "Dừng ghi nhật ký kiểm toán (CloudTrail) từ IP 198.51.100.24: dấu hiệu xóa dấu vết."),
    (ct("CLOUDTRAIL_TAMPERING", action="DeleteTrail", user="mallory", ip="198.51.100.24"),
     "người dùng AWS mallory",
     "Xóa nhật ký kiểm toán (CloudTrail) từ IP 198.51.100.24: dấu hiệu xóa dấu vết."),
    (ct("KMS_KEY_TAMPERING", action="ScheduleKeyDeletion", user="mallory", ip="198.51.100.25", key_id="k-123"),
     "khóa KMS k-123",
     "mallory hẹn xóa khóa mã hóa từ IP 198.51.100.25. Khẩn cấp: mất khóa là mất toàn bộ log và bảng sự cố."),
    (ct("KMS_KEY_TAMPERING", action="DisableKey", user="mallory", ip="198.51.100.25", key_id="k-123"),
     "khóa KMS k-123",
     "mallory vô hiệu hóa khóa mã hóa từ IP 198.51.100.25. Khẩn cấp: mất khóa là mất toàn bộ log và bảng sự cố."),
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
     "người dùng AWS bob", "alice tạo khóa truy cập (access key) cho người dùng AWS bob."),
    (iam("IAM_ACCESS_KEY_CREATED", "CreateAccessKey"),
     "người dùng AWS alice", "alice tạo khóa truy cập (access key) cho chính mình."),
    (iam("IAM_POLICY_ATTACHED", "AttachRolePolicy", target_role="DeployRole",
         policy_arn="arn:aws:iam::aws:policy/AdministratorAccess", via_service="cloudformation.amazonaws.com"),
     "role DeployRole",
     "alice gắn policy AdministratorAccess cho role DeployRole. Đây là quyền cao nhất. "
     "Thực hiện qua CloudFormation (cdk deploy)."),
    (iam("IAM_POLICY_ATTACHED", "AttachUserPolicy", target_user="bob",
         policy_arn="arn:aws:iam::123456789012:policy/ReadLogs", error_code="AccessDenied"),
     "người dùng AWS bob", "alice gắn policy ReadLogs cho người dùng AWS bob. Bị từ chối (AccessDenied)."),
    (iam("IAM_INLINE_POLICY_PUT", "PutGroupPolicy", target_group="ops", policy_name="AllowAll"),
     "nhóm ops", "alice ghi inline policy AllowAll cho nhóm ops."),
    (iam("IAM_POLICY_VERSION_CREATED", "CreatePolicyVersion", policy_arn="arn:aws:iam::123456789012:policy/AppPolicy"),
     "policy AppPolicy", "alice sửa nội dung policy AppPolicy (tạo phiên bản mới)."),
    (iam("IAM_TRUST_POLICY_CHANGED", "UpdateAssumeRolePolicy", target_role="DeployRole"),
     "role DeployRole",
     "alice sửa trust policy của role DeployRole: danh sách ai được mượn quyền của role này có thể đã đổi."),
    (iam("IAM_LOGIN_PROFILE_CHANGED", "CreateLoginProfile", target_user="bob"),
     "người dùng AWS bob", "alice đặt mật khẩu AWS Console cho người dùng AWS bob."),
    (iam("IAM_LOGIN_PROFILE_CHANGED", "UpdateLoginProfile", target_user="bob"),
     "người dùng AWS bob", "alice đổi mật khẩu AWS Console của người dùng AWS bob."),
    (iam("IAM_USER_ADDED_TO_GROUP", "AddUserToGroup", target_user="bob", target_group="admins"),
     "nhóm admins", "alice thêm người dùng AWS bob vào nhóm admins."),
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
     "v@x.co", "a@x.co đề xuất nâng v@x.co lên Quản trị. Các quản trị viên khác vào mục Phân quyền để bỏ phiếu."),
    (gov("ROLE_REQUEST_CREATED", action="disable", target_user="v@x.co", request_id="r1"),
     "v@x.co", "a@x.co đề xuất vô hiệu hóa tài khoản v@x.co. Các quản trị viên khác vào mục Phân quyền để bỏ phiếu."),
    (gov("ADMIN_ROLE_CHANGED", action="promote", target_user="v@x.co", bootstrap=False,
         approvers=["cognito:a@x.co", "cognito:b@x.co"]),
     "v@x.co", "v@x.co được nâng lên Quản trị, với sự đồng ý của a@x.co, b@x.co."),
    (gov("ADMIN_ROLE_CHANGED", action="demote", target_user="c@x.co", bootstrap=False,
         approvers=["cognito:a@x.co", "cognito:b@x.co"]),
     "c@x.co", "c@x.co bị hạ xuống Người xem, với sự đồng ý của a@x.co, b@x.co."),
    (gov("ADMIN_ROLE_CHANGED", username="admin", action="promote", target_user="v@x.co", bootstrap=True,
         approvers=["local:admin"]),
     "v@x.co", "v@x.co được nâng lên Quản trị bởi admin nội bộ (chế độ khởi tạo)."),
    (gov("USER_DISABLED", action="disable", target_user="v@x.co", approvers=["cognito:a@x.co", "cognito:b@x.co"]),
     "v@x.co", "Tài khoản v@x.co bị vô hiệu hóa, với sự đồng ý của a@x.co, b@x.co."),
    (gov("ROLE_CHANGE_FAILED", action="promote", target_user="v@x.co", request_id="r1"),
     "v@x.co", "Đủ phiếu để nâng v@x.co lên Quản trị nhưng Cognito lỗi nên chưa thực hiện. "
               "Bấm Đồng ý lại trên yêu cầu đó để thử lại."),
    (gov("ADMIN_PIN_LOCKED", auth="cognito"),
     "tài khoản a@x.co", "Nhập sai PIN mục Phân quyền 5 lần, PIN bị khóa 15 phút. "
                         "Nếu không phải chủ tài khoản: phiên đăng nhập có thể đã bị chiếm."),
    (gov("ADMIN_PIN_RESET", target_user="b@x.co"),
     "b@x.co", "a@x.co đặt lại PIN mục Phân quyền của b@x.co."),
]


@pytest.mark.parametrize("incident,subject,sentence", GOVERNANCE,
                         ids=[f"{c[0]['rule']}-{n}" for n, c in enumerate(GOVERNANCE)])
def test_governance_events(incident, subject, sentence):
    assert describe_all([incident])[0] == {"subject": subject, "sentence": sentence}


def test_unknown_rule_falls_back_without_hiding_the_data():
    d = describe("SOMETHING_NEW", ip="203.0.113.50", actor="eve", foo="bar")
    assert d == {"subject": "IP 203.0.113.50 · tài khoản eve",
                 "sentence": "Chưa có mô tả cho luật này. Bấm “Xem dữ liệu gốc” để xem chi tiết."}


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
    assert d["sentence"] == "Chèn mã độc vào ô tìm kiếm: UNION SELECT " + "x" * 67 + "…. IP đã bị khóa 24 giờ."
