// Cau tieng Viet de doc cho cot Doi tuong / Chi tiet cua bang su co (thiet ke chot 11/11).
//   IncidentText.describe({rule, ip, actor, details}) -> {subject, sentence}
// Ham thuan, khong cham DOM: console.js chen ket qua bang textContent (du lieu ke tan cong nhap chi hien thanh chu).
// Moi luat Detector co the sinh ra PHAI co mot muc o RULES (tests/unit/test_incident_text.py kiem tra).
// Thieu truong (ban ghi cu, du lieu la): cau van doc duoc, khong bao gio hien "undefined".
(function (root) {
  "use strict";
  var BLOCKED = "IP đã bị khóa 24 giờ.";
  var PAYLOAD_MAX = 80;
  var FALLBACK = "Chưa có mô tả cho luật này. Bấm “Xem dữ liệu gốc” để xem chi tiết.";

  // ------------------------------------------------------------- tien ich
  function text(x) { return x == null || typeof x === "object" ? "" : String(x); }
  function shorten(x, max) { var s = text(x); return s.length > max ? s.slice(0, max) + "…" : s; }
  function duration(seconds) {
    var s = Number(seconds) || 0;
    if (s >= 3600 && s % 3600 === 0) return s / 3600 + " giờ";
    if (s >= 120 && s % 60 === 0) return s / 60 + " phút";
    return s + " giây";
  }
  function times(n) { return text(n) ? n + " lần" : "nhiều lần"; }
  function within(seconds) { return Number(seconds) > 0 ? " trong " + duration(seconds) : ""; }
  function fromIp(ip) { return text(ip) ? " từ IP " + ip : ""; }
  function who(name) { return text(name) || "Có người"; }
  function joinParts(parts) { return parts.filter(Boolean).join(" · "); }
  function ipAndAccount(i) {
    return joinParts([text(i.ip) && "IP " + i.ip, text(i.actor) && "tài khoản " + i.actor]);
  }
  function ipOnly(i) { return text(i.ip) ? "IP " + i.ip : ""; }
  function awsUser(name) { return text(name) ? "người dùng AWS " + name : ""; }

  var RULES = {};

  // --------------------------------------------------------------- web app
  RULES.BRUTE_FORCE_DETECTED = function (i, d) {
    return { subject: ipAndAccount(i),
             sentence: "Đoán sai mật khẩu " + times(d.attempt_count) + within(d.window_seconds) + ". " + BLOCKED };
  };
  RULES.SLOW_BRUTE_FORCE = function (i, d) {
    return { subject: ipAndAccount(i),
             sentence: "Đoán sai mật khẩu " + times(d.attempt_count) + within(d.window_seconds) +
               ", rải đều để né luật đoán nhanh. " + BLOCKED };
  };
  RULES.ACCOUNT_UNDER_ATTACK = function (i, d) {
    var account = text(d.username) || text(i.actor);
    var last = text(d.last_ip) ? " (gần nhất " + d.last_ip + ")" : "";
    return { subject: account ? "tài khoản " + account : "",
             sentence: "Bị đoán sai mật khẩu " + times(d.attempt_count) + within(d.window_seconds) +
               " từ nhiều IP khác nhau" + last + ". Không IP nào bị khóa tự động." };
  };
  RULES.LOGIN_FAILURE_SPIKE = function (i, d) {
    var count = text(d.attempt_count) ? d.attempt_count + " lần" : "Rất nhiều lần";
    return { subject: "Toàn hệ thống",
             sentence: count + " đăng nhập sai" + within(d.window_seconds) +
               ", từ nhiều IP vào nhiều tài khoản. Có thể đang bị thử mật khẩu hàng loạt." };
  };
  RULES.SCAN_DETECTED = function (i, d) {
    var last = text(d.path) ? " (gần nhất: " + shorten(d.path, PAYLOAD_MAX) + ")" : "";
    var count = text(d.attempt_count) ? d.attempt_count + " đường dẫn" : "nhiều đường dẫn";
    return { subject: ipOnly(i),
             sentence: "Gọi " + count + " không tồn tại" + within(d.window_seconds) + last + ". " + BLOCKED };
  };
  RULES.SQL_INJECTION = function (i, d) {
    var where = d.field === "username" || d.field === "email" ? "ô đăng nhập" : "ô tìm kiếm";
    var payload = text(d.payload) ? ": " + shorten(d.payload, PAYLOAD_MAX) : "";
    return { subject: ipOnly(i), sentence: "Chèn mã độc vào " + where + payload + ". " + BLOCKED };
  };
  RULES.MFA_BYPASS_ATTEMPT = function (i) {
    return { subject: ipAndAccount(i),
             sentence: "Mật khẩu đúng nhưng mã OTP sai: mật khẩu có thể đã bị lộ, nên đổi ngay. " + BLOCKED };
  };

  // ------------------------------------------------- CloudTrail (tai khoan AWS)
  RULES.ROOT_ACCOUNT_LOGIN = function (i, d) {
    var how = d.outcome === "Failure" ? " thất bại" : d.mfa_used === "Yes" ? ", có dùng MFA" : ", không dùng MFA";
    return { subject: "tài khoản root AWS",
             sentence: "Đăng nhập AWS Console bằng tài khoản root" + fromIp(d.ip) + how +
               ". Root không nên dùng hằng ngày: kiểm tra có phải bạn không." };
  };
  RULES.CONSOLE_LOGIN_NO_MFA = function (i, d) {
    return { subject: awsUser(d.user),
             sentence: "Đăng nhập AWS Console thành công" + fromIp(d.ip) +
               " mà không dùng MFA. Nên bật MFA cho người dùng này." };
  };
  RULES.CONSOLE_BRUTE_FORCE = function (i, d) {
    return { subject: joinParts([text(d.ip) && "IP " + d.ip, awsUser(d.user)]),
             sentence: "Đăng nhập AWS Console sai " + times(d.attempt_count) + within(d.window_seconds) +
               ". Hệ thống không khóa được IP ở AWS Console." };
  };
  RULES.MFA_TAMPERING = function (i, d) {
    var what = d.action === "DeleteVirtualMFADevice" ? "Xóa thiết bị MFA ảo" : "Tắt thiết bị MFA";
    return { subject: awsUser(d.user), sentence: what + fromIp(d.ip) + "." };
  };
  RULES.CLOUDTRAIL_TAMPERING = function (i, d) {
    var what = d.action === "DeleteTrail" ? "Xóa" : "Dừng ghi";
    return { subject: awsUser(d.user),
             sentence: what + " nhật ký kiểm toán (CloudTrail)" + fromIp(d.ip) + ": dấu hiệu xóa dấu vết." };
  };
  RULES.KMS_KEY_TAMPERING = function (i, d) {
    var what = d.action === "DisableKey" ? " vô hiệu hóa" : " hẹn xóa";
    return { subject: text(d.key_id) ? "khóa KMS " + d.key_id : "khóa KMS",
             sentence: who(d.user) + what + " khóa mã hóa" + fromIp(d.ip) +
               ". Khẩn cấp: mất khóa là mất toàn bộ log và bảng sự cố." };
  };

  // ------------------------------------------------------ leo thang quyen IAM
  function iamTarget(d) {
    if (text(d.target_role)) return "role " + d.target_role;
    if (text(d.target_group)) return "nhóm " + d.target_group;
    if (text(d.target_user)) return "người dùng AWS " + d.target_user;
    return "";
  }
  function policyName(d) {
    var arn = text(d.policy_arn);
    return arn ? arn.split("/").pop() : text(d.policy_name);
  }
  function iamSuffix(d) {
    var parts = [];
    if (policyName(d) === "AdministratorAccess") parts.push("Đây là quyền cao nhất.");
    if (text(d.error_code)) parts.push("Bị từ chối (" + d.error_code + ").");
    if (d.via_service === "cloudformation.amazonaws.com") parts.push("Thực hiện qua CloudFormation (cdk deploy).");
    else if (text(d.via_service)) parts.push("Thực hiện qua dịch vụ " + d.via_service + ".");
    return parts.length ? " " + parts.join(" ") : "";
  }
  function iamRule(subjectOf, sentenceOf) {
    return function (i, d) {
      return { subject: subjectOf(d), sentence: who(d.actor) + " " + sentenceOf(d) + "." + iamSuffix(d) };
    };
  }
  function to(d) { return iamTarget(d) || "một đối tượng IAM"; }
  function policy(d) { return policyName(d) ? "policy " + policyName(d) : "một policy"; }

  RULES.IAM_ACCESS_KEY_CREATED = iamRule(
    function (d) { return iamTarget(d) || awsUser(d.actor); },
    function (d) { return "tạo khóa truy cập (access key) cho " + (iamTarget(d) || "chính mình"); });
  RULES.IAM_POLICY_ATTACHED = iamRule(iamTarget,
    function (d) { return "gắn " + policy(d) + " cho " + to(d); });
  RULES.IAM_INLINE_POLICY_PUT = iamRule(iamTarget,
    function (d) { return "ghi inline " + policy(d) + " cho " + to(d); });
  RULES.IAM_POLICY_VERSION_CREATED = iamRule(
    function (d) { return policyName(d) ? "policy " + policyName(d) : ""; },
    function (d) { return "sửa nội dung " + policy(d) + " (tạo phiên bản mới)"; });
  RULES.IAM_TRUST_POLICY_CHANGED = iamRule(iamTarget,
    function (d) { return "sửa trust policy của " + to(d) + ": danh sách ai được mượn quyền của role này có thể đã đổi"; });
  RULES.IAM_LOGIN_PROFILE_CHANGED = iamRule(iamTarget,
    function (d) {
      return d.action === "CreateLoginProfile" ? "đặt mật khẩu AWS Console cho " + to(d)
        : "đổi mật khẩu AWS Console của " + to(d);
    });
  RULES.IAM_USER_ADDED_TO_GROUP = iamRule(
    function (d) { return text(d.target_group) ? "nhóm " + d.target_group : ""; },
    function (d) {
      return "thêm " + (awsUser(d.target_user) || "một người dùng AWS") + " vào " +
        (text(d.target_group) ? "nhóm " + d.target_group : "một nhóm");
    });

  // ------------------------------------------- muc Phan quyen cua SOC Console
  var PROPOSAL = { promote: "nâng {t} lên Quản trị", demote: "hạ {t} xuống Người xem", disable: "vô hiệu hóa tài khoản {t}" };
  function targetUser(d) { return text(d.target_user) || "một tài khoản"; }
  function proposal(d) { return (PROPOSAL[d.action] || "thay đổi quyền của {t}").replace("{t}", targetUser(d)); }
  function person(principal) {
    var p = text(principal);
    if (p.indexOf("local:") === 0) return "admin nội bộ";
    return p.indexOf(":") >= 0 ? p.slice(p.indexOf(":") + 1) : p;
  }
  function approvedBy(d) {
    var list = Array.isArray(d.approvers) ? d.approvers.map(person).filter(Boolean) : [];
    return list.length ? ", với sự đồng ý của " + list.join(", ") : "";
  }

  RULES.ROLE_REQUEST_CREATED = function (i, d) {
    return { subject: text(d.target_user),
             sentence: who(d.username) + " đề xuất " + proposal(d) + ". Các quản trị viên khác vào mục Phân quyền để bỏ phiếu." };
  };
  RULES.ADMIN_ROLE_CHANGED = function (i, d) {
    var change = d.action === "demote" ? " bị hạ xuống Người xem" : " được nâng lên Quản trị";
    var how = d.bootstrap === true ? " bởi admin nội bộ (chế độ khởi tạo)" : approvedBy(d);
    return { subject: text(d.target_user), sentence: targetUser(d) + change + how + "." };
  };
  RULES.USER_DISABLED = function (i, d) {
    return { subject: text(d.target_user), sentence: "Tài khoản " + targetUser(d) + " bị vô hiệu hóa" + approvedBy(d) + "." };
  };
  RULES.ROLE_CHANGE_FAILED = function (i, d) {
    return { subject: text(d.target_user),
             sentence: "Đủ phiếu để " + proposal(d) + " nhưng Cognito lỗi nên chưa thực hiện. " +
               "Bấm Đồng ý lại trên yêu cầu đó để thử lại." };
  };
  RULES.ADMIN_PIN_LOCKED = function (i, d) {
    return { subject: text(d.username) ? "tài khoản " + d.username : "",
             sentence: "Nhập sai PIN mục Phân quyền 5 lần, PIN bị khóa 15 phút. " +
               "Nếu không phải chủ tài khoản: phiên đăng nhập có thể đã bị chiếm." };
  };
  RULES.ADMIN_PIN_RESET = function (i, d) {
    return { subject: text(d.target_user),
             sentence: who(d.username) + " đặt lại PIN mục Phân quyền của " + targetUser(d) + "." };
  };

  // ------------------------------------------------------------- diem vao
  function describe(incident) {
    var i = incident && typeof incident === "object" ? incident : {};
    var d = i.details && typeof i.details === "object" ? i.details : {};
    var rule = Object.prototype.hasOwnProperty.call(RULES, i.rule) ? RULES[i.rule] : null;
    if (rule) {
      try { return rule(i, d); } catch (e) { /* du lieu la: roi xuong cau mac dinh */ }
    }
    return { subject: ipAndAccount(i), sentence: FALLBACK };
  }

  var api = { describe: describe, RULES: Object.keys(RULES) };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.IncidentText = api;
})(typeof window !== "undefined" ? window : this);
