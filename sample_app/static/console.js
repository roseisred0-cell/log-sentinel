// LogSentinel SOC Console. Moi du lieu tu may chu deu chen bang textContent (khong innerHTML):
// payload tan cong (vd <script>) chi hien thanh chu, khong bao gio chay.
(function () {
  "use strict";
  var REFRESH_MS = 15000;
  var ROLE_LABEL = { admin: "Quản trị", viewer: "Người xem", pending: "Chờ duyệt" };
  var csrf = "", timer = null, lastData = null, role = "", authKind = "local";
  var cfg = { cognito: false, min_password_level: 2 };
  var pendingEmail = "";
  var $ = function (id) { return document.getElementById(id); };
  var canViewData = function () { return role === "admin" || role === "viewer"; };

  function api(path, options) {
    options = options || {};
    options.credentials = "same-origin";
    options.headers = Object.assign({ "X-CSRF-Token": csrf }, options.headers || {});
    return fetch(path, options).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (body) {
        return { status: res.status, body: body };
      });
    });
  }

  function post(path, obj) {
    return api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj || {}) });
  }

  function cell(text, cls) {
    var td = document.createElement("td");
    if (cls) td.className = cls;
    td.textContent = text == null || text === "" ? "—" : String(text);
    return td;
  }

  function localTime(iso) {
    var d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString("vi-VN");
  }

  function remaining(expiresAt, now) {
    var s = Math.max(0, expiresAt - now), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return h + " giờ " + m + " phút";
  }

  function summarize(details) {
    var skip = { client_ip: 1, ip: 1, username: 1, user: 1, actor: 1, timestamp: 1, source: 1, event_type: 1, severity: 1 };
    return Object.keys(details || {}).filter(function (k) { return !skip[k]; }).map(function (k) {
      var v = details[k];
      return k + ": " + (typeof v === "object" ? JSON.stringify(v) : v);
    }).join(" · ");
  }

  // ------------------------------------------------------------ du lieu su co
  function render(data) {
    lastData = data;
    var filter = $("filter").value;
    var incidents = data.incidents.filter(function (i) { return !filter || i.severity === filter; });
    var count = function (sev) { return data.incidents.filter(function (i) { return i.severity === sev; }).length; };
    $("t-total").textContent = data.incidents.length;
    $("t-critical").textContent = count("CRITICAL");
    $("t-high").textContent = count("HIGH");
    $("t-blocked").textContent = data.blocks.length;

    var tb = $("incidents");
    tb.replaceChildren();
    incidents.forEach(function (i) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(localTime(i.time)));
      var sev = document.createElement("td"), badge = document.createElement("span");
      badge.className = "badge " + (i.severity === "CRITICAL" ? "CRITICAL" : "HIGH");
      badge.textContent = i.severity || "?";
      sev.appendChild(badge);
      tr.appendChild(sev);
      tr.appendChild(cell(i.rule, "mono"));
      tr.appendChild(cell(i.ip, "mono"));
      tr.appendChild(cell(i.actor));
      tr.appendChild(cell(summarize(i.details), "details"));
      tb.appendChild(tr);
    });
    $("incidents-empty").hidden = incidents.length > 0;

    var bb = $("blocks");
    bb.replaceChildren();
    data.blocks.forEach(function (b) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(b.ip, "mono"));
      tr.appendChild(cell(b.reason));
      tr.appendChild(cell(localTime(b.blocked_at)));
      tr.appendChild(cell(remaining(b.expires_at, data.server_time)));
      var td = document.createElement("td");
      if (role === "admin") {  // nguoi xem chi doc, khong go khoa
        var btn = document.createElement("button");
        btn.type = "button"; btn.className = "small"; btn.textContent = "Gỡ khóa";
        btn.addEventListener("click", function () { unblock(b.ip, btn); });
        td.appendChild(btn);
      }
      tr.appendChild(td);
      bb.appendChild(tr);
    });
    $("blocks-empty").hidden = data.blocks.length > 0;
    $("refreshed").textContent = "Cập nhật lúc " + new Date().toLocaleTimeString("vi-VN") + " · tự làm mới mỗi 15 giây";
  }

  function load() {
    if (!canViewData()) return Promise.resolve();
    return api("/api/overview").then(function (r) {
      if (r.status === 401) return showLogin();
      if (r.status !== 200) { $("app-error").textContent = r.body.error || "Không tải được dữ liệu."; return; }
      $("app-error").textContent = "";
      render(r.body);
    }).catch(function () { $("app-error").textContent = "Mất kết nối tới máy chủ."; });
  }

  function unblock(ip, btn) {
    if (!window.confirm("Gỡ khóa IP " + ip + "?")) return;
    btn.disabled = true;
    post("/api/unblock", { ip: ip }).then(function (r) {
      if (r.status !== 200) $("app-error").textContent = r.body.error || "Gỡ khóa thất bại.";
      return load();
    });
  }

  // --------------------------------------------------------------- man hinh
  var PANELS = ["login", "mfa", "register", "confirm", "forgot", "reset"];

  function showPanel(name) {
    PANELS.forEach(function (p) { $("panel-" + p).hidden = p !== name; });
    var tabbed = cfg.cognito && (name === "login" || name === "register");
    $("auth-tabs").hidden = !tabbed;
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (t) {
      t.classList.toggle("active", t.getAttribute("data-tab") === name);
    });
    var first = $("panel-" + name).querySelector("input");
    if (first) first.focus();
  }

  function showLogin() {
    clearInterval(timer);
    role = ""; csrf = "";
    $("app-view").hidden = true; $("userbox").hidden = true; $("login-view").hidden = false;
    showPanel("login");
  }

  function showApp(info) {
    csrf = info.csrf; role = info.role || ""; authKind = info.auth || "local";
    $("username").textContent = info.user;
    var badge = $("role-badge");
    badge.textContent = ROLE_LABEL[role] || role;
    badge.className = "role " + role;
    $("login-view").hidden = true; $("userbox").hidden = false; $("app-view").hidden = false;

    $("data-view").hidden = !canViewData();
    $("pending-notice").hidden = role !== "pending";
    $("users-card").hidden = role !== "admin";
    $("account-card").hidden = role !== "pending";   // nguoi cho duyet: mo san de bat 2FA
    $("mfa-setup").hidden = true;
    $("mfa-disable").hidden = true;

    clearInterval(timer);
    if (canViewData()) { load(); timer = setInterval(load, REFRESH_MS); }
    if (role === "admin") loadUsers();
    loadAccount();
  }

  function start() {
    api("/api/config").then(function (r) { if (r.status === 200) cfg = r.body; })
      .catch(function () {})
      .then(function () {
        configureLoginForm();
        return api("/api/session");
      })
      .then(function (r) { r.status === 200 ? showApp(r.body) : showLogin(); });
  }

  // ------------------------------------------------------------- dang nhap
  function isLocalAccount(name) { return !cfg.cognito || name.indexOf("@") < 0; }

  function configureLoginForm() {
    var user = $("login-user");
    if (!cfg.cognito) {
      if (!user.value) user.value = "admin";
      $("login-hint").textContent = "Dùng tài khoản quản trị và mã 6 số trong ứng dụng Authenticator.";
    } else {
      user.placeholder = "email hoặc admin";
      $("login-hint").textContent = "Đăng nhập bằng email đã đăng ký. Tài khoản nội bộ “admin” cần thêm mã OTP.";
    }
    $("forgot-link").hidden = !cfg.cognito;
    updateOtpField();
  }

  function updateOtpField() {
    var local = isLocalAccount($("login-user").value.trim());
    $("otp-field").hidden = !local;
    $("login-otp").required = local;
  }

  $("login-user").addEventListener("input", updateOtpField);

  $("login-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var form = ev.target, errBox = $("login-error");
    errBox.textContent = "";
    var name = form.username.value.trim(), password = form.password.value;
    var request;
    if (isLocalAccount(name)) {
      request = fetch("/login", { method: "POST", credentials: "same-origin",
                                  body: new URLSearchParams({ username: name, password: password, otp: form.otp.value }) })
        .then(function (res) { return { status: res.status, body: {} }; });
    } else {
      request = post("/auth/login", { email: name, password: password });
    }
    request.then(function (r) {
      if (r.status === 200 && r.body.mfa_required) { form.password.value = ""; $("mfa-form").reset(); return showPanel("mfa"); }
      if (r.status === 200) { form.reset(); return start(); }
      var msg = { 401: "Sai tài khoản hoặc mật khẩu.", 403: "Mã OTP không hợp lệ, hoặc IP của bạn đã bị khóa.",
                  429: "Thao tác quá nhanh, thử lại sau vài giây." };
      if (r.body.error === "not_confirmed") {
        pendingEmail = name.toLowerCase();
        $("confirm-email").textContent = pendingEmail;
        $("confirm-error").textContent = "Email chưa được xác nhận. Nhập mã đã gửi tới hộp thư của bạn.";
        return showPanel("confirm");
      }
      errBox.textContent = msg[r.status] || "Đăng nhập thất bại (" + r.status + ").";
    }).catch(function () { errBox.textContent = "Mất kết nối tới máy chủ."; });
  });

  $("mfa-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    $("mfa-error").textContent = "";
    post("/auth/mfa", { code: ev.target.code.value.trim() }).then(function (r) {
      if (r.status === 200) { ev.target.reset(); return start(); }
      if (r.status === 401) {
        showPanel("login");
        $("login-error").textContent = "Phiên xác thực đã hết hạn, hãy đăng nhập lại.";
        return;
      }
      $("mfa-error").textContent = r.status === 403 ? "Mã OTP không đúng, hoặc IP của bạn đã bị khóa."
        : "Xác thực thất bại (" + r.status + ").";
    }).catch(function () { $("mfa-error").textContent = "Mất kết nối tới máy chủ."; });
  });

  // ---------------------------------------------------------------- dang ky
  // Thanh do manh dung chung cho Dang ky va Dat lai mat khau. Tra ve ham cap nhat (va tra ve muc hien tai).
  function strengthWidget(ids, getEmail, extraValid) {
    function update() {
      var pass = $(ids.pass).value, pass2 = $(ids.pass2).value;
      var result = PasswordStrength.evaluate(pass, getEmail());
      $(ids.meter).setAttribute("data-level", pass ? String(result.level) : "-1");
      $(ids.level).textContent = pass ? "Độ mạnh: " + PasswordStrength.LABELS[result.level] : "Chưa nhập mật khẩu";
      $(ids.warning).textContent = pass ? PasswordStrength.WARNINGS[result.level] : "";
      var tips = $(ids.tips);
      tips.replaceChildren();
      result.tips.forEach(function (t) { var li = document.createElement("li"); li.textContent = t; tips.appendChild(li); });
      var match = pass !== "" && pass === pass2;
      $(ids.submit).disabled = !(result.level >= cfg.min_password_level && match && extraValid());
      $(ids.error).textContent = pass && pass2 && !match ? "Hai mật khẩu chưa giống nhau." : "";
      return result;
    }
    [ids.pass, ids.pass2].concat(ids.extra || []).forEach(function (id) { $(id).addEventListener("input", update); });
    return update;
  }

  var updateStrength = strengthWidget(
    { pass: "reg-pass", pass2: "reg-pass2", meter: "reg-meter", level: "reg-level", warning: "reg-warning",
      tips: "reg-tips", submit: "reg-submit", error: "register-error", extra: ["reg-email"] },
    function () { return $("reg-email").value.trim().toLowerCase(); },
    function () { return $("reg-email").validity.valid && $("reg-email").value.trim() !== ""; });

  $("register-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var email = $("reg-email").value.trim().toLowerCase(), errBox = $("register-error");
    if (updateStrength().level < cfg.min_password_level) return;
    $("reg-submit").disabled = true;
    post("/auth/register", { email: email, password: $("reg-pass").value }).then(function (r) {
      if (r.status === 200) {
        pendingEmail = email;
        $("confirm-email").textContent = email;
        $("confirm-error").textContent = ""; $("confirm-ok").textContent = "";
        ev.target.reset(); updateStrength();
        return showPanel("confirm");
      }
      var msg = { weak_password: "Mật khẩu chưa đủ mạnh.", invalid_email: "Email không hợp lệ.",
                  rate_limited: "Bạn thao tác quá nhiều lần, thử lại sau ít phút." };
      errBox.textContent = msg[r.body.error] || "Đăng ký thất bại (" + r.status + ").";
      updateStrength();
    }).catch(function () { errBox.textContent = "Mất kết nối tới máy chủ."; updateStrength(); });
  });

  $("confirm-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    $("confirm-error").textContent = ""; $("confirm-ok").textContent = "";
    post("/auth/confirm", { email: pendingEmail, code: ev.target.code.value.trim() }).then(function (r) {
      if (r.status === 200) {
        ev.target.reset();
        $("login-user").value = pendingEmail; updateOtpField();
        showPanel("login");
        $("login-error").textContent = "";
        $("login-hint").textContent = "Email đã được xác nhận. Hãy đăng nhập; quản trị viên sẽ duyệt tài khoản của bạn.";
        return;
      }
      var msg = { 429: "Thử quá nhiều lần, hãy đợi vài phút." };
      $("confirm-error").textContent = msg[r.status] || "Mã không đúng hoặc đã hết hạn.";
    }).catch(function () { $("confirm-error").textContent = "Mất kết nối tới máy chủ."; });
  });

  $("resend").addEventListener("click", function () {
    $("confirm-error").textContent = ""; $("confirm-ok").textContent = "";
    post("/auth/resend", { email: pendingEmail }).then(function (r) {
      if (r.status === 200) $("confirm-ok").textContent = "Nếu email hợp lệ, mã mới đã được gửi.";
      else $("confirm-error").textContent = r.status === 429 ? "Bạn yêu cầu quá nhiều lần, hãy đợi vài phút." : "Gửi lại mã thất bại.";
    });
  });

  Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (t) {
    t.addEventListener("click", function () { showPanel(t.getAttribute("data-tab")); });
  });

  // ------------------------------------------------------------ quen mat khau
  var updateResetStrength = strengthWidget(
    { pass: "rst-pass", pass2: "rst-pass2", meter: "rst-meter", level: "rst-level", warning: "rst-warning",
      tips: "rst-tips", submit: "rst-submit", error: "reset-error" },
    function () { return pendingEmail; },
    function () { return true; });

  $("forgot-link").addEventListener("click", function () {
    var typed = $("login-user").value.trim();
    $("forgot-email").value = typed.indexOf("@") > 0 ? typed : "";
    $("forgot-error").textContent = "";
    showPanel("forgot");
  });

  Array.prototype.forEach.call(document.querySelectorAll(".back-to-login"), function (b) {
    b.addEventListener("click", function () { $("login-error").textContent = ""; showPanel("login"); });
  });

  $("forgot-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var email = $("forgot-email").value.trim().toLowerCase();
    $("forgot-error").textContent = "";
    post("/auth/forgot", { email: email }).then(function (r) {
      if (r.status !== 200) {
        $("forgot-error").textContent = r.status === 429 ? "Bạn yêu cầu quá nhiều lần, hãy đợi vài phút." : "Không gửi được mã (" + r.status + ").";
        return;
      }
      pendingEmail = email;
      $("reset-info").textContent = "Nếu " + email + " đã đăng ký, mã 6 số đã được gửi tới hộp thư. Nhập mã và mật khẩu mới bên dưới.";
      $("reset-form").reset(); $("reset-error").textContent = "";
      updateResetStrength();
      showPanel("reset");
    }).catch(function () { $("forgot-error").textContent = "Mất kết nối tới máy chủ."; });
  });

  $("reset-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var form = ev.target;
    if (updateResetStrength().level < cfg.min_password_level) return;
    $("rst-submit").disabled = true;
    post("/auth/reset", { email: pendingEmail, code: form.code.value.trim(), password: form.password.value }).then(function (r) {
      if (r.status === 200) {
        form.reset(); updateResetStrength();
        $("login-user").value = pendingEmail; updateOtpField();
        showPanel("login");
        $("login-error").textContent = "";
        $("login-hint").textContent = "Đã đổi mật khẩu. Hãy đăng nhập bằng mật khẩu mới.";
        return;
      }
      var msg = { invalid_code: "Mã không đúng hoặc đã hết hạn.", weak_password: "Mật khẩu chưa đủ mạnh.",
                  rate_limited: "Thử quá nhiều lần, hãy đợi vài phút." };
      $("reset-error").textContent = msg[r.body.error] || "Đặt lại mật khẩu thất bại (" + r.status + ").";
      updateResetStrength();
    }).catch(function () { $("reset-error").textContent = "Mất kết nối tới máy chủ."; updateResetStrength(); });
  });

  // ------------------------------------------------------ tai khoan & 2FA
  function showQr(svgText) {
    var box = $("mfa-qr");
    box.replaceChildren();
    if (!svgText) return;
    var root = new DOMParser().parseFromString(svgText, "image/svg+xml").documentElement;
    if (root && root.nodeName.toLowerCase() === "svg") box.appendChild(document.importNode(root, true));
  }

  function loadAccount() {
    api("/api/account").then(function (r) {
      if (r.status === 401) return showLogin();
      if (r.status !== 200) { $("account-error").textContent = "Không đọc được thông tin tài khoản."; return; }
      var a = r.body, toggle = $("mfa-toggle");
      $("acc-email").textContent = a.email;
      $("acc-role").textContent = ROLE_LABEL[a.role] || a.role;
      $("account-error").textContent = "";
      if (a.auth !== "cognito") {
        $("mfa-state").textContent = "đang bật (bắt buộc)";
        $("mfa-note").textContent = "Tài khoản quản trị nội bộ luôn dùng 2FA; khóa được cấu hình trên máy chủ nên không tắt được ở đây.";
        toggle.hidden = true;
        return;
      }
      toggle.hidden = false;
      toggle.setAttribute("data-enabled", a.mfa_enabled ? "1" : "0");
      toggle.textContent = a.mfa_enabled ? "Tắt 2FA" : "Bật 2FA";
      $("mfa-state").textContent = a.mfa_enabled ? "đang BẬT" : "đang TẮT";
      $("mfa-note").textContent = a.mfa_enabled
        ? "Mỗi lần đăng nhập bạn cần thêm mã 6 số từ ứng dụng Authenticator."
        : "Khuyến nghị bật 2FA: nếu chỉ có mật khẩu, tài khoản dễ bị chiếm khi mật khẩu bị lộ.";
    }).catch(function () { $("account-error").textContent = "Mất kết nối tới máy chủ."; });
  }

  $("account-toggle").addEventListener("click", function () {
    $("account-card").hidden = !$("account-card").hidden;
  });

  $("mfa-toggle").addEventListener("click", function () {
    var enabled = $("mfa-toggle").getAttribute("data-enabled") === "1";
    $("account-error").textContent = "";
    if (enabled) {
      $("mfa-setup").hidden = true;
      $("mfa-disable-form").reset();
      $("mfa-disable").hidden = false;
      $("mfa-disable-form").password.focus();
      return;
    }
    $("mfa-disable").hidden = true;
    post("/api/mfa/setup").then(function (r) {
      if (r.status === 401) return showLogin();
      if (r.status !== 200) { $("account-error").textContent = "Không bắt đầu được thiết lập 2FA."; return; }
      $("mfa-secret").textContent = r.body.secret;
      showQr(r.body.qr_svg);
      $("mfa-enable-form").reset();
      $("mfa-setup").hidden = false;
      $("mfa-enable-code").focus();
    });
  });

  $("mfa-cancel").addEventListener("click", function () { $("mfa-setup").hidden = true; });
  $("mfa-disable-cancel").addEventListener("click", function () { $("mfa-disable").hidden = true; });

  $("mfa-disable-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var form = ev.target;
    $("account-error").textContent = "";
    post("/api/mfa/disable", { password: form.password.value, code: form.code.value.trim() }).then(function (r) {
      if (r.status === 401) return showLogin();
      if (r.status !== 200) {
        var msg = { reauth_failed: "Mật khẩu hoặc mã OTP không đúng.", rate_limited: "Thử quá nhiều lần, hãy đợi vài phút." };
        $("account-error").textContent = msg[r.body.error] || "Không tắt được 2FA (" + r.status + ").";
        return;
      }
      form.reset();
      $("mfa-disable").hidden = true;
      loadAccount();
    }).catch(function () { $("account-error").textContent = "Mất kết nối tới máy chủ."; });
  });

  $("mfa-enable-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    $("account-error").textContent = "";
    post("/api/mfa/enable", { code: ev.target.code.value.trim() }).then(function (r) {
      if (r.status === 401) return showLogin();
      if (r.status !== 200) { $("account-error").textContent = "Mã OTP không đúng. Kiểm tra giờ trên điện thoại rồi thử lại."; return; }
      $("mfa-setup").hidden = true;
      $("mfa-secret").textContent = "";
      $("mfa-qr").replaceChildren();
      loadAccount();
    });
  });

  // -------------------------------------------------- quan tri duyet nguoi dung
  function userRow(u, label, action) {
    var tr = document.createElement("tr");
    tr.appendChild(cell(u.email));
    tr.appendChild(cell(u.created ? localTime(u.created) : "", "muted"));
    var td = document.createElement("td"), btn = document.createElement("button");
    btn.type = "button"; btn.className = "small"; btn.textContent = label;
    btn.addEventListener("click", function () {
      if (action === "revoke" && !window.confirm("Thu hồi quyền xem của " + u.email + "?")) return;
      btn.disabled = true;
      post("/api/users/" + action, { username: u.username }).then(function (r) {
        if (r.status !== 200) $("app-error").textContent = "Thao tác thất bại (" + (r.body.error || r.status) + ").";
        loadUsers();
      });
    });
    td.appendChild(btn); tr.appendChild(td);
    return tr;
  }

  function fillUsers(tbodyId, emptyId, rows, label, action) {
    var tb = $(tbodyId);
    tb.replaceChildren();
    rows.forEach(function (u) { tb.appendChild(userRow(u, label, action)); });
    $(emptyId).hidden = rows.length > 0;
  }

  function loadUsers() {
    api("/api/users").then(function (r) {
      if (r.status !== 200) { $("app-error").textContent = "Không tải được danh sách người dùng."; return; }
      fillUsers("users-pending", "users-pending-empty", r.body.pending, "Duyệt", "approve");
      fillUsers("users-viewers", "users-viewers-empty", r.body.viewers, "Thu hồi", "revoke");
      var admins = r.body.admins.map(function (u) { return u.email; });
      $("users-admins").textContent = admins.length ? "Quản trị viên (Cognito): " + admins.join(", ") : "";
    });
  }

  $("logout").addEventListener("click", function () { api("/api/logout", { method: "POST" }).then(showLogin); });
  $("filter").addEventListener("change", function () { if (lastData) render(lastData); });
  start();
})();
