// LogSentinel SOC Console. Moi du lieu tu may chu deu chen bang textContent (khong innerHTML):
// payload tan cong (vd <script>) chi hien thanh chu, khong bao gio chay.
(function () {
  "use strict";
  var REFRESH_MS = 15000;
  var ROLE_LABEL = { admin: "Quản trị", viewer: "Người xem", pending: "Chờ duyệt" };
  var csrf = "", timer = null, lastData = null, role = "", authKind = "local", mfaSetupRequired = false;
  var cfg = { cognito: false, chat: false, min_password_level: 2 };
  // Bang Su co gan day: mac dinh chi hien 10 dong moi nhat, bam "Xem them" de mo het (giu trang thai khi tu lam moi).
  var INCIDENT_PREVIEW = 10, incidentsExpanded = false;
  var chatIncident = null;   // su co dang hoi tro ly AI (null = cac su co gan day)
  // Thong ke: 24 gio tu lam moi moi 60 giay; 7 / 30 ngay chi tai khi bam chon (doc toi 5.000 su co).
  var STATS_MS = 60000, statsTimer = null, statsRange = "24h";
  var pendingEmail = "";
  var $ = function (id) { return document.getElementById(id); };
  // Quan tri vien Cognito chua bat 2FA: chi duoc vao muc Tai khoan de bat 2FA (may chu cung chan).
  var canViewData = function () { return (role === "admin" || role === "viewer") && !mfaSetupRequired; };

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

  // Cot Chi tiet: cau tieng Viet de doc (incident-text.js) + nut "Xem du lieu goc" mo JSON day du.
  // Moi gia tri chen bang textContent: payload tan cong trong du lieu goc chi hien thanh chu.
  function detailsCell(incident, sentence) {
    var td = document.createElement("td"), p = document.createElement("div");
    td.className = "details";
    p.textContent = sentence;
    td.appendChild(p);
    var box = document.createElement("details"), summary = document.createElement("summary");
    var pre = document.createElement("pre");
    summary.textContent = "Xem dữ liệu gốc";
    pre.textContent = JSON.stringify(incident.details || {}, null, 2);
    box.appendChild(summary);
    box.appendChild(pre);
    td.appendChild(box);
    return td;
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
    var hiddenCount = incidents.length - INCIDENT_PREVIEW;
    var shown = incidentsExpanded ? incidents : incidents.slice(0, INCIDENT_PREVIEW);
    shown.forEach(function (i) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(localTime(i.time)));
      var sev = document.createElement("td"), badge = document.createElement("span");
      badge.className = "badge " + (i.severity === "CRITICAL" ? "CRITICAL" : "HIGH");
      badge.textContent = i.severity || "?";
      sev.appendChild(badge);
      tr.appendChild(sev);
      tr.appendChild(cell(i.rule, "mono"));
      var text = IncidentText.describe(i);
      tr.appendChild(cell(i.ip, "mono"));
      tr.appendChild(cell(text.subject));
      var details = detailsCell(i, text.sentence);
      if (cfg.chat) {   // nut nam trong o Chi tiet (khong them cot: bang da rong)
        var ask = document.createElement("button");
        ask.type = "button"; ask.className = "small ask-ai"; ask.textContent = "Hỏi AI";
        ask.addEventListener("click", function () { chatAbout(i); });
        details.appendChild(ask);
      }
      tr.appendChild(details);
      tb.appendChild(tr);
    });
    $("incidents-empty").hidden = incidents.length > 0;
    var more = $("incidents-more");
    more.hidden = hiddenCount <= 0;
    more.setAttribute("aria-expanded", String(incidentsExpanded));
    more.textContent = incidentsExpanded ? "Thu gọn (chỉ hiện " + INCIDENT_PREVIEW + " sự cố mới nhất)"
                                         : "Xem thêm " + hiddenCount + " sự cố";

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
    clearInterval(govClock);
    clearInterval(statsTimer);
    role = ""; csrf = ""; mfaSetupRequired = false;
    $("app-view").hidden = true; $("userbox").hidden = true; $("login-view").hidden = false;
    showPanel("login");
  }

  function showApp(info) {
    csrf = info.csrf; role = info.role || ""; authKind = info.auth || "local";
    mfaSetupRequired = !!info.mfa_setup_required;
    $("username").textContent = info.user;
    var badge = $("role-badge");
    badge.textContent = ROLE_LABEL[role] || role;
    badge.className = "role " + role;
    $("login-view").hidden = true; $("userbox").hidden = false; $("app-view").hidden = false;

    $("data-view").hidden = !canViewData();
    $("pending-notice").hidden = role !== "pending";
    $("mfa-required-notice").hidden = !mfaSetupRequired;
    $("gov-card").hidden = role !== "admin" || mfaSetupRequired;
    $("chat-card").hidden = !(cfg.chat && canViewData());
    // nguoi cho duyet va admin chua bat 2FA: mo san muc Tai khoan de bat 2FA
    $("account-card").hidden = !(role === "pending" || mfaSetupRequired);
    $("mfa-setup").hidden = true;
    $("mfa-disable").hidden = true;
    govNotify();

    clearInterval(timer);
    clearInterval(statsTimer);
    if (canViewData()) {
      load(); timer = setInterval(load, REFRESH_MS);
      selectRange(statsRange);
    }
    if (role === "admin" && !mfaSetupRequired) loadGov();
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
      var adminLocked = a.role === "admin" && a.mfa_enabled;   // quan tri vien khong duoc tat 2FA
      toggle.hidden = adminLocked;
      toggle.setAttribute("data-enabled", a.mfa_enabled ? "1" : "0");
      toggle.textContent = a.mfa_enabled ? "Tắt 2FA" : "Bật 2FA";
      $("mfa-state").textContent = a.mfa_enabled ? "đang BẬT" : "đang TẮT";
      $("mfa-note").textContent = adminLocked
        ? "Quản trị viên bắt buộc dùng 2FA nên không có nút tắt."
        : a.mfa_enabled
          ? "Mỗi lần đăng nhập bạn cần thêm mã 6 số từ ứng dụng Authenticator."
          : a.role === "admin"
            ? "Quản trị viên bắt buộc bật 2FA trước khi xem dữ liệu."
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
      if (mfaSetupRequired) return start();   // admin vua bat 2FA: tai lai phien de mo du lieu va Phan quyen
      loadAccount();
    });
  });

  // ------------------------------------------------------- muc Phan quyen
  // PIN rieng 6 so; mo 10 phut. Nang/ha/vo hieu hoa can phieu cua cac quan tri vien khac (admin_governance.py).
  var GOV_ERRORS = {
    weak_pin: "PIN phải đúng 6 chữ số và không dễ đoán (vd 123456, 000000, 121212).",
    pin_exists: "Bạn đã có PIN.", wrong_pin: "PIN không đúng.",
    pin_locked: "PIN đang bị khóa 15 phút do nhập sai nhiều lần.",
    pin_required: "Mục Phân quyền đã tự khóa, hãy nhập lại PIN.",
    busy: "Một thao tác phân quyền khác đang chạy, thử lại sau vài giây.",
    local_admin_restricted: "Đã đủ 2 quản trị viên: tài khoản admin nội bộ chỉ còn xem và gỡ khóa IP.",
    not_admin: "Chỉ quản trị viên được làm thao tác này.",
    unauthenticated: "Phiên đăng nhập không còn hợp lệ với hệ thống phân quyền, hãy đăng nhập lại.",
    upstream: "Dịch vụ tài khoản đang lỗi nên chưa thực hiện được. Yêu cầu vẫn được giữ; bấm Đồng ý lại để thử lại.",
    invalid_target: "Không thực hiện được với tài khoản này.",
    self_action: "Bạn không thể tự thao tác lên tài khoản của chính mình.",
    min_admins: "Phải luôn còn ít nhất 2 quản trị viên.",
    not_enough_admins: "Chưa đủ quản trị viên để duyệt thao tác này.",
    local_admin_no_vote: "Đã đủ 2 quản trị viên: tài khoản admin nội bộ không còn quyền bỏ phiếu.",
    not_a_voter: "Bạn không được bỏ phiếu cho yêu cầu này.",
    already_voted: "Bạn đã đồng ý yêu cầu này rồi.", request_closed: "Yêu cầu đã kết thúc.",
    request_expired: "Yêu cầu đã hết hạn (24 giờ).", not_found: "Không tìm thấy.",
    execution_failed: "Không thực hiện được: danh sách người dùng đã thay đổi.",
    invalid_request: "Yêu cầu không hợp lệ."
  };
  var ACTION_LABEL = { promote: "Nâng lên Quản trị", demote: "Hạ xuống Người xem", disable: "Vô hiệu hóa" };
  var govClock = null, govUntil = 0, clockOffset = 0;

  function govMessage(r) {
    return GOV_ERRORS[r.body.error] || "Thao tác thất bại (" + (r.body.error || r.status) + ").";
  }

  function govNotify(err, ok) { $("gov-error").textContent = err || ""; $("gov-ok").textContent = ok || ""; }

  function showGovState(state) {
    ["setpin", "unlock", "open"].forEach(function (s) { $("gov-" + s).hidden = s !== state; });
    var first = $("gov-" + state).querySelector("input");
    if (first && state !== "open") first.focus();
  }

  function tickGovClock() {
    var left = Math.round(govUntil - (Date.now() / 1000 + clockOffset));
    if (left <= 0) { clearInterval(govClock); $("gov-timer").textContent = ""; return loadGov(); }
    $("gov-timer").textContent = "Tự khóa sau " + Math.floor(left / 60) + ":" + ("0" + (left % 60)).slice(-2);
  }

  function loadGov() {
    return api("/api/governance").then(function (r) {
      if (r.status === 401) return showLogin();
      if (r.status === 403 && r.body.error === "mfa_setup_required") return start();
      if (r.status !== 200) { govNotify("Không tải được mục Phân quyền."); return; }
      var g = r.body;
      clearInterval(govClock);
      renderGovSummary(g);   // canh bao do duoi 2 admin: hien ca khi muc dang khoa
      if (!g.has_pin) { $("gov-timer").textContent = ""; pendingHint(false); return showGovState("setpin"); }
      if (!g.unlocked) { $("gov-timer").textContent = ""; pendingHint(true); return showGovState("unlock"); }
      $("gov-pending-hint").hidden = true;   // muc da mo: danh sach cho duyet hien ngay ben duoi
      showGovState("open");
      clockOffset = g.server_time - Date.now() / 1000;
      govUntil = g.unlocked_until;
      tickGovClock();
      govClock = setInterval(tickGovClock, 1000);
      renderRequests(g.requests || []);
      return loadUsers();
    }).catch(function () { govNotify("Mất kết nối tới máy chủ."); });
  }

  // Muc dang khoa: van bao co bao nhieu tai khoan cho duyet (chi dem, khong lo email) de admin biet vi sao can PIN.
  function pendingHint(hasPin) {
    var hint = $("gov-pending-hint");
    api("/api/users").then(function (r) {
      var n = r.status === 200 && r.body.pending ? r.body.pending.length : 0;
      hint.hidden = n === 0;
      hint.textContent = "Có " + n + " tài khoản đang chờ duyệt. " +
        (hasPin ? "Nhập PIN bên dưới để mở mục và duyệt." : "Đặt PIN bên dưới để mở mục và duyệt.");
    }).catch(function () { hint.hidden = true; });
  }

  function renderGovSummary(g) {
    var warn = $("gov-min-warning"), boot = $("gov-bootstrap");
    warn.hidden = g.admin_count >= 2;
    warn.textContent = "Hiện có " + g.admin_count + " quản trị viên, tối thiểu phải là 2.";
    boot.hidden = !g.bootstrap;
    boot.textContent = authKind === "local"
      ? "Chế độ khởi tạo: bạn (admin nội bộ) được tự nâng một Người xem lên Quản trị cho tới khi đủ 2 quản trị viên."
      : "Chế độ khởi tạo: admin nội bộ được bỏ phiếu thay người thứ hai cho tới khi đủ 2 quản trị viên.";
  }

  function renderRequests(requests) {
    var tb = $("gov-requests");
    tb.replaceChildren();
    requests.forEach(function (q) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(ACTION_LABEL[q.action] || q.action));
      tr.appendChild(cell(q.target_user));
      tr.appendChild(cell(q.initiator));
      tr.appendChild(cell(q.approvals + "/" + q.needed));
      tr.appendChild(cell(localTime(q.expires_at * 1000), "muted"));
      var td = document.createElement("td");
      td.appendChild(govButton("Đồng ý", function () {
        return govAction("/api/governance/requests/" + encodeURIComponent(q.id) + "/vote", { decision: "approve" });
      }));
      td.appendChild(govButton("Từ chối", function () {
        if (!window.confirm("Từ chối sẽ hủy yêu cầu ngay. Tiếp tục?")) return null;
        return govAction("/api/governance/requests/" + encodeURIComponent(q.id) + "/vote", { decision: "reject" });
      }));
      tr.appendChild(td);
      tb.appendChild(tr);
    });
    $("gov-requests-empty").hidden = requests.length > 0;
  }

  function govButton(label, onClick) {
    var btn = document.createElement("button");
    btn.type = "button"; btn.className = "small"; btn.textContent = label;
    btn.addEventListener("click", function () {
      var pending = onClick();
      if (!pending) return;
      btn.disabled = true;
      pending.then(function () { btn.disabled = false; });
    });
    return btn;
  }

  // Thao tac can PIN xac nhan (tao yeu cau, bo phieu, dat lai PIN).
  function govAction(path, body) {
    var pin = $("gov-pin").value.trim();
    if (!/^[0-9]{6}$/.test(pin)) { govNotify("Nhập PIN xác nhận (6 số) trước khi thao tác."); $("gov-pin").focus(); return null; }
    govNotify();
    return post(path, Object.assign({ pin: pin }, body)).then(function (r) {
      $("gov-pin").value = "";
      if (r.status === 401) return showLogin();
      if (r.status !== 200) { govNotify(govMessage(r)); return loadGov(); }
      var msg = { pending: "Đã ghi phiếu. Đang chờ các quản trị viên khác đồng ý.",
                  executed: "Đã thực hiện: " + (ACTION_LABEL[r.body.action] || "") + " " + (r.body.target_user || "") + ".",
                  rejected: "Đã từ chối và hủy yêu cầu." };
      govNotify("", msg[r.body.status] || "Đã lưu.");
      return loadGov();
    }).catch(function () { govNotify("Mất kết nối tới máy chủ."); });
  }

  function propose(action, u) {
    if (!window.confirm(ACTION_LABEL[action] + ": " + u.email + "?\nCác quản trị viên khác cần đồng ý thì mới có hiệu lực.")) return null;
    return govAction("/api/governance/requests", { action: action, username: u.username });
  }

  function simpleUserAction(action, u) {
    if (action === "revoke" && !window.confirm("Thu hồi quyền xem của " + u.email + "?")) return null;
    govNotify();
    return post("/api/users/" + action, { username: u.username }).then(function (r) {
      if (r.status !== 200) govNotify(govMessage(r));
      return loadGov();
    });
  }

  function userRow(u, buttons) {
    var tr = document.createElement("tr");
    tr.appendChild(cell(u.email));
    tr.appendChild(cell(u.created ? localTime(u.created) : "", "muted"));
    var td = document.createElement("td");
    if (u.email !== $("username").textContent) buttons.forEach(function (b) { td.appendChild(govButton(b[0], b[1])); });
    tr.appendChild(td);
    return tr;
  }

  function fillUsers(tbodyId, emptyId, rows, buttonsFor) {
    var tb = $(tbodyId);
    tb.replaceChildren();
    rows.forEach(function (u) { tb.appendChild(userRow(u, buttonsFor(u))); });
    $(emptyId).hidden = rows.length > 0;
  }

  function loadUsers() {
    return api("/api/users").then(function (r) {
      if (r.status !== 200) { govNotify("Không tải được danh sách người dùng."); return; }
      fillUsers("users-pending", "users-pending-empty", r.body.pending, function (u) {
        return [["Duyệt", function () { return simpleUserAction("approve", u); }]];
      });
      fillUsers("users-viewers", "users-viewers-empty", r.body.viewers, function (u) {
        return [["Thu hồi", function () { return simpleUserAction("revoke", u); }],
                ["Đề xuất lên Quản trị", function () { return propose("promote", u); }],
                ["Vô hiệu hóa", function () { return propose("disable", u); }]];
      });
      fillUsers("users-admins", "users-admins-empty", r.body.admins, function (u) {
        return [["Đề xuất hạ quyền", function () { return propose("demote", u); }],
                ["Vô hiệu hóa", function () { return propose("disable", u); }],
                ["Đặt lại PIN", function () {
                  if (!window.confirm("Xóa PIN của " + u.email + "? Người đó sẽ tự đặt PIN mới ở lần vào sau.")) return null;
                  return govAction("/api/governance/pin/reset", { username: u.username });
                }]];
      });
    });
  }

  $("gov-setpin-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var form = ev.target;
    if (form.pin.value !== form.pin2.value) { govNotify("Hai lần nhập PIN chưa giống nhau."); return; }
    govNotify();
    post("/api/governance/pin", { pin: form.pin.value }).then(function (r) {
      form.reset();
      if (r.status !== 200) { govNotify(govMessage(r)); return; }
      govNotify("", "Đã đặt PIN. Mục Phân quyền mở trong 10 phút.");
      loadGov();
    });
  });

  $("gov-unlock-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var form = ev.target;
    govNotify();
    post("/api/governance/unlock", { pin: form.pin.value }).then(function (r) {
      form.reset();
      if (r.status !== 200) { govNotify(govMessage(r)); return; }
      loadGov();
    });
  });

  // ------------------------------------------------------------- thong ke
  function selectRange(rng) {
    statsRange = rng;
    Array.prototype.forEach.call($("stats-range").querySelectorAll("button"), function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-range") === rng));
    });
    clearInterval(statsTimer);
    loadStats();
    if (rng === "24h") statsTimer = setInterval(loadStats, STATS_MS);
  }

  $("stats-range").addEventListener("click", function (ev) {
    var b = ev.target.closest("button[data-range]");
    if (b) selectRange(b.getAttribute("data-range"));
  });

  function loadStats() {
    $("stats-note").textContent = "Đang tải…";
    var tz = -new Date().getTimezoneOffset();   // phut lech UTC cua nguoi xem: ngay bat dau luc 00:00 gio dia phuong
    api("/api/stats?range=" + encodeURIComponent(statsRange) + "&tz=" + tz).then(function (r) {
      if (r.status === 401) { showLogin(); return; }
      if (r.status !== 200) { $("stats-note").textContent = "Không tải được thống kê."; return; }
      try {
        IncidentCharts.render(r.body, { hourly: $("stats-hourly"), matrix: $("stats-matrix"),
                                        table: $("stats-table"), note: $("stats-note"), legend: $("stats-legend"),
                                        tip: $("viz-tip") });
      } catch (e) {   // du lieu khong dung dinh dang: bao dung loi, khong nham voi mat mang
        $("stats-note").textContent = "Không vẽ được thống kê (dữ liệu không hợp lệ).";
      }
    }).catch(function () { $("stats-note").textContent = "Mất kết nối tới máy chủ."; });
  }

  // ------------------------------------------------------------- tro ly AI
  // Cau tra loi cua AI la du lieu khong tin cay (co the bi log tan cong dan dat): chi hien bang textContent.
  function chatLine(who, text) {
    var p = document.createElement("p");
    p.className = "msg " + who;
    p.textContent = text;
    $("chat-log").appendChild(p);
    $("chat-log").scrollTop = $("chat-log").scrollHeight;
    return p;
  }

  function chatAbout(incident) {
    chatIncident = incident;
    $("chat-context").textContent = incident ? (incident.rule + " lúc " + localTime(incident.time)) : "các sự cố gần đây";
    $("chat-clear").hidden = !incident;
    if (incident && !$("chat-input").value) $("chat-input").value = "Sự cố này là gì, có nguy hiểm không, cần khắc phục thế nào?";
    $("chat-card").scrollIntoView({ behavior: "smooth" });
    $("chat-input").focus();
  }

  $("chat-clear").addEventListener("click", function () { chatAbout(null); });

  $("chat-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var message = $("chat-input").value.trim();
    if (!message) return;
    var body = { message: message };
    if (chatIncident) body.incident_id = chatIncident.id;
    $("chat-error").textContent = "";
    $("chat-send").disabled = true;
    chatLine("user", message);
    var waiting = chatLine("ai muted", "Đang phân tích…");
    post("/api/chat", body).then(function (r) {
      if (r.status === 200) { waiting.className = "msg ai"; waiting.textContent = r.body.answer; $("chat-input").value = ""; return; }
      waiting.remove();
      if (r.status === 401) { showLogin(); return; }
      $("chat-error").textContent = (r.body && r.body.error) ||
        (r.status === 429 ? "Bạn hỏi quá nhanh, đợi một chút." : "Trợ lý AI tạm thời không trả lời được.");
    }).catch(function () {
      waiting.remove();
      $("chat-error").textContent = "Mất kết nối tới máy chủ.";
    }).then(function () { $("chat-send").disabled = false; });
  });

  $("logout").addEventListener("click", function () { api("/api/logout", { method: "POST" }).then(showLogin); });
  // O PIN chi nhan chu so: bo moi ky tu khac ngay luc go / dan (go nham chu khi mo khoa bi tinh la 1 lan sai).
  // \D khong co co u -> chi giu so ASCII 0-9 (so toan goc / so A Rap cung bi bo, khop kiem tra o may chu).
  Array.prototype.forEach.call(document.querySelectorAll("input[data-digits]"), function (box) {
    box.addEventListener("input", function () {
      var clean = box.value.replace(/\D/g, "").slice(0, 6);
      if (clean !== box.value) box.value = clean;
    });
  });
  $("filter").addEventListener("change", function () { if (lastData) render(lastData); });
  $("incidents-more").addEventListener("click", function () {
    incidentsExpanded = !incidentsExpanded;
    if (lastData) render(lastData);
    if (!incidentsExpanded) $("incidents").closest(".card").scrollIntoView({ behavior: "smooth", block: "start" });
  });
  start();
})();
