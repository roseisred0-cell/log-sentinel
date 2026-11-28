// LogSentinel SOC Console. Moi du lieu tu may chu deu chen bang textContent (khong innerHTML):
// payload tan cong (vd <script>) chi hien thanh chu, khong bao gio chay.
(function () {
  "use strict";
  var REFRESH_MS = 15000;
  var ROLE_LABEL = { admin: "Admin", viewer: "Viewer", pending: "Pending" };
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
    return isNaN(d) ? iso : d.toLocaleString("en-GB");
  }

  function remaining(expiresAt, now) {
    var s = Math.max(0, expiresAt - now), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return h + "h " + m + "m";
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
    summary.textContent = "Show raw data";
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
        ask.type = "button"; ask.className = "small ask-ai"; ask.textContent = "Ask AI";
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
    more.textContent = incidentsExpanded ? "Show less (latest " + INCIDENT_PREVIEW + " incidents only)"
                                         : "Show " + hiddenCount + " more incidents";

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
        btn.type = "button"; btn.className = "small"; btn.textContent = "Unblock";
        btn.addEventListener("click", function () { unblock(b.ip, btn); });
        td.appendChild(btn);
      }
      tr.appendChild(td);
      bb.appendChild(tr);
    });
    $("blocks-empty").hidden = data.blocks.length > 0;
    $("refreshed").textContent = "Updated at " + new Date().toLocaleTimeString("en-GB") + " · refreshes every 15 seconds";
  }

  function load() {
    if (!canViewData()) return Promise.resolve();
    return api("/api/overview").then(function (r) {
      if (r.status === 401) return showLogin();
      if (r.status !== 200) { $("app-error").textContent = r.body.error || "Could not load data."; return; }
      $("app-error").textContent = "";
      render(r.body);
    }).catch(function () { $("app-error").textContent = "Lost connection to the server."; });
  }

  function unblock(ip, btn) {
    if (!window.confirm("Unblock IP " + ip + "?")) return;
    btn.disabled = true;
    post("/api/unblock", { ip: ip }).then(function (r) {
      if (r.status !== 200) $("app-error").textContent = r.body.error || "Unblock failed.";
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
    clearInterval(healthTimer);
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
    clearInterval(healthTimer);
    var showHealth = role === "admin" && !mfaSetupRequired;   // thong tin van hanh: chi Admin
    $("health-card").hidden = !showHealth;
    if (showHealth) { loadHealth(); healthTimer = setInterval(loadHealth, HEALTH_MS); }
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
      $("login-hint").textContent = "Use the admin account and the 6-digit code from your Authenticator app.";
    } else {
      user.placeholder = "email or admin";
      $("login-hint").textContent = "Sign in with your registered email. The internal “admin” account also needs an OTP code.";
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
      var msg = { 401: "Wrong username or password.", 403: "Invalid OTP code, or your IP has been blocked.",
                  429: "Too many attempts. Try again in a few seconds." };
      if (r.body.error === "not_confirmed") {
        pendingEmail = name.toLowerCase();
        $("confirm-email").textContent = pendingEmail;
        $("confirm-error").textContent = "Your email is not confirmed yet. Enter the code sent to your inbox.";
        return showPanel("confirm");
      }
      errBox.textContent = msg[r.status] || "Sign-in failed (" + r.status + ").";
    }).catch(function () { errBox.textContent = "Lost connection to the server."; });
  });

  $("mfa-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    $("mfa-error").textContent = "";
    post("/auth/mfa", { code: ev.target.code.value.trim() }).then(function (r) {
      if (r.status === 200) { ev.target.reset(); return start(); }
      if (r.status === 401) {
        showPanel("login");
        $("login-error").textContent = "Your verification session expired. Please sign in again.";
        return;
      }
      $("mfa-error").textContent = r.status === 403 ? "Wrong OTP code, or your IP has been blocked."
        : "Verification failed (" + r.status + ").";
    }).catch(function () { $("mfa-error").textContent = "Lost connection to the server."; });
  });

  // ---------------------------------------------------------------- dang ky
  // Thanh do manh dung chung cho Dang ky va Dat lai mat khau. Tra ve ham cap nhat (va tra ve muc hien tai).
  function strengthWidget(ids, getEmail, extraValid) {
    function update() {
      var pass = $(ids.pass).value, pass2 = $(ids.pass2).value;
      var result = PasswordStrength.evaluate(pass, getEmail());
      $(ids.meter).setAttribute("data-level", pass ? String(result.level) : "-1");
      $(ids.level).textContent = pass ? "Strength: " + PasswordStrength.LABELS[result.level] : "No password entered";
      $(ids.warning).textContent = pass ? PasswordStrength.WARNINGS[result.level] : "";
      var tips = $(ids.tips);
      tips.replaceChildren();
      result.tips.forEach(function (t) { var li = document.createElement("li"); li.textContent = t; tips.appendChild(li); });
      var match = pass !== "" && pass === pass2;
      $(ids.submit).disabled = !(result.level >= cfg.min_password_level && match && extraValid());
      $(ids.error).textContent = pass && pass2 && !match ? "The two passwords do not match." : "";
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
      var msg = { weak_password: "The password is not strong enough.", invalid_email: "Invalid email address.",
                  rate_limited: "Too many attempts. Try again in a few minutes." };
      errBox.textContent = msg[r.body.error] || "Sign-up failed (" + r.status + ").";
      updateStrength();
    }).catch(function () { errBox.textContent = "Lost connection to the server."; updateStrength(); });
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
        $("login-hint").textContent = "Email confirmed. Sign in now; an administrator will approve your account.";
        return;
      }
      var msg = { 429: "Too many attempts. Please wait a few minutes." };
      $("confirm-error").textContent = msg[r.status] || "The code is wrong or has expired.";
    }).catch(function () { $("confirm-error").textContent = "Lost connection to the server."; });
  });

  $("resend").addEventListener("click", function () {
    $("confirm-error").textContent = ""; $("confirm-ok").textContent = "";
    post("/auth/resend", { email: pendingEmail }).then(function (r) {
      if (r.status === 200) $("confirm-ok").textContent = "If the email is valid, a new code has been sent.";
      else $("confirm-error").textContent = r.status === 429 ? "Too many requests. Please wait a few minutes." : "Could not resend the code.";
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
        $("forgot-error").textContent = r.status === 429 ? "Too many requests. Please wait a few minutes." : "Could not send the code (" + r.status + ").";
        return;
      }
      pendingEmail = email;
      $("reset-info").textContent = "If " + email + " is registered, a 6-digit code has been sent to the inbox. Enter the code and a new password below.";
      $("reset-form").reset(); $("reset-error").textContent = "";
      updateResetStrength();
      showPanel("reset");
    }).catch(function () { $("forgot-error").textContent = "Lost connection to the server."; });
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
        $("login-hint").textContent = "Password changed. Sign in with your new password.";
        return;
      }
      var msg = { invalid_code: "The code is wrong or has expired.", weak_password: "The password is not strong enough.",
                  rate_limited: "Too many attempts. Please wait a few minutes." };
      $("reset-error").textContent = msg[r.body.error] || "Password reset failed (" + r.status + ").";
      updateResetStrength();
    }).catch(function () { $("reset-error").textContent = "Lost connection to the server."; updateResetStrength(); });
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
      if (r.status !== 200) { $("account-error").textContent = "Could not load account details."; return; }
      var a = r.body, toggle = $("mfa-toggle");
      $("acc-email").textContent = a.email;
      $("acc-role").textContent = ROLE_LABEL[a.role] || a.role;
      $("account-error").textContent = "";
      if (a.auth !== "cognito") {
        $("mfa-state").textContent = "on (required)";
        $("mfa-note").textContent = "The internal admin account always uses 2FA; its key is configured on the server, so it cannot be turned off here.";
        toggle.hidden = true;
        return;
      }
      var adminLocked = a.role === "admin" && a.mfa_enabled;   // quan tri vien khong duoc tat 2FA
      toggle.hidden = adminLocked;
      toggle.setAttribute("data-enabled", a.mfa_enabled ? "1" : "0");
      toggle.textContent = a.mfa_enabled ? "Turn off 2FA" : "Turn on 2FA";
      $("mfa-state").textContent = a.mfa_enabled ? "ON" : "OFF";
      $("mfa-note").textContent = adminLocked
        ? "Administrators must use 2FA, so there is no button to turn it off."
        : a.mfa_enabled
          ? "Each sign-in also needs the 6-digit code from your Authenticator app."
          : a.role === "admin"
            ? "Administrators must turn on 2FA before they can see data."
            : "Turning on 2FA is recommended: with a password alone, the account is easy to take over if the password leaks.";
    }).catch(function () { $("account-error").textContent = "Lost connection to the server."; });
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
      if (r.status !== 200) { $("account-error").textContent = "Could not start the 2FA setup."; return; }
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
        var msg = { reauth_failed: "Wrong password or OTP code.", rate_limited: "Too many attempts. Please wait a few minutes." };
        $("account-error").textContent = msg[r.body.error] || "Could not turn off 2FA (" + r.status + ").";
        return;
      }
      form.reset();
      $("mfa-disable").hidden = true;
      loadAccount();
    }).catch(function () { $("account-error").textContent = "Lost connection to the server."; });
  });

  $("mfa-enable-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    $("account-error").textContent = "";
    post("/api/mfa/enable", { code: ev.target.code.value.trim() }).then(function (r) {
      if (r.status === 401) return showLogin();
      if (r.status !== 200) { $("account-error").textContent = "Wrong OTP code. Check the time on your phone and try again."; return; }
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
    weak_pin: "The PIN must be exactly 6 digits and not easy to guess (e.g. 123456, 000000, 121212).",
    pin_exists: "You already have a PIN.", wrong_pin: "Wrong PIN.",
    pin_locked: "The PIN is locked for 15 minutes after too many wrong attempts.",
    pin_required: "The Roles section locked itself. Enter your PIN again.",
    busy: "Another role change is running. Try again in a few seconds.",
    local_admin_restricted: "There are already 2 administrators: the internal admin account can now only view data and unblock IPs.",
    not_admin: "Only administrators can do this.",
    unauthenticated: "Your session is no longer valid for role management. Please sign in again.",
    upstream: "The account service failed, so the change was not applied. The request is kept; click Approve again to retry.",
    invalid_target: "This action cannot be applied to that account.",
    self_action: "You cannot apply this action to your own account.",
    min_admins: "There must always be at least 2 administrators.",
    not_enough_admins: "Not enough administrators to approve this action.",
    local_admin_no_vote: "There are already 2 administrators: the internal admin account can no longer vote.",
    not_a_voter: "You cannot vote on this request.",
    already_voted: "You have already approved this request.", request_closed: "This request is closed.",
    request_expired: "This request has expired (24 hours).", not_found: "Not found.",
    execution_failed: "Could not apply the change: the user list has changed.",
    invalid_request: "Invalid request."
  };
  var ACTION_LABEL = { promote: "Promote to Admin", demote: "Demote to Viewer", disable: "Disable" };
  var govClock = null, govUntil = 0, clockOffset = 0;

  function govMessage(r) {
    return GOV_ERRORS[r.body.error] || "Action failed (" + (r.body.error || r.status) + ").";
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
    $("gov-timer").textContent = "Locks in " + Math.floor(left / 60) + ":" + ("0" + (left % 60)).slice(-2);
  }

  function loadGov() {
    return api("/api/governance").then(function (r) {
      if (r.status === 401) return showLogin();
      if (r.status === 403 && r.body.error === "mfa_setup_required") return start();
      if (r.status !== 200) { govNotify("Could not load the Roles section."); return; }
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
    }).catch(function () { govNotify("Lost connection to the server."); });
  }

  // Muc dang khoa: van bao co bao nhieu tai khoan cho duyet (chi dem, khong lo email) de admin biet vi sao can PIN.
  function pendingHint(hasPin) {
    var hint = $("gov-pending-hint");
    api("/api/users").then(function (r) {
      var n = r.status === 200 && r.body.pending ? r.body.pending.length : 0;
      hint.hidden = n === 0;
      hint.textContent = n + " account(s) waiting for approval. " +
        (hasPin ? "Enter your PIN below to open this section and approve them." : "Set a PIN below to open this section and approve them.");
    }).catch(function () { hint.hidden = true; });
  }

  function renderGovSummary(g) {
    var warn = $("gov-min-warning"), boot = $("gov-bootstrap");
    warn.hidden = g.admin_count >= 2;
    warn.textContent = "There are " + g.admin_count + " administrator(s); at least 2 are required.";
    boot.hidden = !g.bootstrap;
    boot.textContent = authKind === "local"
      ? "Bootstrap mode: you (internal admin) may promote a Viewer to Admin by yourself until there are 2 administrators."
      : "Bootstrap mode: the internal admin may cast the second vote until there are 2 administrators.";
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
      td.appendChild(govButton("Approve", function () {
        return govAction("/api/governance/requests/" + encodeURIComponent(q.id) + "/vote", { decision: "approve" });
      }));
      td.appendChild(govButton("Reject", function () {
        if (!window.confirm("Rejecting cancels the request immediately. Continue?")) return null;
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
    if (!/^[0-9]{6}$/.test(pin)) { govNotify("Enter the confirmation PIN (6 digits) first."); $("gov-pin").focus(); return null; }
    govNotify();
    return post(path, Object.assign({ pin: pin }, body)).then(function (r) {
      $("gov-pin").value = "";
      if (r.status === 401) return showLogin();
      if (r.status !== 200) { govNotify(govMessage(r)); return loadGov(); }
      var msg = { pending: "Vote recorded. Waiting for other administrators to approve.",
                  executed: "Done: " + (ACTION_LABEL[r.body.action] || "") + " " + (r.body.target_user || "") + ".",
                  rejected: "Rejected and cancelled the request." };
      govNotify("", msg[r.body.status] || "Saved.");
      return loadGov();
    }).catch(function () { govNotify("Lost connection to the server."); });
  }

  function propose(action, u) {
    if (!window.confirm(ACTION_LABEL[action] + ": " + u.email + "?\nOther administrators must approve before it takes effect.")) return null;
    return govAction("/api/governance/requests", { action: action, username: u.username });
  }

  function simpleUserAction(action, u) {
    if (action === "revoke" && !window.confirm("Revoke viewer access for " + u.email + "?")) return null;
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
      if (r.status !== 200) { govNotify("Could not load the user list."); return; }
      fillUsers("users-pending", "users-pending-empty", r.body.pending, function (u) {
        return [["Approve", function () { return simpleUserAction("approve", u); }]];
      });
      fillUsers("users-viewers", "users-viewers-empty", r.body.viewers, function (u) {
        return [["Revoke", function () { return simpleUserAction("revoke", u); }],
                ["Propose Admin", function () { return propose("promote", u); }],
                ["Disable", function () { return propose("disable", u); }]];
      });
      fillUsers("users-admins", "users-admins-empty", r.body.admins, function (u) {
        return [["Propose demotion", function () { return propose("demote", u); }],
                ["Disable", function () { return propose("disable", u); }],
                ["Reset PIN", function () {
                  if (!window.confirm("Delete the PIN of " + u.email + "? They will set a new PIN next time.")) return null;
                  return govAction("/api/governance/pin/reset", { username: u.username });
                }]];
      });
    });
  }

  $("gov-setpin-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var form = ev.target;
    if (form.pin.value !== form.pin2.value) { govNotify("The two PINs do not match."); return; }
    govNotify();
    post("/api/governance/pin", { pin: form.pin.value }).then(function (r) {
      form.reset();
      if (r.status !== 200) { govNotify(govMessage(r)); return; }
      govNotify("", "PIN set. The Roles section is open for 10 minutes.");
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
    $("stats-note").textContent = "Loading…";
    var tz = -new Date().getTimezoneOffset();   // phut lech UTC cua nguoi xem: ngay bat dau luc 00:00 gio dia phuong
    api("/api/stats?range=" + encodeURIComponent(statsRange) + "&tz=" + tz).then(function (r) {
      if (r.status === 401) { showLogin(); return; }
      if (r.status !== 200) { $("stats-note").textContent = "Could not load statistics."; return; }
      try {
        IncidentCharts.render(r.body, { hourly: $("stats-hourly"), matrix: $("stats-matrix"),
                                        table: $("stats-table"), note: $("stats-note"), legend: $("stats-legend"),
                                        tip: $("viz-tip") });
      } catch (e) {   // du lieu khong dung dinh dang: bao dung loi, khong nham voi mat mang
        $("stats-note").textContent = "Could not draw statistics (invalid data).";
      }
    }).catch(function () { $("stats-note").textContent = "Lost connection to the server."; });
  }

  // ------------------------------------------------------------- system health (admin)
  // Alarm + Lambda metric doc tu CloudWatch qua may chu (role EC2 chi doc); trinh duyet khong goi AWS truc tiep.
  var HEALTH_MS = 300000, healthTimer = null, healthRange = "24h";
  var STATE_LABEL = { OK: "OK", ALARM: "ALARM", INSUFFICIENT_DATA: "No data" };

  function sparkline(inv, err) {
    var NS = "http://www.w3.org/2000/svg", W = 160, H = 28, n = inv.length || 1;
    var max = Math.max.apply(null, inv.concat([1])), slot = W / n, bw = Math.max(1, slot - 1);
    var svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("width", W); svg.setAttribute("height", H);
    svg.setAttribute("class", "spark");
    inv.forEach(function (v, i) {
      var h = v ? Math.max(1.5, (v / max) * (H - 2)) : 0;
      var r = document.createElementNS(NS, "rect");
      r.setAttribute("x", i * slot); r.setAttribute("y", H - h); r.setAttribute("width", bw); r.setAttribute("height", h);
      r.setAttribute("class", err[i] ? "spark-err" : "spark-inv");
      var t = document.createElementNS(NS, "title");
      t.textContent = v + " invocation(s), " + (err[i] || 0) + " error(s)";
      r.appendChild(t);
      svg.appendChild(r);
    });
    return svg;
  }

  function renderHealth(h) {
    var ab = $("health-alarms");
    ab.replaceChildren();
    h.alarms.forEach(function (a) {
      var tr = document.createElement("tr"), td = document.createElement("td"), badge = document.createElement("span");
      badge.className = "state " + a.state;
      badge.textContent = STATE_LABEL[a.state] || a.state;
      td.appendChild(badge);
      tr.appendChild(td);
      tr.appendChild(cell(a.name));
      tr.appendChild(cell(a.description, "details"));
      tr.appendChild(cell(a.updated ? localTime(a.updated * 1000) : ""));
      ab.appendChild(tr);
    });
    var fb = $("health-functions");
    fb.replaceChildren();
    h.functions.forEach(function (f) {
      var tr = document.createElement("tr"), td = document.createElement("td");
      tr.appendChild(cell(f.label, "mono"));
      tr.appendChild(cell(f.total_invocations));
      tr.appendChild(cell(f.total_errors, f.total_errors ? "err-count" : ""));
      tr.appendChild(cell(f.total_invocations ? (100 * f.total_errors / f.total_invocations).toFixed(1) + "%" : "0%"));
      td.appendChild(sparkline(f.invocations, f.errors));
      tr.appendChild(td);
      fb.appendChild(tr);
    });
    var bad = h.alarms.filter(function (a) { return a.state === "ALARM"; }).length;
    $("health-note").textContent = (bad ? bad + " alarm(s) firing" : "All alarms OK or without data") +
      " · checked at " + new Date(h.checked_at * 1000).toLocaleTimeString("en-GB") + " · refreshes every 5 minutes";
    var link = $("health-dashboard");
    link.hidden = !h.dashboard_url;
    if (h.dashboard_url) link.href = h.dashboard_url;
  }

  function loadHealth() {
    var tz = -new Date().getTimezoneOffset();
    api("/api/health?range=" + encodeURIComponent(healthRange) + "&tz=" + tz).then(function (r) {
      if (r.status === 401) { showLogin(); return; }
      if (r.status === 404) { $("health-card").hidden = true; return; }
      if (r.status !== 200) { $("health-note").textContent = (r.body && r.body.error) || "Could not read CloudWatch."; return; }
      try { renderHealth(r.body); } catch (e) { $("health-note").textContent = "Could not show health data (invalid data)."; }
    }).catch(function () { $("health-note").textContent = "Lost connection to the server."; });
  }

  function selectHealthRange(rng) {
    healthRange = rng;
    Array.prototype.forEach.call($("health-range").querySelectorAll("button"), function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-range") === rng));
    });
    loadHealth();
  }

  $("health-range").addEventListener("click", function (ev) {
    var b = ev.target.closest("button[data-range]");
    if (b) selectHealthRange(b.getAttribute("data-range"));
  });

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
    $("chat-context").textContent = incident ? (incident.rule + " at " + localTime(incident.time)) : "recent incidents";
    $("chat-clear").hidden = !incident;
    if (incident && !$("chat-input").value) $("chat-input").value = "What is this incident, is it dangerous, and how do I fix it?";
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
    var waiting = chatLine("ai muted", "Analyzing…");
    post("/api/chat", body).then(function (r) {
      if (r.status === 200) { waiting.className = "msg ai"; waiting.textContent = r.body.answer; $("chat-input").value = ""; return; }
      waiting.remove();
      if (r.status === 401) { showLogin(); return; }
      $("chat-error").textContent = (r.body && r.body.error) ||
        (r.status === 429 ? "You are asking too fast. Please wait a moment." : "The AI assistant is temporarily unavailable.");
    }).catch(function () {
      waiting.remove();
      $("chat-error").textContent = "Lost connection to the server.";
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
