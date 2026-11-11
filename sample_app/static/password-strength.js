// Cham diem do manh mat khau. Quy tac PHAI giong het password_strength.py (may chu chan lai khi dang ky).
(function (root) {
  "use strict";
  var LABELS = ["Rất yếu", "Yếu", "Trung bình", "Mạnh", "Rất mạnh"];
  var WARNINGS = [
    "Rất dễ bị đoán ra — không được chấp nhận.",
    "Mật khẩu yếu — không được chấp nhận.",
    "Chấp nhận được, nhưng nên dài hơn và đa dạng ký tự hơn.",
    "Mật khẩu tốt.",
    "Mật khẩu rất tốt."
  ];
  var MIN_LEVEL = 2, MIN_LENGTH = 8;
  var COMMON = ("password passw0rd qwerty qwertyuiop azerty letmein welcome admin administrator iloveyou monkey " +
    "dragon master football baseball sunshine princess shadow superman batman trustno login abc abcdef abcdefgh " +
    "asdfgh asdfghjkl zxcvbn zxcvbnm secret changeme default guest root test testing hello freedom whatever " +
    "matkhau vietnam hanoi saigon anhyeuem logsentinel aws amazon cloud").split(" ");
  var LEET = { "@": "a", "0": "o", "3": "e", "$": "s", "5": "s", "7": "t" };

  function isCommon(pw) {
    var lowered = pw.toLowerCase();
    var leet = lowered.replace(/[@03$57]/g, function (c) { return LEET[c]; });
    return [lowered, leet].some(function (candidate) {
      var core = candidate.replace(/[^a-z]+$/, "");
      return COMMON.indexOf(core) >= 0 || COMMON.indexOf(candidate) >= 0;
    });
  }

  function hasRun(pw, size) {
    var s = pw.toLowerCase();
    for (var i = 0; i + size <= s.length; i++) {
      var d = s.charCodeAt(i + 1) - s.charCodeAt(i), ok = d === 0 || d === 1 || d === -1;
      for (var j = 1; ok && j < size - 1; j++) ok = s.charCodeAt(i + j + 1) - s.charCodeAt(i + j) === d;
      if (ok) return true;
    }
    return false;
  }

  function evaluate(password, email) {
    var pw = password || "", n = Array.from(pw).length, tips = [];
    var lower = /[a-z]/.test(pw), upper = /[A-Z]/.test(pw), digit = /[0-9]/.test(pw);
    var symbol = Array.from(pw).some(function (c) { return !/[A-Za-z0-9]/.test(c); });
    var local = (email || "").split("@")[0].toLowerCase();
    var level;

    if (n < MIN_LENGTH || isCommon(pw)) {
      level = 0;
    } else {
      var lengthPts = n < 10 ? 1 : n < 12 ? 2 : n < 16 ? 3 : n < 20 ? 4 : 5;
      var classes = [lower, upper, digit, symbol].filter(Boolean).length;
      var total = lengthPts + Math.max(classes - 1, 0);
      if (hasRun(pw, 4)) total -= 1;
      if (local.length >= 3 && pw.toLowerCase().indexOf(local) >= 0) total -= 2;
      level = total <= 2 ? 0 : Math.min(total - 2, 4);
    }

    if (n === 0) return { level: 0, tips: [] };
    if (n < MIN_LENGTH) tips.push("Dùng ít nhất " + MIN_LENGTH + " ký tự.");
    else if (isCommon(pw)) tips.push("Mật khẩu này nằm trong danh sách mật khẩu phổ biến.");
    if (n >= MIN_LENGTH && n < 12) tips.push("Dài từ 12 ký tự trở lên sẽ an toàn hơn nhiều.");
    if (!upper) tips.push("Thêm chữ hoa.");
    if (!lower) tips.push("Thêm chữ thường.");
    if (!digit) tips.push("Thêm chữ số.");
    if (!symbol) tips.push("Thêm ký tự đặc biệt (ví dụ ! @ # -).");
    if (n >= MIN_LENGTH && hasRun(pw, 4)) tips.push("Tránh chuỗi lặp hoặc liên tiếp như aaaa, abcd, 1234.");
    if (local.length >= 3 && pw.toLowerCase().indexOf(local) >= 0) tips.push("Không dùng phần tên email trong mật khẩu.");
    return { level: level, tips: tips };
  }

  var api = { evaluate: evaluate, LABELS: LABELS, WARNINGS: WARNINGS, MIN_LEVEL: MIN_LEVEL };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PasswordStrength = api;
})(typeof window !== "undefined" ? window : this);
