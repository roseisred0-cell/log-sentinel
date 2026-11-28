// Cham diem do manh mat khau. Quy tac PHAI giong het password_strength.py (may chu chan lai khi dang ky).
(function (root) {
  "use strict";
  var LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
  var WARNINGS = [
    "Very easy to guess — not accepted.",
    "Weak password — not accepted.",
    "Acceptable, but longer and more varied is better.",
    "Good password.",
    "Very good password."
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
    if (n < MIN_LENGTH) tips.push("Use at least " + MIN_LENGTH + " characters.");
    else if (isCommon(pw)) tips.push("This password is on the list of common passwords.");
    if (n >= MIN_LENGTH && n < 12) tips.push("12 characters or more is much safer.");
    if (!upper) tips.push("Add an uppercase letter.");
    if (!lower) tips.push("Add a lowercase letter.");
    if (!digit) tips.push("Add a digit.");
    if (!symbol) tips.push("Add a symbol (e.g. ! @ # -).");
    if (n >= MIN_LENGTH && hasRun(pw, 4)) tips.push("Avoid repeated or sequential runs like aaaa, abcd, 1234.");
    if (local.length >= 3 && pw.toLowerCase().indexOf(local) >= 0) tips.push("Do not use the name part of your email in the password.");
    return { level: level, tips: tips };
  }

  var api = { evaluate: evaluate, LABELS: LABELS, WARNINGS: WARNINGS, MIN_LEVEL: MIN_LEVEL };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PasswordStrength = api;
})(typeof window !== "undefined" ? window : this);
