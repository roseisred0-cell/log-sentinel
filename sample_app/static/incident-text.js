// Readable English sentences for the Subject / Details columns of the incident table.
//   IncidentText.describe({rule, ip, actor, details}) -> {subject, sentence}
// Pure function, no DOM: console.js inserts the result with textContent (attacker input only ever shows as text).
// Every rule the Detector can emit MUST have an entry in RULES (tests/unit/test_incident_text.py checks this).
// Missing fields (old records, odd data): the sentence still reads well and never shows "undefined".
(function (root) {
  "use strict";
  var BLOCKED = "The IP was blocked for 24 hours.";
  var PAYLOAD_MAX = 80;
  var FALLBACK = "No description for this rule yet. Click “Show raw data” for details.";

  // ------------------------------------------------------------- helpers
  function text(x) { return x == null || typeof x === "object" ? "" : String(x); }
  function shorten(x, max) { var s = text(x); return s.length > max ? s.slice(0, max) + "…" : s; }
  function plural(n, unit) { return n + " " + unit + (Number(n) === 1 ? "" : "s"); }
  function duration(seconds) {
    var s = Number(seconds) || 0;
    if (s >= 3600 && s % 3600 === 0) return plural(s / 3600, "hour");
    if (s >= 120 && s % 60 === 0) return plural(s / 60, "minute");
    return plural(s, "second");
  }
  function times(n) { return text(n) ? plural(n, "time") : "many times"; }
  function within(seconds) { return Number(seconds) > 0 ? " within " + duration(seconds) : ""; }
  function fromIp(ip) { return text(ip) ? " from IP " + ip : ""; }
  function who(name) { return text(name) || "Someone"; }
  function joinParts(parts) { return parts.filter(Boolean).join(" · "); }
  function ipAndAccount(i) {
    return joinParts([text(i.ip) && "IP " + i.ip, text(i.actor) && "account " + i.actor]);
  }
  function ipOnly(i) { return text(i.ip) ? "IP " + i.ip : ""; }
  function awsUser(name) { return text(name) ? "AWS user " + name : ""; }

  var RULES = {};

  // --------------------------------------------------------------- web app
  RULES.BRUTE_FORCE_DETECTED = function (i, d) {
    return { subject: ipAndAccount(i),
             sentence: "Wrong password " + times(d.attempt_count) + within(d.window_seconds) + ". " + BLOCKED };
  };
  RULES.SLOW_BRUTE_FORCE = function (i, d) {
    return { subject: ipAndAccount(i),
             sentence: "Wrong password " + times(d.attempt_count) + within(d.window_seconds) +
               ", spread out to avoid the fast brute-force rule. " + BLOCKED };
  };
  RULES.ACCOUNT_UNDER_ATTACK = function (i, d) {
    var account = text(d.username) || text(i.actor);
    var last = text(d.last_ip) ? " (latest " + d.last_ip + ")" : "";
    return { subject: account ? "account " + account : "",
             sentence: "Wrong password " + times(d.attempt_count) + within(d.window_seconds) +
               " from many different IPs" + last + ". No IP was blocked automatically." };
  };
  RULES.LOGIN_FAILURE_SPIKE = function (i, d) {
    var count = text(d.attempt_count) ? plural(d.attempt_count, "failed sign-in") : "A very large number of failed sign-ins";
    return { subject: "Whole system",
             sentence: count + within(d.window_seconds) +
               ", from many IPs against many accounts. Leaked passwords may be being tried in bulk." };
  };
  RULES.SCAN_DETECTED = function (i, d) {
    var last = text(d.path) ? " (latest: " + shorten(d.path, PAYLOAD_MAX) + ")" : "";
    var count = text(d.attempt_count) ? plural(d.attempt_count, "path") : "many paths";
    return { subject: ipOnly(i),
             sentence: "Requested " + count + " that do not exist" + within(d.window_seconds) + last + ". " + BLOCKED };
  };
  RULES.SQL_INJECTION = function (i, d) {
    var where = d.field === "username" || d.field === "email" ? "the sign-in form" : "the search box";
    var payload = text(d.payload) ? ": " + shorten(d.payload, PAYLOAD_MAX) : "";
    return { subject: ipOnly(i), sentence: "Malicious code injected into " + where + payload + ". " + BLOCKED };
  };
  RULES.MFA_BYPASS_ATTEMPT = function (i) {
    return { subject: ipAndAccount(i),
             sentence: "Correct password but wrong OTP code: the password may have leaked, change it now. " + BLOCKED };
  };

  // ------------------------------------------------- CloudTrail (AWS account)
  RULES.ROOT_ACCOUNT_LOGIN = function (i, d) {
    var how = d.outcome === "Failure" ? " (failed)" : d.mfa_used === "Yes" ? " with MFA" : " without MFA";
    return { subject: "AWS root account",
             sentence: "AWS Console sign-in with the root account" + fromIp(d.ip) + how +
               ". The root account should not be used day to day: check whether this was you." };
  };
  RULES.CONSOLE_LOGIN_NO_MFA = function (i, d) {
    return { subject: awsUser(d.user),
             sentence: "Successful AWS Console sign-in" + fromIp(d.ip) +
               " without MFA. Turn on MFA for this user." };
  };
  RULES.CONSOLE_BRUTE_FORCE = function (i, d) {
    return { subject: joinParts([text(d.ip) && "IP " + d.ip, awsUser(d.user)]),
             sentence: "Failed AWS Console sign-in " + times(d.attempt_count) + within(d.window_seconds) +
               ". The system cannot block IPs on the AWS Console." };
  };
  RULES.MFA_TAMPERING = function (i, d) {
    var what = d.action === "DeleteVirtualMFADevice" ? "Virtual MFA device deleted" : "MFA device deactivated";
    return { subject: awsUser(d.user), sentence: what + fromIp(d.ip) + "." };
  };
  RULES.CLOUDTRAIL_TAMPERING = function (i, d) {
    var what = d.action === "DeleteTrail" ? "Deleted" : "Stopped";
    return { subject: awsUser(d.user),
             sentence: what + " the audit log (CloudTrail)" + fromIp(d.ip) + ": a sign of covering tracks." };
  };
  RULES.KMS_KEY_TAMPERING = function (i, d) {
    var what = d.action === "DisableKey" ? " disabled" : " scheduled deletion of";
    return { subject: text(d.key_id) ? "KMS key " + d.key_id : "KMS key",
             sentence: who(d.user) + what + " the encryption key" + fromIp(d.ip) +
               ". Urgent: losing the key means losing all logs and the incident table." };
  };

  // ------------------------------------------------------ IAM privilege escalation
  function iamTarget(d) {
    if (text(d.target_role)) return "role " + d.target_role;
    if (text(d.target_group)) return "group " + d.target_group;
    if (text(d.target_user)) return "AWS user " + d.target_user;
    return "";
  }
  function policyName(d) {
    var arn = text(d.policy_arn);
    return arn ? arn.split("/").pop() : text(d.policy_name);
  }
  function iamSuffix(d) {
    var parts = [];
    if (policyName(d) === "AdministratorAccess") parts.push("This is the highest privilege.");
    if (text(d.error_code)) parts.push("Denied (" + d.error_code + ").");
    if (d.via_service === "cloudformation.amazonaws.com") parts.push("Done through CloudFormation (cdk deploy).");
    else if (text(d.via_service)) parts.push("Done through the " + d.via_service + " service.");
    return parts.length ? " " + parts.join(" ") : "";
  }
  function iamRule(subjectOf, sentenceOf) {
    return function (i, d) {
      return { subject: subjectOf(d), sentence: who(d.actor) + " " + sentenceOf(d) + "." + iamSuffix(d) };
    };
  }
  function to(d) { return iamTarget(d) || "an IAM identity"; }
  function policy(d) { return policyName(d) ? "policy " + policyName(d) : "a policy"; }

  RULES.IAM_ACCESS_KEY_CREATED = iamRule(
    function (d) { return iamTarget(d) || awsUser(d.actor); },
    function (d) { return "created an access key for " + (iamTarget(d) || "themselves"); });
  RULES.IAM_POLICY_ATTACHED = iamRule(iamTarget,
    function (d) { return "attached " + policy(d) + " to " + to(d); });
  RULES.IAM_INLINE_POLICY_PUT = iamRule(iamTarget,
    function (d) { return "put inline " + policy(d) + " on " + to(d); });
  RULES.IAM_POLICY_VERSION_CREATED = iamRule(
    function (d) { return policyName(d) ? "policy " + policyName(d) : ""; },
    function (d) { return "changed the content of " + policy(d) + " (new version)"; });
  RULES.IAM_TRUST_POLICY_CHANGED = iamRule(iamTarget,
    function (d) { return "changed the trust policy of " + to(d) + ": who can assume this role may have changed"; });
  RULES.IAM_LOGIN_PROFILE_CHANGED = iamRule(iamTarget,
    function (d) {
      return d.action === "CreateLoginProfile" ? "set an AWS Console password for " + to(d)
        : "changed the AWS Console password of " + to(d);
    });
  RULES.IAM_USER_ADDED_TO_GROUP = iamRule(
    function (d) { return text(d.target_group) ? "group " + d.target_group : ""; },
    function (d) {
      return "added " + (awsUser(d.target_user) || "an AWS user") + " to " +
        (text(d.target_group) ? "group " + d.target_group : "a group");
    });

  // ------------------------------------------- Roles section of the SOC Console
  var PROPOSAL = { promote: "promote {t} to Admin", demote: "demote {t} to Viewer", disable: "disable the account {t}" };
  function targetUser(d) { return text(d.target_user) || "an account"; }
  function proposal(d) { return (PROPOSAL[d.action] || "change the role of {t}").replace("{t}", targetUser(d)); }
  function person(principal) {
    var p = text(principal);
    if (p.indexOf("local:") === 0) return "internal admin";
    return p.indexOf(":") >= 0 ? p.slice(p.indexOf(":") + 1) : p;
  }
  function approvedBy(d) {
    var list = Array.isArray(d.approvers) ? d.approvers.map(person).filter(Boolean) : [];
    return list.length ? ", approved by " + list.join(", ") : "";
  }

  RULES.ROLE_REQUEST_CREATED = function (i, d) {
    return { subject: text(d.target_user),
             sentence: who(d.username) + " proposed to " + proposal(d) + ". Other administrators should vote in the Roles section." };
  };
  RULES.ADMIN_ROLE_CHANGED = function (i, d) {
    var change = d.action === "demote" ? " was demoted to Viewer" : " was promoted to Admin";
    var how = d.bootstrap === true ? " by the internal admin (bootstrap mode)" : approvedBy(d);
    return { subject: text(d.target_user), sentence: targetUser(d) + change + how + "." };
  };
  RULES.USER_DISABLED = function (i, d) {
    return { subject: text(d.target_user), sentence: "Account " + targetUser(d) + " was disabled" + approvedBy(d) + "." };
  };
  RULES.ROLE_CHANGE_FAILED = function (i, d) {
    return { subject: text(d.target_user),
             sentence: "Enough votes to " + proposal(d) + ", but Cognito failed so it was not applied. " +
               "Click Approve on that request again to retry." };
  };
  RULES.ADMIN_PIN_LOCKED = function (i, d) {
    return { subject: text(d.username) ? "account " + d.username : "",
             sentence: "Wrong Roles PIN entered 5 times; the PIN is locked for 15 minutes. " +
               "If this was not the account owner, the session may have been hijacked." };
  };
  RULES.ADMIN_PIN_RESET = function (i, d) {
    return { subject: text(d.target_user),
             sentence: who(d.username) + " reset the Roles PIN of " + targetUser(d) + "." };
  };

  // ------------------------------------------------------------- entry point
  function describe(incident) {
    var i = incident && typeof incident === "object" ? incident : {};
    var d = i.details && typeof i.details === "object" ? i.details : {};
    var rule = Object.prototype.hasOwnProperty.call(RULES, i.rule) ? RULES[i.rule] : null;
    if (rule) {
      try { return rule(i, d); } catch (e) { /* odd data: fall back to the default sentence */ }
    }
    return { subject: ipAndAccount(i), sentence: FALLBACK };
  }

  var api = { describe: describe, RULES: Object.keys(RULES) };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.IncidentText = api;
})(typeof window !== "undefined" ? window : this);
