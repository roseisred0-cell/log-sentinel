# Knowledge for the LogSentinel AI assistant

## Overview
LogSentinel is a SIEM + SOAR system on AWS: the web app (EC2, Nginx + Flask) sits behind CloudFront + AWS WAF; web app logs and CloudTrail go to CloudWatch; the Lambda Detector applies 26 rules in real time, records incidents in DynamoDB, and alerts by email (SNS) and Telegram.
Three layers of IP blocking: the web app blocks locally (60 seconds) → a 24-hour block record in DynamoDB → the Lambda WafSync pushes blocked IPs to AWS WAF every minute to block them at the edge.
IPs in the admin list (admin_cidr) are never blocked.
Console roles: Admin (unblock IPs, Roles section, 2FA required), Viewer (read-only), Pending (waiting for approval).

## Daily use
- **Four tiles at the top:** recent incidents, CRITICAL count, HIGH count, number of blocked IPs.
- **Statistics:** incidents by severity (stacked columns) and a rule × time heatmap, for 24 hours, 7 days or 30 days.
- **Blocked IPs:** each IP is blocked for 24 hours. If it was blocked by mistake (for example an employee typed a wrong password 5 times), click **Unblock**. It takes effect within 60 seconds on the web app and within about 1 minute on AWS WAF. Every unblock is logged.
- **Incidents:** the latest incidents, filterable by severity; the table shows 10 rows first, click "Show more" for the rest. The page refreshes every 15 seconds.
- **Ask AI:** next to each incident, asks this assistant to explain that incident.
- Sessions expire after 30 minutes. Click **Sign out** when done: the session is revoked on the server, so a copied cookie cannot be reused.

## Roles section (administrators)
- The Roles section needs a separate 6-digit PIN, different from the sign-in password. The first time, the admin sets the PIN; after that, entering the PIN opens the section for 10 minutes. 5 wrong PINs lock it for 15 minutes and alert the other administrators.
- Approving or revoking a Viewer only needs the section to be open.
- Promote to Admin, demote to Viewer, and disable an account need votes from other administrators (two-person approval). There must always be at least 2 administrators.
- A forgotten PIN can be reset by another administrator ("Reset PIN"); the owner then sets a new PIN.

## Meaning of the rules
| Rule | Meaning | What to do |
|---|---|---|
| `BRUTE_FORCE_DETECTED` | One IP entered a wrong password 5 times within 60 seconds | The IP was blocked automatically. If it is a colleague, unblock it |
| `SLOW_BRUTE_FORCE` | One IP entered a wrong password 20 times within 1 hour, spread out to avoid the fast rule | The IP was blocked. Check the targeted accounts |
| `LOGIN_FAILURE_SPIKE` | More than 50 failed sign-ins in 5 minutes across the system, from many IPs against many accounts | Likely a leaked-password list being tried. Ask users to change passwords and turn on 2FA |
| `SCAN_DETECTED` | One IP requested 30 non-existent paths within 60 seconds (probing for vulnerabilities) | The IP was blocked. Nothing else needed |
| `ACCOUNT_UNDER_ATTACK` | One account had 10 wrong passwords in 5 minutes from **many different IPs** (distributed attack) | No IP is blocked automatically. Change that account's password, turn on 2FA |
| `SQL_INJECTION` | Someone tried to inject malicious code into the search box or sign-in form | The IP was blocked. Nothing else needed |
| `MFA_BYPASS_ATTEMPT` | **Correct** password but wrong OTP code | **Change the password now**: it may have leaked |
| `ROOT_ACCOUNT_LOGIN` | Someone signed in with the AWS root account | Confirm it was you; if not, change the root password and contact AWS Support |
| `CONSOLE_LOGIN_NO_MFA` | **Successful** AWS Console sign-in without MFA | Turn on MFA for that user |
| `CONSOLE_BRUTE_FORCE` | One IP failed AWS Console sign-in 5 times in 5 minutes | Check the targeted user; change the password, turn on MFA. The system cannot block IPs on the AWS Console |
| `MFA_TAMPERING` | Someone deactivated or deleted an MFA device | Find out who; turn MFA back on |
| `CLOUDTRAIL_TAMPERING` | Someone stopped or deleted the audit log | A sign of covering tracks. Turn the trail back on, review the account that did it |
| `IAM_ACCESS_KEY_CREATED` / `IAM_POLICY_ATTACHED` / `IAM_INLINE_POLICY_PUT` | An access key was created, or permissions were added to a user, role or group | If it was not a planned change: revoke the key, remove the permissions |
| `IAM_POLICY_VERSION_CREATED` / `IAM_TRUST_POLICY_CHANGED` | A policy in use was changed, or outsiders may now assume a role | Find out who; restore the previous policy / trust policy |
| `IAM_LOGIN_PROFILE_CHANGED` / `IAM_USER_ADDED_TO_GROUP` | A Console password was set for another user, or a user was added to a group | Sign of a backdoor. If it was not you: reset the password, remove from the group |
| `KMS_KEY_TAMPERING` | Someone disabled or scheduled deletion of an encryption key | **Urgent**: cancel the deletion (`aws kms cancel-key-deletion`), enable the key. Losing the key means losing all logs and the incident table |
| `ROLE_REQUEST_CREATED` | An administrator proposed to promote/demote or disable an account | Vote in the **Roles** section. If nobody on the team proposed it: **Reject** it and change the proposer's password |
| `ADMIN_ROLE_CHANGED` / `USER_DISABLED` | The change got enough votes and took effect (`bootstrap: true` = the internal admin promoted someone during setup) | Compare with the team's plan |
| `ROLE_CHANGE_FAILED` | Enough votes, but Cognito failed so the change was not applied | Wait a few minutes and click **Approve** on that request again |
| `ADMIN_PIN_LOCKED` | Someone entered a wrong Roles PIN 5 times | Ask the account owner. If it was not them, their session may be hijacked: change the password |
| `ADMIN_PIN_RESET` | An administrator reset another administrator's PIN | Confirm the person asked for it |

IAM incidents with `via_service: cloudformation.amazonaws.com` come from a `cdk deploy` — usually your own, but still compare the time.
