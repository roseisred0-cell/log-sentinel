"""Phan quyen admin (muc "Phan quyen" cua SOC Console): PIN rieng, bo phieu nang/ha/vo hieu hoa, che do khoi tao.

Quyet dinh thiet ke: docs/NHAT_KY_2026-11-11.md muc 3 va docs/NHAT_KY_2026-11-12.md muc 1.
Seam A: HTTP API cua web app (Cognito gia + store RAM).
"""
import pytest

pytest.importorskip("flask")

from .test_console_accounts import (  # noqa: E402,F401  (fixture dung chung)
    GOOD_TOTP, STRONG, acct, env, get, local_admin, mod, post,
)

PIN = "482915"
OTHER_PIN = "730146"


def cognito_admin(a, email, ip="198.51.100.60"):
    """Admin Cognito da bat 2FA, dang nhap qua buoc OTP. Tra ve CSRF."""
    if email not in a.identity.users:
        a.identity.add(email, mfa=True, role="admin")
    post(a, "/auth/login", {"email": email, "password": STRONG}, ip=ip)
    assert post(a, "/auth/mfa", {"code": GOOD_TOTP}, ip=ip).status_code == 200
    return get(a, "/api/session", ip=ip).get_json()["csrf"]


def gov(a, ip="198.51.100.60"):
    return get(a, "/api/governance", ip=ip)


# ------------------------------------------- Seam B: so phieu can co
@pytest.fixture
def gm(mod):
    import admin_governance  # sample_app da nam tren sys.path nho fixture `mod`
    return admin_governance


@pytest.mark.parametrize("action,admins,needed", [
    # nang len Quan tri: da so admin hien co, toi thieu 2 (vd 2 admin can 2, 3 can 2, 4 can 3)
    ("promote", 2, 2), ("promote", 3, 2), ("promote", 4, 3), ("promote", 5, 3), ("promote", 6, 4),
    # ha Quan tri: da so tinh tren TAT CA admin ke ca nguoi bi ha (quyet dinh A1), nguoi do khong bo phieu
    ("demote", 3, 2), ("demote", 4, 3), ("demote", 5, 3),
    # vo hieu hoa: luon 2 nguoi
    ("disable", 2, 2), ("disable", 5, 2), ("disable", 10, 2),
])
def test_required_approvals(gm, action, admins, needed):
    assert gm.required_approvals(action, admins) == needed


def test_required_approvals_rejects_unknown_action(gm):
    with pytest.raises(ValueError):
        gm.required_approvals("delete_everything", 3)


# ------------------------------------------------------------ PIN rieng
def test_admin_sets_pin_on_first_entry_and_section_unlocks(acct):
    csrf = local_admin(acct)
    status = gov(acct).get_json()
    assert status["has_pin"] is False and status["unlocked"] is False

    assert post(acct, "/api/governance/pin", {"pin": PIN}, csrf=csrf).status_code == 200
    status = gov(acct).get_json()
    assert status["has_pin"] is True and status["unlocked"] is True
    assert status["unlocked_until"] == acct.clock.t + 600  # giao dien dem nguoc 10 phut


def test_unlock_lasts_ten_minutes_then_pin_is_needed_again(acct):
    csrf = local_admin(acct)
    post(acct, "/api/governance/pin", {"pin": PIN}, csrf=csrf)
    acct.clock.t += 9 * 60
    assert gov(acct).get_json()["unlocked"] is True
    acct.clock.t += 2 * 60
    assert gov(acct).get_json()["unlocked"] is False

    assert post(acct, "/api/governance/unlock", {"pin": PIN}, csrf=csrf).status_code == 200
    assert gov(acct).get_json()["unlocked"] is True


@pytest.mark.parametrize("pin", ["000000", "111111", "123456", "654321", "012345", "987654", "121212",
                                 "123123", "112233", "12345", "1234567", "abcdef", "48291a", "", None, 482915])
def test_weak_or_malformed_pin_is_refused(acct, pin):
    csrf = local_admin(acct)
    r = post(acct, "/api/governance/pin", {"pin": pin}, csrf=csrf)
    assert r.status_code == 400 and r.get_json()["error"] == "weak_pin"
    assert gov(acct).get_json()["has_pin"] is False


def test_pin_cannot_be_overwritten_by_setting_it_again(acct):
    csrf = local_admin(acct)
    post(acct, "/api/governance/pin", {"pin": PIN}, csrf=csrf)
    r = post(acct, "/api/governance/pin", {"pin": OTHER_PIN}, csrf=csrf)
    assert r.status_code == 400 and r.get_json()["error"] == "pin_exists"
    acct.clock.t += 11 * 60
    assert post(acct, "/api/governance/unlock", {"pin": OTHER_PIN}, csrf=csrf).status_code == 403


def test_pin_is_never_written_to_the_log(acct):
    csrf = local_admin(acct)
    post(acct, "/api/governance/pin", {"pin": PIN}, csrf=csrf)
    post(acct, "/api/governance/unlock", {"pin": OTHER_PIN}, csrf=csrf)
    text = str(acct.logs())
    assert PIN not in text and OTHER_PIN not in text


def test_five_wrong_pins_lock_for_fifteen_minutes_and_raise_alert(acct):
    csrf = local_admin(acct)
    post(acct, "/api/governance/pin", {"pin": PIN}, csrf=csrf)
    acct.clock.t += 11 * 60
    codes = [post(acct, "/api/governance/unlock", {"pin": OTHER_PIN}, csrf=csrf).status_code for _ in range(5)]
    assert codes == [403] * 5
    alert = acct.logs()[-1]
    assert alert["event_type"] == "ADMIN_PIN_LOCKED" and alert["username"] == "admin"

    r = post(acct, "/api/governance/unlock", {"pin": PIN}, csrf=csrf)  # dung PIN van bi tu choi khi dang khoa
    assert r.status_code == 423 and r.get_json()["error"] == "pin_locked"
    acct.clock.t += 15 * 60 + 1
    assert post(acct, "/api/governance/unlock", {"pin": PIN}, csrf=csrf).status_code == 200


def test_pin_lock_survives_logout_and_new_login(acct):
    """Bo dem nam o store dung chung, khong nam trong cookie: dang nhap lai khong xoa duoc."""
    csrf = local_admin(acct)
    post(acct, "/api/governance/pin", {"pin": PIN}, csrf=csrf)
    acct.clock.t += 11 * 60
    for _ in range(5):
        post(acct, "/api/governance/unlock", {"pin": OTHER_PIN}, csrf=csrf)
    post(acct, "/api/logout", csrf=csrf)
    csrf = local_admin(acct)
    assert post(acct, "/api/governance/unlock", {"pin": PIN}, csrf=csrf).status_code == 423


def test_correct_pin_resets_the_failure_counter(acct):
    csrf = local_admin(acct)
    post(acct, "/api/governance/pin", {"pin": PIN}, csrf=csrf)
    for _ in range(4):
        post(acct, "/api/governance/unlock", {"pin": OTHER_PIN}, csrf=csrf)
    post(acct, "/api/governance/unlock", {"pin": PIN}, csrf=csrf)
    for _ in range(4):
        post(acct, "/api/governance/unlock", {"pin": OTHER_PIN}, csrf=csrf)
    assert post(acct, "/api/governance/unlock", {"pin": PIN}, csrf=csrf).status_code == 200


# ------------------------------------------------ yeu cau & bo phieu
PINS = {}  # email -> PIN rieng cua admin trong test


def enter(a, who):
    """Dang nhap `who` ("admin" = admin noi bo, con lai = email admin Cognito) va mo khoa muc Phan quyen."""
    csrf = local_admin(a) if who == "admin" else cognito_admin(a, who)
    pin = PINS.setdefault(who, f"{482915 + 7 * len(PINS):06d}")
    if not gov(a).get_json()["has_pin"]:
        assert post(a, "/api/governance/pin", {"pin": pin}, csrf=csrf).status_code == 200
    else:
        assert post(a, "/api/governance/unlock", {"pin": pin}, csrf=csrf).status_code == 200
    return csrf


def request_change(a, who, action, target_email):
    csrf = enter(a, who)
    username = a.identity.users[target_email]["username"]
    return post(a, "/api/governance/requests", {"action": action, "username": username, "pin": PINS[who]}, csrf=csrf)


def vote(a, who, request_id, decision="approve"):
    csrf = enter(a, who)
    return post(a, f"/api/governance/requests/{request_id}/vote", {"decision": decision, "pin": PINS[who]}, csrf=csrf)


def role(a, email):
    return a.identity.users[email]["role"]


@pytest.fixture(autouse=True)
def _fresh_pins():
    PINS.clear()


@pytest.fixture
def team(acct):
    """Hai admin Cognito (da bat 2FA) va mot nguoi xem."""
    for email in ("a@x.co", "b@x.co"):
        acct.identity.add(email, mfa=True, role="admin")
    acct.identity.add("v@x.co", role="viewer")
    return acct


def test_promotion_waits_for_second_admin_then_takes_effect(team):
    r = request_change(team, "a@x.co", "promote", "v@x.co")
    assert r.status_code == 200 and r.get_json()["status"] == "pending"
    assert role(team, "v@x.co") == "viewer"
    created = team.logs()[-1]
    assert created["event_type"] == "ROLE_REQUEST_CREATED" and created["target_user"] == "v@x.co"

    r = vote(team, "b@x.co", r.get_json()["id"])
    assert r.status_code == 200 and r.get_json()["status"] == "executed"
    assert role(team, "v@x.co") == "admin"
    changed = [e for e in team.logs() if e["event_type"] == "ADMIN_ROLE_CHANGED"]
    assert len(changed) == 1 and changed[0]["action"] == "promote"
    assert changed[0]["target_user"] == "v@x.co" and set(changed[0]["approvers"]) == {"cognito:a@x.co", "cognito:b@x.co"}


def test_initiator_cannot_approve_own_request_twice(team):
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]
    r = vote(team, "a@x.co", rid)
    assert r.status_code == 409 and r.get_json()["error"] == "already_voted"
    assert role(team, "v@x.co") == "viewer"


def test_four_admins_need_three_votes_to_promote(team):
    for email in ("c@x.co", "d@x.co"):
        team.identity.add(email, mfa=True, role="admin")
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]
    assert vote(team, "b@x.co", rid).get_json()["status"] == "pending"
    assert role(team, "v@x.co") == "viewer"
    assert vote(team, "c@x.co", rid).get_json()["status"] == "executed"
    assert role(team, "v@x.co") == "admin"


def test_one_rejection_cancels_the_request(team):
    team.identity.add("c@x.co", mfa=True, role="admin")
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]
    assert vote(team, "b@x.co", rid, "reject").get_json()["status"] == "rejected"
    assert team.logs()[-1]["event_type"] == "ROLE_REQUEST_REJECTED"
    r = vote(team, "c@x.co", rid)
    assert r.status_code == 409 and r.get_json()["error"] == "request_closed"
    assert role(team, "v@x.co") == "viewer"


def test_request_expires_after_24_hours(team):
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]
    team.clock.t += 24 * 3600 + 1
    r = vote(team, "b@x.co", rid)
    assert r.status_code == 410 and r.get_json()["error"] == "request_expired"
    assert role(team, "v@x.co") == "viewer"
    assert gov(team).get_json()["requests"] == []


def test_pending_requests_are_listed_for_admins(team):
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]
    enter(team, "b@x.co")
    listed = gov(team).get_json()["requests"]
    assert [(q["id"], q["action"], q["target_user"], q["approvals"], q["needed"]) for q in listed] == \
        [(rid, "promote", "v@x.co", 1, 2)]


def test_only_viewers_can_be_promoted(team):
    team.identity.add("p@x.co")  # cho duyet: phai duyet thanh Nguoi xem truoc
    r = request_change(team, "a@x.co", "promote", "p@x.co")
    assert r.status_code == 400 and r.get_json()["error"] == "invalid_target"


def test_demotion_is_blocked_when_it_would_leave_fewer_than_two_admins(team):
    r = request_change(team, "a@x.co", "demote", "b@x.co")
    assert r.status_code == 409 and r.get_json()["error"] == "min_admins"
    assert role(team, "b@x.co") == "admin"


def test_demotion_with_three_admins_and_target_cannot_vote(team):
    team.identity.add("c@x.co", mfa=True, role="admin")
    rid = request_change(team, "a@x.co", "demote", "c@x.co").get_json()["id"]
    r = vote(team, "c@x.co", rid)
    assert r.status_code == 403 and r.get_json()["error"] == "not_a_voter"
    assert vote(team, "b@x.co", rid).get_json()["status"] == "executed"
    assert role(team, "c@x.co") == "viewer"


@pytest.mark.parametrize("action", ["demote", "disable"])
def test_admin_cannot_target_themself(team, action):
    team.identity.add("c@x.co", mfa=True, role="admin")
    r = request_change(team, "a@x.co", action, "a@x.co")
    assert r.status_code == 400 and r.get_json()["error"] == "self_action"


def test_disabling_a_viewer_needs_two_admins(team):
    team.identity.add("c@x.co", mfa=True, role="admin")
    rid = request_change(team, "a@x.co", "disable", "v@x.co").get_json()["id"]
    assert team.identity.users["v@x.co"].get("disabled") is None
    assert vote(team, "b@x.co", rid).get_json()["status"] == "executed"
    assert team.identity.users["v@x.co"]["disabled"] is True


def test_disabling_an_admin_respects_the_two_admin_minimum(team):
    r = request_change(team, "a@x.co", "disable", "b@x.co")
    assert r.status_code == 409 and r.get_json()["error"] == "min_admins"


def test_changes_need_unlocked_section_and_correct_pin(team):
    csrf = enter(team, "a@x.co")
    username = team.identity.users["v@x.co"]["username"]
    r = post(team, "/api/governance/requests", {"action": "promote", "username": username, "pin": OTHER_PIN}, csrf=csrf)
    assert r.status_code == 403 and r.get_json()["error"] == "wrong_pin"
    team.clock.t += 11 * 60  # muc Phan quyen tu khoa lai
    r = post(team, "/api/governance/requests", {"action": "promote", "username": username, "pin": PINS["a@x.co"]},
             csrf=csrf)
    assert r.status_code == 403 and r.get_json()["error"] == "pin_required"
    post(team, "/api/governance/unlock", {"pin": PINS["a@x.co"]}, csrf=csrf)
    assert gov(team).get_json()["requests"] == []


@pytest.mark.parametrize("body", [{}, {"action": "promote"}, {"action": "explode", "username": "uid-v"},
                                  {"action": ["promote"], "username": "uid-v"}, {"action": "promote", "username": 5}])
def test_malformed_requests_are_400(team, body):
    csrf = enter(team, "a@x.co")
    r = post(team, "/api/governance/requests", {**body, "pin": PINS["a@x.co"]}, csrf=csrf)
    assert r.status_code in (400, 404)
    assert role(team, "v@x.co") == "viewer"


def test_unknown_request_id_is_404(team):
    r = vote(team, "a@x.co", "does-not-exist")
    assert r.status_code == 404


# ------------------------------------------- sua sau review 12/11
def test_demoting_one_of_four_admins_needs_three_votes(team):
    """Quyet dinh A1: da so tinh tren TAT CA admin (4 -> 3), nguoi bi ha khong bo phieu."""
    for email in ("c@x.co", "d@x.co"):
        team.identity.add(email, mfa=True, role="admin")
    rid = request_change(team, "a@x.co", "demote", "d@x.co").get_json()["id"]
    assert vote(team, "b@x.co", rid).get_json()["status"] == "pending"
    assert role(team, "d@x.co") == "admin"
    assert vote(team, "c@x.co", rid).get_json()["status"] == "executed"
    assert role(team, "d@x.co") == "viewer"


def test_failed_cognito_call_keeps_the_request_open_and_is_logged(team):
    import cognito_identity as cog
    real = team.identity.promote
    team.identity.promote = lambda username: (_ for _ in ()).throw(cog.UpstreamError("boom"))
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]
    r = vote(team, "b@x.co", rid)
    assert r.status_code == 502 and role(team, "v@x.co") == "viewer"
    assert team.logs()[-1]["event_type"] == "ROLE_CHANGE_FAILED"
    assert [q["id"] for q in gov(team).get_json()["requests"]] == [rid]  # khong mat yeu cau

    team.identity.promote = real  # Cognito hoi phuc: nguoi da bo phieu bam lai de thuc thi
    assert vote(team, "b@x.co", rid).get_json()["status"] == "executed"
    assert role(team, "v@x.co") == "admin"


def test_executions_are_serialised_by_a_shared_lock(team):
    """Hai worker thuc thi cung luc co the cung thay 3 admin roi cung ha mot nguoi -> con 1 admin."""
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]
    assert team.gov_store.lock_acquire("execute", team.clock(), 30, "other") is True  # worker khac dang thuc thi
    r = vote(team, "b@x.co", rid)
    assert r.status_code == 409 and r.get_json()["error"] == "busy"
    assert role(team, "v@x.co") == "viewer"
    team.clock.t += 31  # khoa tu het han (worker kia chet giua chung)
    assert vote(team, "b@x.co", rid).get_json()["status"] == "executed"


def test_a_rejection_cannot_slip_in_while_the_change_is_being_executed(team):
    """B bo phieu quyet dinh, trong luc Lambda dang goi Cognito thi C bam Tu choi. Truoc day phieu cua C
    ghi 'rejected' ngay giua chung: Cognito van doi vai tro nhung ban ghi noi 'da tu choi'. Nay C phai doi."""
    import types
    team.identity.add("c@x.co", mfa=True, role="admin")
    c_browser = types.SimpleNamespace(**vars(team))
    c_browser.client = team.app.test_client()
    enter(c_browser, "c@x.co")
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]

    real, seen = team.identity.promote, {}

    def promote_while_c_rejects(username):
        seen["reject"] = vote(c_browser, "c@x.co", rid, "reject")
        return real(username)

    team.identity.promote = promote_while_c_rejects
    r = vote(team, "b@x.co", rid)
    assert r.get_json()["status"] == "executed" and role(team, "v@x.co") == "admin"
    assert seen["reject"].status_code == 409 and seen["reject"].get_json()["error"] == "busy"
    assert team.gov_store.req_get(rid)["status"] == "executed"
    assert not [e for e in team.logs() if e["event_type"] == "ROLE_REQUEST_REJECTED"]


def test_admin_count_and_warning_data_are_visible_before_unlocking(team):
    csrf = cognito_admin(team, "a@x.co")
    status = gov(team).get_json()
    assert status["unlocked"] is False and status["admin_count"] == 2 and status["bootstrap"] is False
    assert "requests" not in status  # chi tiet yeu cau van can PIN


def test_disabling_logs_its_own_event(team):
    team.identity.add("c@x.co", mfa=True, role="admin")
    rid = request_change(team, "a@x.co", "disable", "v@x.co").get_json()["id"]
    vote(team, "b@x.co", rid)
    events = [e["event_type"] for e in team.logs()]
    assert "USER_DISABLED" in events and "ADMIN_ROLE_CHANGED" not in events


def test_internal_admin_outside_bootstrap_only_views_and_unblocks(team):
    """A2 + Q2 (b): du 2 admin Cognito -> admin noi bo chi con xem va go khoa IP."""
    enter(team, "a@x.co")
    team.identity.add("p@x.co")
    csrf = enter(team, "admin")
    r = post(team, "/api/governance/pin/reset", {"username": "uid-a", "pin": PINS["admin"]}, csrf=csrf)
    assert r.status_code == 403 and r.get_json()["error"] == "local_admin_restricted"
    for path, user in (("/api/users/revoke", "uid-v"), ("/api/users/approve", "uid-p")):
        r = post(team, path, {"username": user}, csrf=csrf)
        assert r.status_code == 403 and r.get_json()["error"] == "local_admin_restricted", path
    assert role(team, "v@x.co") == "viewer" and role(team, "p@x.co") == "pending"
    assert post(team, "/api/unblock", {"ip": "203.0.113.5"}, csrf=csrf).status_code == 200
    assert get(team, "/api/overview").status_code == 200


def test_console_sends_the_users_own_token_never_a_claimed_identity(mod, env):
    """Seam A -> G: moi thao tac phan quyen di qua executor (Lambda), kem token Cognito cua chinh nguoi bam."""
    import types
    import admin_governance
    import cognito_identity as cog
    import governance_lambda
    from .test_console_accounts import FakeIdentity
    from .test_sample_app import Clock
    identity, clock, store = FakeIdentity(cog), Clock(), admin_governance.MemoryGovernanceStore()
    for email in ("a@x.co", "b@x.co"):
        identity.add(email, mfa=True, role="admin")
    identity.add("v@x.co", role="viewer")
    identity.add("p@x.co")
    inner = governance_lambda.InProcessExecutor(
        admin_governance.Governance(store, identity=identity, clock=clock), identity)
    events = []

    def spy(event):
        events.append(event)
        return inner(event)

    class Store:
        def recent_incidents(self, limit=50):
            return []

        def active_blocks(self, now):
            return []

    app = mod.create_app(mod.load_config_from_env(env), mod.BlockList(lambda ip: None, clock=clock), Store(),
                         identity=identity, clock=clock, governance_store=store, executor=spy)
    a = types.SimpleNamespace(client=app.test_client(), identity=identity, clock=clock)
    csrf = cognito_admin(a, "a@x.co")
    post(a, "/api/governance/pin", {"pin": PIN}, csrf=csrf)
    post(a, "/api/governance/requests", {"action": "promote", "username": "uid-v", "pin": PIN}, csrf=csrf)
    post(a, "/api/users/approve", {"username": "uid-p"}, csrf=csrf)
    assert [e["op"] for e in events] == ["create", "approve_viewer"]
    assert all(e["caller"] == {"access_token": "tok-a@x.co"} for e in events)
    assert all("principal" not in e for e in events)


def test_internal_admin_may_reset_pins_during_bootstrap(acct):
    acct.identity.add("a@x.co", mfa=True, role="admin")
    enter(acct, "a@x.co")
    assert reset_pin(acct, "admin", "a@x.co").status_code == 200


# --------------------------- B4: doi vai tro co hieu luc ngay, khong doi het phien 30 phut
def second_browser(a, email, ip="198.51.100.99"):
    """Phien rieng cua nguoi bi tac dong (trinh duyet khac, cookie rieng)."""
    c = a.app.test_client()
    kw = {"environ_base": {"REMOTE_ADDR": "127.0.0.1"}, "headers": {"X-Real-IP": ip}}
    c.post("/auth/login", json={"email": email, "password": STRONG}, **kw)
    if a.identity.users[email]["mfa"]:
        c.post("/auth/mfa", json={"code": GOOD_TOTP}, **kw)
    return lambda path: c.get(path, **kw)


def test_demoted_admin_loses_admin_session_immediately(team):
    team.identity.add("c@x.co", mfa=True, role="admin")
    c_get = second_browser(team, "c@x.co")
    assert c_get("/api/users").status_code == 200
    team.clock.t += 1
    rid = request_change(team, "a@x.co", "demote", "c@x.co").get_json()["id"]
    vote(team, "b@x.co", rid)
    assert c_get("/api/users").status_code == 401  # phai dang nhap lai -> nhan vai tro moi


def test_disabled_user_session_dies_immediately(team):
    team.identity.add("c@x.co", mfa=True, role="admin")
    v_get = second_browser(team, "v@x.co")
    assert v_get("/api/overview").status_code == 200
    team.clock.t += 1
    rid = request_change(team, "a@x.co", "disable", "v@x.co").get_json()["id"]
    vote(team, "b@x.co", rid)
    assert v_get("/api/overview").status_code == 401


def test_promoted_viewer_must_log_in_again_to_get_admin_rights(team):
    """Dang nhap lai -> vai tro admin moi co hieu luc va buoc bat 2FA neu chua bat."""
    v_get = second_browser(team, "v@x.co")
    team.clock.t += 1
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]
    vote(team, "b@x.co", rid)
    assert v_get("/api/overview").status_code == 401
    team.clock.t += 1
    v_get = second_browser(team, "v@x.co")
    session = v_get("/api/session").get_json()
    assert session["role"] == "admin" and session["mfa_setup_required"] is True


def test_other_users_sessions_are_untouched(team):
    b_get = second_browser(team, "b@x.co")
    team.clock.t += 1
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]
    assert vote(team, "b@x.co", rid).get_json()["status"] == "executed"
    assert b_get("/api/users").status_code == 200  # phien khac cua nguoi bo phieu van con


def test_revoked_viewer_session_dies_immediately(team):
    """Thu hoi Nguoi xem: nguoi do bi dang xuat ngay, khong doc tiep su co toi het 30 phut."""
    v_get = second_browser(team, "v@x.co")
    assert v_get("/api/overview").status_code == 200
    team.clock.t += 1
    csrf = enter(team, "a@x.co")
    assert post(team, "/api/users/revoke", {"username": "uid-v"}, csrf=csrf).status_code == 200
    assert v_get("/api/overview").status_code == 401


# ------------------------------------------------------- dat lai PIN
def reset_pin(a, who, target_email):
    csrf = enter(a, who)
    username = a.identity.users[target_email]["username"]
    return post(a, "/api/governance/pin/reset", {"username": username, "pin": PINS[who]}, csrf=csrf)


def test_another_admin_resets_a_forgotten_pin_and_it_is_alerted(team):
    enter(team, "a@x.co")  # a dat PIN roi quen
    r = reset_pin(team, "b@x.co", "a@x.co")
    assert r.status_code == 200
    alert = team.logs()[-1]
    assert alert["event_type"] == "ADMIN_PIN_RESET" and alert["target_user"] == "a@x.co"  # muc HIGH: Detector
    csrf = cognito_admin(team, "a@x.co")
    assert gov(team).get_json()["has_pin"] is False
    assert post(team, "/api/governance/pin", {"pin": OTHER_PIN}, csrf=csrf).status_code == 200


def test_reset_also_lifts_a_pin_lockout(team):
    csrf = enter(team, "a@x.co")
    team.clock.t += 11 * 60
    for _ in range(5):
        post(team, "/api/governance/unlock", {"pin": "999990"}, csrf=csrf)
    assert reset_pin(team, "b@x.co", "a@x.co").status_code == 200
    csrf = cognito_admin(team, "a@x.co")
    assert post(team, "/api/governance/pin", {"pin": OTHER_PIN}, csrf=csrf).status_code == 200


def test_admin_cannot_reset_own_pin(team):
    r = reset_pin(team, "a@x.co", "a@x.co")
    assert r.status_code == 400 and r.get_json()["error"] == "self_action"


def test_only_admin_pins_can_be_reset_from_the_browser(team):
    r = reset_pin(team, "a@x.co", "v@x.co")
    assert r.status_code == 400 and r.get_json()["error"] == "invalid_target"


def test_reset_needs_the_resetting_admins_own_pin(team):
    enter(team, "a@x.co")
    csrf = enter(team, "b@x.co")
    r = post(team, "/api/governance/pin/reset", {"username": "uid-a", "pin": OTHER_PIN}, csrf=csrf)
    assert r.status_code == 403
    cognito_admin(team, "a@x.co")
    assert gov(team).get_json()["has_pin"] is True


# ------------------------------------- duyet Nguoi xem nam trong muc Phan quyen
def test_approving_and_revoking_viewers_need_unlocked_section(team):
    team.identity.add("p@x.co")
    csrf = cognito_admin(team, "a@x.co")
    for path, user in (("/api/users/approve", "uid-p"), ("/api/users/revoke", "uid-v")):
        r = post(team, path, {"username": user}, csrf=csrf)
        assert r.status_code == 403 and r.get_json()["error"] == "pin_required", path
    csrf = enter(team, "a@x.co")
    assert post(team, "/api/users/approve", {"username": "uid-p"}, csrf=csrf).status_code == 200
    assert post(team, "/api/users/revoke", {"username": "uid-v"}, csrf=csrf).status_code == 200


# ------------------------------------------------------ che do khoi tao
def test_bootstrap_lets_internal_admin_promote_alone(acct):
    acct.identity.add("v@x.co", role="viewer")
    assert gov_status(acct, "admin")["bootstrap"] is True
    r = request_change(acct, "admin", "promote", "v@x.co")
    assert r.status_code == 200 and r.get_json()["status"] == "executed"
    assert role(acct, "v@x.co") == "admin"
    changed = acct.logs()[-1]
    assert changed["event_type"] == "ADMIN_ROLE_CHANGED" and changed["bootstrap"] is True


def test_bootstrap_still_on_with_one_cognito_admin(acct):
    acct.identity.add("a@x.co", mfa=True, role="admin")
    acct.identity.add("v@x.co", role="viewer")
    assert request_change(acct, "admin", "promote", "v@x.co").get_json()["status"] == "executed"
    assert gov_status(acct, "admin")["bootstrap"] is False  # da du 2 admin Cognito


def test_cognito_admin_request_in_bootstrap_needs_internal_admin(acct):
    acct.identity.add("a@x.co", mfa=True, role="admin")
    acct.identity.add("v@x.co", role="viewer")
    rid = request_change(acct, "a@x.co", "promote", "v@x.co").get_json()["id"]
    assert role(acct, "v@x.co") == "viewer"
    assert vote(acct, "admin", rid).get_json()["status"] == "executed"


def test_internal_admin_loses_vote_once_two_cognito_admins_exist(team):
    r = request_change(team, "admin", "promote", "v@x.co")
    assert r.status_code == 403 and r.get_json()["error"] == "local_admin_no_vote"
    rid = request_change(team, "a@x.co", "promote", "v@x.co").get_json()["id"]
    r = vote(team, "admin", rid)
    assert r.status_code == 403 and r.get_json()["error"] == "local_admin_no_vote"
    assert role(team, "v@x.co") == "viewer"


def test_two_cognito_admins_flag_reported(team):
    status = gov_status(team, "a@x.co")
    assert status["bootstrap"] is False and status["admin_count"] == 2


def gov_status(a, who):
    enter(a, who)
    return gov(a).get_json()


# ------------------------------------------------- admin bat buoc 2FA
def test_cognito_admin_without_2fa_must_enable_it_before_anything_else(acct):
    from .test_console_accounts import sign_in
    acct.identity.add("boss@x.co", role="admin")  # chua bat 2FA
    csrf = sign_in(acct, "boss@x.co")
    assert get(acct, "/api/session").get_json()["mfa_setup_required"] is True
    for path in ("/api/overview", "/api/users", "/api/governance"):
        r = get(acct, path)
        assert r.status_code == 403 and r.get_json()["error"] == "mfa_setup_required", path
    assert post(acct, "/api/unblock", {"ip": "203.0.113.5"}, csrf=csrf).status_code == 403

    post(acct, "/api/mfa/setup", csrf=csrf)
    assert post(acct, "/api/mfa/enable", {"code": GOOD_TOTP}, csrf=csrf).status_code == 200
    assert get(acct, "/api/session").get_json()["mfa_setup_required"] is False
    assert get(acct, "/api/overview").status_code == 200


def test_admin_cannot_switch_2fa_off(acct):
    csrf = cognito_admin(acct, "boss@x.co")
    r = post(acct, "/api/mfa/disable", {"password": STRONG, "code": GOOD_TOTP}, csrf=csrf)
    assert r.status_code == 403 and r.get_json()["error"] == "admin_mfa_required"
    assert acct.identity.users["boss@x.co"]["mfa"] is True


def test_viewer_2fa_stays_optional(acct):
    from .test_console_accounts import sign_in
    acct.identity.add("v@x.co", role="viewer")
    sign_in(acct, "v@x.co")
    assert get(acct, "/api/session").get_json()["mfa_setup_required"] is False
    assert get(acct, "/api/overview").status_code == 200


def test_viewer_cannot_reach_the_section(acct):
    acct.identity.add("v@x.co", role="viewer")
    from .test_console_accounts import sign_in
    csrf = sign_in(acct, "v@x.co")
    assert gov(acct).status_code == 403
    assert post(acct, "/api/governance/pin", {"pin": PIN}, csrf=csrf).status_code == 403


def test_every_pin_box_in_the_console_accepts_digits_only():
    """Go nham chu vao o PIN khi mo khoa bi tinh la 1 lan sai (5 lan -> khoa 15 phut): chan ngay tu luc go."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "sample_app"
    html = (root / "templates" / "console.html").read_text(encoding="utf-8")
    pin_inputs = [t for t in re.findall(r"<input[^>]*>", html) if 'name="pin' in t or 'id="gov-pin"' in t]
    assert len(pin_inputs) == 4                                   # dat PIN (2 o), mo khoa, xac nhan thao tac
    assert all("data-digits" in t and 'inputmode="numeric"' in t and 'maxlength="6"' in t for t in pin_inputs)
    js = (root / "static" / "console.js").read_text(encoding="utf-8")
    assert "input[data-digits]" in js and "replace(/\D/g" in js


def test_locked_section_tells_the_admin_how_many_accounts_are_waiting(acct):
    """Su co 19/11: admin khong biet co nguoi cho duyet vi muc Phan quyen dang khoa (chua dat PIN)."""
    from pathlib import Path
    acct.identity.add("cho@x.co", role="pending")
    cognito_admin(acct, "rose@x.co")
    assert gov(acct).get_json()["unlocked"] is False
    users = get(acct, "/api/users")                       # danh sach van doc duoc khi muc dang khoa (chi doc)
    assert users.status_code == 200 and len(users.get_json()["pending"]) == 1
    root = Path(__file__).resolve().parents[2] / "sample_app"
    assert 'id="gov-pending-hint"' in (root / "templates" / "console.html").read_text(encoding="utf-8")
    js = (root / "static" / "console.js").read_text(encoding="utf-8")
    assert "đang chờ duyệt" in js and "gov-pending-hint" in js
