"""Seam 4: POST /api/chat cua SOC Console (Flask test client, AI gia, Cognito gia)."""
import json
import types
from pathlib import Path

import pytest

pytest.importorskip("flask")

from .test_chat_assistant import FakeProvider, ca  # noqa: E402
from .test_console_accounts import FakeIdentity, get, post, sign_in, local_admin  # noqa: E402
from .test_sample_app import Clock, env, mod  # noqa: E402,F401

SQLI = {"incident_id": "INC#7", "timestamp": "2026-11-19T01:02:03Z", "rule": "SQL_INJECTION", "severity": "HIGH",
        "details": {"client_ip": "203.0.113.9", "query": "' OR 1=1 --", "username": "victim@congty.vn"}}
BRUTE = {"incident_id": "INC#8", "timestamp": "2026-11-19T02:00:00Z", "rule": "BRUTE_FORCE", "severity": "MEDIUM",
         "details": {"client_ip": "198.51.100.77"}}


def build(mod, env, chat):
    import admin_governance
    import cognito_identity as cog
    clock = Clock()
    identity = FakeIdentity(cog)

    class Store:
        def recent_incidents(self, limit=50):
            return [SQLI, BRUTE][:limit]

        def active_blocks(self, now):
            return []

        def incidents_since(self, since, limit):
            return [i for i in (SQLI, BRUTE) if i["timestamp"] >= since][:limit]

    store = Store()
    app = mod.create_app(mod.load_config_from_env(env), mod.BlockList(lambda ip: None, clock=clock), store,
                         identity=identity, clock=clock, governance_store=admin_governance.MemoryGovernanceStore(),
                         chat=chat)
    log_path = Path(env["APP_LOG_PATH"])
    return types.SimpleNamespace(
        client=app.test_client(), identity=identity, store=store, clock=clock,
        logs=lambda: [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()] if log_path.exists() else [])


@pytest.fixture
def provider():
    return FakeProvider("Day la SQL injection. Khac phuc: dung truy van tham so hoa.")


@pytest.fixture
def chat_app(mod, env, provider):
    return build(mod, env, ca.ChatAssistant(provider, ca.MemoryChatQuota(), daily_limit=2))


def viewer(a, email="viewer@x.co"):
    a.identity.add(email, role="viewer")
    return sign_in(a, email)


def test_chat_route_does_not_exist_when_the_chatbot_is_not_configured(mod, env):
    a = build(mod, env, None)
    csrf = local_admin(a)
    assert post(a, "/api/chat", {"message": "hi"}, csrf=csrf).status_code == 404
    assert get(a, "/api/config").get_json().get("chat") is False


def test_requires_login_csrf_and_an_approved_role(chat_app, provider):
    assert post(chat_app, "/api/chat", {"message": "hi"}).status_code == 401
    csrf = viewer(chat_app)
    assert post(chat_app, "/api/chat", {"message": "hi"}).status_code == 403          # thieu CSRF
    chat_app.identity.add("moi@x.co", role="pending")
    pending_csrf = sign_in(chat_app, "moi@x.co", ip="198.51.100.61")
    assert post(chat_app, "/api/chat", {"message": "hi"}, csrf=pending_csrf, ip="198.51.100.61").status_code == 403
    assert provider.calls == [] and csrf


def test_viewer_asks_about_one_incident_and_gets_the_analysis(chat_app, provider):
    csrf = viewer(chat_app)
    r = post(chat_app, "/api/chat", {"message": "Su co nay la gi?", "incident_id": "INC#7"}, csrf=csrf)
    assert r.status_code == 200 and r.get_json() == {"answer": provider.answer}
    sent = provider.calls[0][1][-1]["content"]
    assert "SQL_INJECTION" in sent and "BRUTE_FORCE" not in sent       # chi su co duoc chon
    assert "victim@congty.vn" not in sent                               # email da duoc che


def test_without_incident_id_the_recent_incidents_are_attached(chat_app, provider):
    csrf = local_admin(chat_app)
    assert post(chat_app, "/api/chat", {"message": "Tom tat tan cong gan day"}, csrf=csrf).status_code == 200
    sent = provider.calls[0][1][-1]["content"]
    assert "SQL_INJECTION" in sent and "BRUTE_FORCE" in sent


def test_unknown_incident_is_rejected_without_calling_the_ai(chat_app, provider):
    csrf = viewer(chat_app)
    r = post(chat_app, "/api/chat", {"message": "?", "incident_id": "INC#khong-co"}, csrf=csrf)
    assert r.status_code == 404 and provider.calls == []


def test_quota_and_ai_errors_map_to_status_codes_and_the_log_never_holds_the_question(chat_app, provider):
    csrf = viewer(chat_app)
    for _ in range(2):
        assert post(chat_app, "/api/chat", {"message": "cau hoi bi mat 123"}, csrf=csrf).status_code == 200
    r = post(chat_app, "/api/chat", {"message": "cau hoi bi mat 123"}, csrf=csrf)
    assert r.status_code == 429 and "hết lượt" in r.get_json()["error"]
    events = [l for l in chat_app.logs() if l["event_type"] == "CHAT_QUESTION"]
    assert len(events) == 2 and "cau hoi bi mat" not in json.dumps(chat_app.logs())


def test_ai_outage_returns_503(mod, env):
    class Broken:
        def complete(self, i, m):
            raise RuntimeError("Incorrect API key sk-xyz")

    a = build(mod, env, ca.ChatAssistant(Broken(), ca.MemoryChatQuota()))
    csrf = viewer(a)
    r = post(a, "/api/chat", {"message": "hi"}, csrf=csrf)
    assert r.status_code == 503 and "sk-" not in r.get_data(as_text=True)


# ------------------------------------------------- giao dien (kiem tra tinh)
def test_console_has_a_chat_card_that_renders_ai_text_safely():
    root = Path(__file__).resolve().parents[2] / "sample_app"
    html = (root / "templates" / "console.html").read_text(encoding="utf-8")
    js = (root / "static" / "console.js").read_text(encoding="utf-8")
    for element_id in ("chat-card", "chat-log", "chat-form", "chat-input", "chat-context"):
        assert f'id="{element_id}"' in html
    assert 'maxlength="1000"' in html.split('id="chat-input"')[1].split(">")[0]
    assert '"/api/chat"' in js and "Hỏi AI" in js
    assert ".innerHTML" not in js and "insertAdjacentHTML" not in js   # cau tra loi cua AI chi hien bang textContent


def test_recent_incidents_table_shows_ten_rows_with_a_show_more_toggle():
    root = Path(__file__).resolve().parents[2] / "sample_app"
    html = (root / "templates" / "console.html").read_text(encoding="utf-8")
    js = (root / "static" / "console.js").read_text(encoding="utf-8")
    assert 'id="incidents-more"' in html
    assert "INCIDENT_PREVIEW = 10" in js and "Xem thêm" in js and "Thu gọn" in js
    assert 'aria-expanded' in js                                   # trinh doc man hinh biet bang dang mo hay thu gon
