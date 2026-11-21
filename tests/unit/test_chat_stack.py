"""Seam 5: ha tang cho tro ly AI (template CDK + file deploy).

Bat: cdk deploy -c chat_model=<ten model OpenAI>. Sau deploy, nguoi dung TU dua key vao secret
logsentinel/openai_api_key (Claude/nguoi viet code khong bao gio cam key).
"""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENV = {"account": "123456789012", "region": "ap-southeast-1"}


def _template(context):
    aws_cdk = pytest.importorskip("aws_cdk")
    from aws_cdk import assertions
    from log_sentinel.log_sentinel_stack import LogSentinelStack
    app = aws_cdk.App(context={"alert_email": "ops@example.com", **context})
    return assertions.Template.from_stack(LogSentinelStack(app, "chat", env=aws_cdk.Environment(**ENV)))


@pytest.fixture(scope="module")
def off():
    return _template({})


@pytest.fixture(scope="module")
def on():
    return _template({"chat_model": "model-test", "chat_daily_limit": "20"})


def _secrets(t):
    return {k: v for k, v in t.find_resources("AWS::SecretsManager::Secret").items()
            if v["Properties"].get("Name") == "logsentinel/openai_api_key"}


def _policies_of(t, prefix):
    return [v for v in t.find_resources("AWS::IAM::Policy").values()
            if any(r.get("Ref", "").startswith(prefix) for r in v["Properties"].get("Roles", []))]


def test_chatbot_is_off_by_default(off):
    assert _secrets(off) == {}
    assert "CHAT_MODEL" not in str(off.find_resources("AWS::EC2::Instance"))
    assert "CHAT_QUOTA#" not in str(off.find_resources("AWS::IAM::Policy"))


def test_enabled_chatbot_gets_a_secret_and_only_its_arn_reaches_the_instance(on):
    [(logical_id, _)] = _secrets(on).items()
    instance = str(on.find_resources("AWS::EC2::Instance"))
    assert "CHAT_MODEL=model-test" in instance and "CHAT_DAILY_LIMIT=20" in instance
    assert "CHAT_SECRET_ID=" in instance and logical_id in instance
    assert "resolve:secretsmanager" not in instance
    assert "ChatSecretArn" in on.find_outputs("*")


def test_only_the_instance_may_read_the_openai_key_and_it_counts_quota_under_its_own_prefix(on):
    [logical_id] = _secrets(on)
    vm = str(_policies_of(on, "TargetVmRole"))
    assert logical_id in vm and "secretsmanager:GetSecretValue" in vm
    assert "CHAT_QUOTA#*" in vm
    others = [str(p) for p in on.find_resources("AWS::IAM::Policy").values()
              if not any(r.get("Ref", "").startswith("TargetVmRole") for r in p["Properties"].get("Roles", []))]
    assert not any(logical_id in p for p in others)            # Detector / Lambda khac khong doc duoc key


def test_deploy_files_pass_the_settings_through_and_install_the_sdk():
    bootstrap = (ROOT / "sample_app" / "deploy" / "bootstrap.sh").read_text(encoding="utf-8")
    for key in ("CHAT_MODEL", "CHAT_SECRET_ID", "CHAT_DAILY_LIMIT"):
        assert f"{key}=${{{key}:-}}" in bootstrap
    assert "openai" in (ROOT / "sample_app" / "requirements.txt").read_text(encoding="utf-8")


def test_nginx_gives_the_chat_route_its_own_tight_rate_limit_and_a_longer_timeout():
    nginx = (ROOT / "sample_app" / "deploy" / "nginx.conf").read_text(encoding="utf-8")
    assert "zone=chatperip" in nginx and "location = /api/chat" in nginx
    block = nginx.split("location = /api/chat")[1].split("}")[0]
    assert "limit_req  zone=chatperip" in block and "proxy_read_timeout 30s" in block


def test_openai_pin_installs_on_the_ec2_python_3_9():
    """Su co 19/11: ghim openai>=3.55 (doi Python >= 3.10) -> pip loi tren Amazon Linux 2023 (Python 3.9),
    bootstrap dung giua chung, Nginx/web app khong chay. Dong 2.x la dong cuoi con ho tro Python 3.9."""
    import re
    req = (ROOT / "sample_app" / "requirements.txt").read_text(encoding="utf-8")
    line = next(l for l in req.splitlines() if l.startswith("openai"))
    assert re.search(r"<\s*3\b", line), line
