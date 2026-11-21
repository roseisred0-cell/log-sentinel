"""Bao mat may EC2 (nhat ky 12/11 muc 4.D): sandbox systemd, tu va loi bao mat, gioi han ket noi ra.

Muc tieu: loi trong web app kho leo thang thanh chiem ca may, va may bi chiem kho mo kenh dieu khien ra ngoai.
Seam: file deploy (systemd unit, bootstrap.sh) va template CDK. Kiem tra tren may that: `systemd-analyze security webapp`.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UNIT = (ROOT / "sample_app" / "deploy" / "webapp.service").read_text(encoding="utf-8")
BOOTSTRAP = (ROOT / "sample_app" / "deploy" / "bootstrap.sh").read_text(encoding="utf-8")


def _directive(name: str):
    m = re.search(rf"^{name}=(.*)$", UNIT, re.M)
    return m.group(1).strip() if m else None


# ------------------------------------------------------- D2: sandbox systemd
@pytest.mark.parametrize("name,value", [
    ("CapabilityBoundingSet", ""),            # khong giu capability nao (app chay user thuong, cong 8080)
    ("AmbientCapabilities", ""),
    ("NoNewPrivileges", "true"),
    ("ProtectSystem", "strict"),
    ("ProtectHome", "true"),
    ("PrivateTmp", "true"),
    ("PrivateDevices", "true"),
    ("ProtectKernelTunables", "true"),
    ("ProtectKernelModules", "true"),
    ("ProtectKernelLogs", "true"),
    ("ProtectControlGroups", "true"),
    ("ProtectClock", "true"),
    ("ProtectHostname", "true"),
    ("ProtectProc", "invisible"),             # khong thay tien trinh khac (vd CloudWatch Agent, SSM Agent)
    ("RestrictSUIDSGID", "true"),
    ("RestrictNamespaces", "true"),
    ("RestrictRealtime", "true"),
    ("LockPersonality", "true"),
    ("MemoryDenyWriteExecute", "true"),       # chan nap shellcode vao vung nho vua ghi vua chay
    ("SystemCallArchitectures", "native"),
    ("SystemCallFilter", "@system-service"),
    ("RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX"),
    ("ReadWritePaths", "/var/log/webapp"),    # chi ghi duoc thu muc log
])
def test_webapp_service_is_sandboxed(name, value):
    assert _directive(name) == value, f"{name}={_directive(name)!r}"


def test_webapp_still_runs_as_unprivileged_user():
    assert _directive("User") == "webapp" and _directive("Group") == "webapp"


# --------------------------------------------------- D3: tu va loi bao mat
def test_security_updates_install_automatically():
    assert re.search(r"dnf install -y [^\n]*\bdnf-automatic\b", BOOTSTRAP)
    assert "upgrade_type = security" in BOOTSTRAP and "apply_updates = yes" in BOOTSTRAP
    assert "systemctl enable --now dnf-automatic.timer" in BOOTSTRAP


def test_amazon_linux_2023_tracks_the_latest_release_so_updates_exist():
    """AL2023 khoa phien ban kho goi theo AMI: khong theo 'latest' thi dnf-automatic khong thay ban va moi."""
    assert "echo latest > /etc/dnf/vars/releasever" in BOOTSTRAP


# ----------------------------------------------- D4: gioi han ket noi ra
@pytest.fixture(scope="module")
def template():
    aws_cdk = pytest.importorskip("aws_cdk")
    from aws_cdk import assertions
    from log_sentinel.log_sentinel_stack import LogSentinelStack
    app = aws_cdk.App(context={"alert_email": "ops@example.com"})
    return assertions.Template.from_stack(
        LogSentinelStack(app, "ec2-hardening", env=aws_cdk.Environment(account="123456789012", region="ap-southeast-1")))


def _vm_egress(template):
    groups = template.find_resources("AWS::EC2::SecurityGroup")
    sg = next(v for k, v in groups.items() if k.startswith("TargetVmSecurityGroup"))
    return sg["Properties"].get("SecurityGroupEgress", [])


def test_vm_may_only_connect_out_on_https(template):
    """AWS API, SSM, CloudWatch, kho goi dnf/pip deu qua 443. DNS / NTP / IMDS cua AWS khong qua security group."""
    egress = _vm_egress(template)
    assert egress, "thieu luat egress (CDK mac dinh mo tat ca khi allow_all_outbound=True)"
    assert all(e["IpProtocol"] == "tcp" and e["FromPort"] == e["ToPort"] == 443 for e in egress), egress
    assert not any(e.get("IpProtocol") == "-1" for e in egress)
