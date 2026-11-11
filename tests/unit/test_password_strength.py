"""Do manh mat khau: quy tac Python (may chu) va JavaScript (giao dien) PHAI cho cung ket qua."""
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "sample_app"
_spec = importlib.util.spec_from_file_location("password_strength_under_test", SRC / "password_strength.py")
ps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ps)

# (mat khau, email, muc mong doi)  0 Rat yeu | 1 Yeu | 2 Trung binh | 3 Manh | 4 Rat manh
VECTORS = [
    ("", "", 0),
    ("short1A", "", 0),                      # < 8 ky tu
    ("password", "", 0),                     # pho bien
    ("Password123!", "", 0),                 # pho bien + duoi so/ky hieu
    ("P@ssw0rd", "", 0),                     # leet cua 'password'
    ("Abcd1234", "", 0),                     # chuoi lien tiep abcd / 1234
    ("aaaaaaaaaaaa", "", 0),                 # lap ky tu
    ("Hello12345", "", 0),                   # 'hello' pho bien
    ("Tuan@2024x", "tuan@example.com", 1),   # chua ten email
    ("Zebra!7x", "", 2),
    ("correcthorsebatterystaple", "", 3),
    ("Zebra!Lamp7", "", 3),
    ("Blue-sky-over-town", "", 4),
    ("Zebra!Lamp7Quiet", "", 4),
    ("Correct-Horse-Battery9", "", 4),
    ("Mật-khẩu-Rất-Dài-2026", "", 4),        # ky tu co dau tinh la ky hieu o ca hai ben
]


@pytest.mark.parametrize("password,email,expected", VECTORS)
def test_python_levels(password, email, expected):
    assert ps.evaluate(password, email) == expected


def test_server_accepts_only_medium_or_better():
    assert ps.MIN_ACCEPTED_LEVEL == 2
    assert ps.evaluate("Hello12345") < ps.MIN_ACCEPTED_LEVEL
    assert ps.evaluate("Zebra!7x") >= ps.MIN_ACCEPTED_LEVEL


@pytest.mark.skipif(shutil.which("node") is None, reason="can Node.js de doi chieu voi JavaScript")
def test_javascript_matches_python():
    script = (
        "const P=require(process.argv[1]);"
        "const v=JSON.parse(process.argv[2]);"
        "console.log(JSON.stringify(v.map(([p,e])=>P.evaluate(p,e).level)));"
    )
    out = subprocess.run(
        ["node", "-e", script, str(SRC / "static" / "password-strength.js"),
         json.dumps([[p, e] for p, e, _ in VECTORS])],
        capture_output=True, text=True, timeout=30, check=True)
    assert json.loads(out.stdout) == [ps.evaluate(p, e) for p, e, _ in VECTORS]
