"""
Cham diem do manh mat khau (5 muc). Quy tac PHAI giong het static/password-strength.js
(giao dien hien muc de canh bao, may chu chan lai lan nua vi khong the tin trinh duyet).

    evaluate(password, email="") -> 0..4
        0 Rat yeu | 1 Yeu | 2 Trung binh | 3 Manh | 4 Rat manh
    MIN_ACCEPTED_LEVEL: muc thap nhat may chu chap nhan khi dang ky.
"""
import re

LEVELS = ("Rat yeu", "Yeu", "Trung binh", "Manh", "Rat manh")
MIN_ACCEPTED_LEVEL = 2
MIN_LENGTH = 8

COMMON = frozenset((
    "password", "passw0rd", "qwerty", "qwertyuiop", "azerty", "letmein", "welcome", "admin", "administrator",
    "iloveyou", "monkey", "dragon", "master", "football", "baseball", "sunshine", "princess", "shadow",
    "superman", "batman", "trustno", "login", "abc", "abcdef", "abcdefgh", "asdfgh", "asdfghjkl", "zxcvbn",
    "zxcvbnm", "secret", "changeme", "default", "guest", "root", "test", "testing", "hello", "freedom",
    "whatever", "matkhau", "vietnam", "hanoi", "saigon", "anhyeuem", "logsentinel", "aws", "amazon", "cloud",
))

# Ky tu thay the pho bien (p@ssw0rd -> password). Khong gom '1' vi co the la i hoac l.
_LEET = str.maketrans({"@": "a", "0": "o", "3": "e", "$": "s", "5": "s", "7": "t"})


def _has_run(password: str, size: int = 4) -> bool:
    """4 ky tu lien tiep giong nhau (aaaa) hoac tang/giam dan (abcd, 1234, 4321)."""
    s = password.lower()
    for i in range(len(s) - size + 1):
        chunk = s[i:i + size]
        diffs = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(size - 1)}
        if diffs in ({0}, {1}, {-1}):
            return True
    return False


def _is_common(password: str) -> bool:
    lowered = password.lower()
    for candidate in (lowered, lowered.translate(_LEET)):
        core = re.sub(r"[^a-z]+$", "", candidate)  # password123! -> password
        if core in COMMON or candidate in COMMON:
            return True
    return False


def evaluate(password: str, email: str = "") -> int:
    pw = password or ""
    n = len(pw)
    if n < MIN_LENGTH or _is_common(pw):
        return 0

    length_pts = 1 if n < 10 else 2 if n < 12 else 3 if n < 16 else 4 if n < 20 else 5
    # Phan loai theo ASCII de khop voi JavaScript (isalnum/islower cua Python tinh ca chu co dau).
    classes = sum((
        any("a" <= c <= "z" for c in pw),
        any("A" <= c <= "Z" for c in pw),
        any("0" <= c <= "9" for c in pw),
        any(not ("a" <= c <= "z" or "A" <= c <= "Z" or "0" <= c <= "9") for c in pw),
    ))
    total = length_pts + max(classes - 1, 0)
    if _has_run(pw):
        total -= 1
    local = (email or "").split("@")[0].lower()
    if len(local) >= 3 and local in pw.lower():
        total -= 2

    if total <= 2:
        return 0
    return min(total - 2, 4)  # 3->1, 4->2, 5->3, >=6->4 (toi da 4)
