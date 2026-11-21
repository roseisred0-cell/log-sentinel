# Lấy lại PIN bằng câu hỏi bảo mật + giao diện đăng nhập — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admin Cognito tự lấy lại PIN mục Phân quyền bằng câu hỏi bảo mật + mật khẩu + mã 2FA; màn hình đăng nhập luôn có đường quay lại; bật 2FA bằng một nút.

**Architecture:** Quy tắc nằm trong `sample_app/admin_governance.py` (lớp `Governance` + hai store), lưu ở bản ghi `ADMIN_PIN#<principal>` / sort key `RECOVERY` nên không đổi IAM. `sample_app/app.py` chỉ xác thực, gọi `identity.reauthenticate`, ghi log. Detector và `incident-text.js` thêm hai sự kiện HIGH. Giao diện sửa trong `console.html` / `console.js`.

**Tech Stack:** Python 3.12, Flask, pytest, DynamoDB (boto3), JS thuần (không framework), Node để test `incident-text.js`.

**Spec:** `docs/superpowers/specs/2026-11-21-pin-recovery-login-ux-design.md`

Chạy test từ `log-sentinel-main/`: `.venv/Scripts/python -m pytest -q`. Hiện tại: 846 passed, 3 xfailed.

## Global Constraints

- Câu hỏi cố định, mã và chữ đúng như sau: `idol` "Thần tượng của bạn là ai?", `parent` "Tên của phụ huynh bạn là gì?", `hometown` "Quê hương của bạn ở đâu?", `sport` "Môn thể thao bạn ưa thích?".
- Chuẩn hóa câu trả lời: bỏ dấu tiếng Việt (`đ`/`Đ` → `d`), chữ thường, gộp khoảng trắng, cắt hai đầu; sau chuẩn hóa dài 2–100 ký tự.
- Băm câu trả lời bằng scrypt như PIN (`_hash_pin`), salt 16 byte riêng.
- Sai câu trả lời 5 lần → khóa 15 phút (dùng lại `PIN_MAX_FAILURES`, `PIN_LOCK_SECONDS`).
- Lấy lại cần đủ: câu trả lời + mật khẩu + mã 2FA. Chỉ admin Cognito.
- Sự kiện mới: `ADMIN_PIN_RECOVERED`, `ADMIN_PIN_RECOVERY_LOCKED`, mức HIGH, không khóa IP.
- Không bao giờ ghi câu trả lời, mật khẩu, mã OTP vào log.
- Tiếng Việt có dấu cho chữ trên giao diện; comment code không dấu (theo code hiện có).

## Review Focus

1. Câu trả lời có dấu / hoa / khoảng trắng lạ ("  Đà   Nẵng ") phải khớp "da nang" → test ở Task 1.
2. PIN đang bị khóa 15 phút (vì quên PIN, đoán sai) vẫn lấy lại được → test ở Task 2.
3. Admin khác đặt lại PIN (`reset_pin`) không được xóa câu hỏi bảo mật → test ở Task 1.
4. Câu trả lời đúng nhưng mật khẩu/OTP sai: không xóa PIN, tính như `FAILED_LOGIN` → test ở Task 2.
5. Body sai kiểu (`answer` là list, chuỗi 500 ký tự, thiếu trường) → `400`, không lỗi 500 → test ở Task 2.

---

### Task 1: Quy tắc câu hỏi bảo mật trong `admin_governance.py`

**Files:**
- Modify: `sample_app/admin_governance.py` (docstring đầu file, lỗi, hằng, hai store, lớp `Governance`)
- Test: `tests/unit/test_pin_recovery.py` (tạo mới)

**Interfaces:**
- Produces:
  - `RECOVERY_QUESTIONS: dict[str, str]` (4 mã → câu hỏi, đúng Global Constraints)
  - `normalize_answer(answer) -> str` — nem `InvalidAnswer` nếu không phải `str` hoặc sau chuẩn hóa ngoài 2–100 ký tự
  - Lỗi mới (kế thừa `GovernanceError`): `InvalidQuestion` (`"invalid_question"`, 400), `InvalidAnswer` (`"invalid_answer"`, 400), `RecoveryNotSet` (`"recovery_not_set"`, 404), `RecoveryLocked` (`"recovery_locked"`, 423), `WrongAnswer(just_locked: bool = False)` (`"wrong_answer"`, 403)
  - `Governance.set_recovery(principal: str, question, answer) -> None` — ghi đè được; `local:` → `LocalAdminRestricted`
  - `Governance.recovery_question(principal: str) -> Optional[str]` — mã câu hỏi hoặc `None`
  - `Governance.check_recovery_answer(principal: str, answer) -> None` — `RecoveryNotSet` / `RecoveryLocked` / `WrongAnswer`; đúng thì xóa bộ đếm
  - `Governance.complete_recovery(principal: str) -> None` — `pin_delete` + `recovery_clear_failures`
  - Store (cả `MemoryGovernanceStore` và `DynamoGovernanceStore`): `recovery_get(principal) -> Optional[dict]` (`question`, `hash`, `salt`, `failures`, `locked_until`), `recovery_put(principal, question, answer_hash, salt) -> None` (đặt `failures=0`, `locked_until=0`), `recovery_fail(principal) -> int`, `recovery_lock(principal, until) -> None`, `recovery_clear_failures(principal) -> None`. Dynamo: key `{"incident_id": "ADMIN_PIN#<principal>", "timestamp": "RECOVERY"}`, hằng `RECOVERY_SK = "RECOVERY"`.

- [ ] **Step 1: Viết test thất bại** trong `tests/unit/test_pin_recovery.py`, dùng `MemoryGovernanceStore` + đồng hồ giả (`clock=lambda: t[0]`):

```python
P = "cognito:rose@x.co"

@pytest.mark.parametrize("raw,norm", [("  Đà   Nẵng ", "da nang"), ("ĐẠT", "dat"), ("Bóng đá", "bong da"),
                                      ("Sơn Tùng M-TP", "son tung m-tp")])
def test_answer_is_normalized(gm, raw, norm):
    assert gm.normalize_answer(raw) == norm

@pytest.mark.parametrize("bad", ["", " ", "a", "x" * 101, None, ["da nang"], 12])
def test_bad_answer_is_refused(gm, bad):
    with pytest.raises(gm.InvalidAnswer):
        gm.normalize_answer(bad)

def test_question_codes_and_text(gm):
    assert gm.RECOVERY_QUESTIONS == {"idol": "Thần tượng của bạn là ai?", "parent": "Tên của phụ huynh bạn là gì?",
                                     "hometown": "Quê hương của bạn ở đâu?", "sport": "Môn thể thao bạn ưa thích?"}

def test_set_then_check_answer_ignores_accents_and_case(g):
    g.set_recovery(P, "hometown", "Đà Nẵng")
    assert g.recovery_question(P) == "hometown"
    g.check_recovery_answer(P, "da nang")           # khong nem

def test_unknown_question_refused(g, gm):            # "pet", "", None
def test_local_admin_cannot_set_recovery(g, gm):     # "local:admin" -> LocalAdminRestricted
def test_check_without_recovery_set(g, gm):          # RecoveryNotSet
def test_five_wrong_answers_lock_fifteen_minutes(g, gm, t):
    # 4 lan WrongAnswer(just_locked=False), lan 5 just_locked=True; dung cau tra loi -> RecoveryLocked;
    # t += 15*60+1 -> dung cau tra loi qua
def test_correct_answer_clears_failures(g, gm):      # 4 sai, 1 dung, 4 sai nua -> chua khoa
def test_complete_recovery_deletes_pin_keeps_question(g):
    # set_pin + set_recovery -> complete_recovery -> has_pin False, recovery_question van "hometown"
def test_reset_by_other_admin_keeps_question(g):
    # reset_pin chi xoa PIN: store.recovery_get(P) van con (goi qua store vi reset_pin can identity)
def test_answer_is_stored_hashed(g):                 # store.recovery_get(P)["hash"] khong chua "da nang"
```

- [ ] **Step 2: Chạy, xác nhận FAIL**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pin_recovery.py -q`
Expected: FAIL (`AttributeError: ... normalize_answer`)

- [ ] **Step 3: Cài đặt** theo Interfaces. Bỏ dấu: `unicodedata.normalize("NFD", s)` bỏ ký tự loại `Mn`, thay `đ`/`Đ` trước; gộp khoảng trắng bằng `" ".join(s.split())`. Dynamo store dùng `update_item` cho fail/lock/clear (theo mẫu `pin_*`), `put_item` không điều kiện cho `recovery_put`. Thêm dòng `ADMIN_PIN#<principal> / "RECOVERY"` vào docstring `DynamoGovernanceStore` và các hàm mới vào docstring đầu file.

- [ ] **Step 4: Chạy, xác nhận PASS** — lệnh trên, rồi cả bộ: `.venv/Scripts/python -m pytest -q` (846+ passed, 3 xfailed)

- [ ] **Step 5: Commit**

```bash
git add sample_app/admin_governance.py tests/unit/test_pin_recovery.py
git commit -m "Phan quyen: cau hoi bao mat de lay lai PIN (quy tac + luu tru)"
```

### Task 2: API đặt câu hỏi và lấy lại PIN trong `app.py`

**Files:**
- Modify: `sample_app/app.py` (khối route `/api/governance*`, khoảng dòng 1150–1200)
- Test: `tests/unit/test_pin_recovery.py` (thêm Seam HTTP, dùng fixture `acct`, `post`, `get`, `GOOD_TOTP`, `STRONG` từ `test_console_accounts` và `cognito_admin`, `gov`, `PIN` từ `test_admin_governance`)

**Interfaces:**
- Consumes: Task 1 (`set_recovery`, `recovery_question`, `check_recovery_answer`, `complete_recovery`, các lỗi).
- Produces (Task 4 dùng):
  - `GET /api/governance` thêm `has_recovery: bool`, `recovery_question: Optional[str]` (mã câu hỏi), `recovery_questions: dict` (= `RECOVERY_QUESTIONS`).
  - `POST /api/governance/recovery` `{question, answer}` — `require_session`, `require_csrf`, `require_role(*_ADMIN_ROLES)`, `require_unlocked`. `200 {"ok": true}`.
  - `POST /api/governance/pin/recover` `{answer, password, code}` — `require_session`, `require_csrf`, `require_role(*_ADMIN_ROLES)`, `require_cognito`; KHÔNG cần mở PIN. Thứ tự: kiểm tra kiểu body (như `/api/mfa/disable`, thiếu/sai kiểu → `400 reauth_required`; `answer` không phải `str` hoặc > 200 ký tự → `400 invalid_answer`) → `check_recovery_answer` (lần sai làm khóa ghi `ADMIN_PIN_RECOVERY_LOCKED` 403) → `identity.reauthenticate` (sai → `failed_login(403, username=..., reason="Invalid re-authentication")`, `403 reauth_failed`) → `complete_recovery`, `session.pop("gov_unlocked_until", None)`, ghi `ADMIN_PIN_RECOVERED` 200 → `200 {"ok": true}`.

- [ ] **Step 1: Viết test thất bại**

```python
def admin_with_recovery(acct):
    csrf = cognito_admin(acct, "rose@x.co")
    post(acct, "/api/governance/pin", {"pin": PIN}, csrf=csrf)
    assert post(acct, "/api/governance/recovery", {"question": "hometown", "answer": "Đà Nẵng"},
                csrf=csrf).status_code == 200
    return csrf

def test_status_shows_question_but_never_the_answer(acct):
    # has_recovery True, recovery_question "hometown", recovery_questions co 4 muc; "Nẵng" khong co trong response

def test_setting_recovery_needs_unlocked_section(acct):   # clock += 11 phut -> 403
def test_forgot_pin_recovered_with_answer_password_otp(acct):
    csrf = admin_with_recovery(acct)
    r = post(acct, "/api/governance/pin/recover", {"answer": "da nang", "password": STRONG, "code": GOOD_TOTP}, csrf=csrf)
    assert r.status_code == 200
    assert gov(acct).get_json()["has_pin"] is False and gov(acct).get_json()["unlocked"] is False
    assert acct.logs()[-1]["event_type"] == "ADMIN_PIN_RECOVERED"
    assert post(acct, "/api/governance/pin", {"pin": OTHER_PIN}, csrf=csrf).status_code == 200

def test_recovery_works_while_pin_is_locked(acct):        # 5 PIN sai (423) roi recover -> 200
def test_wrong_answer_keeps_pin_and_fifth_raises_alert(acct):
    # 5 lan answer sai -> 403 wrong_answer, logs()[-1] ADMIN_PIN_RECOVERY_LOCKED; lan 6 answer dung -> 423 recovery_locked
@pytest.mark.parametrize("password,code", [("wrong-Password-1", GOOD_TOTP), (STRONG, "000000")])
def test_right_answer_wrong_password_or_otp_is_refused_and_counted(acct, password, code):
    # 403 reauth_failed, has_pin van True, logs()[-1]["event_type"] == "FAILED_LOGIN"
@pytest.mark.parametrize("body", [{}, {"answer": "da nang"}, {"answer": "da nang", "password": STRONG},
                                  {"answer": ["x"], "password": STRONG, "code": GOOD_TOTP},
                                  {"answer": "x" * 500, "password": STRONG, "code": GOOD_TOTP}])
def test_malformed_recover_body_is_400(acct, body):
def test_local_admin_cannot_recover(acct):                # local_admin(acct) -> 400 mfa_managed_locally
def test_recovery_secrets_never_logged(acct):             # "Nẵng", "da nang", STRONG, GOOD_TOTP khong co trong str(acct.logs())
```

- [ ] **Step 2: Chạy, xác nhận FAIL** — `.venv/Scripts/python -m pytest tests/unit/test_pin_recovery.py -q` (404 trên route mới)

- [ ] **Step 3: Cài đặt** ba thay đổi theo Interfaces, dùng lại `_governed`, `_governance_error`, `_json`, `failed_login`, `_identity_error_response`, `write_security_log`. Bắt `cognito.IdentityError` khác như `/api/mfa/disable`.

- [ ] **Step 4: Chạy, xác nhận PASS** — file trên rồi cả bộ.

- [ ] **Step 5: Commit**

```bash
git add sample_app/app.py tests/unit/test_pin_recovery.py
git commit -m "Phan quyen: API dat cau hoi bao mat va lay lai PIN (cau tra loi + mat khau + 2FA)"
```

### Task 3: Detector và câu mô tả cho hai sự kiện mới

**Files:**
- Modify: `lambda_src/detector.py:418-419` (`GOVERNANCE_EVENTS`)
- Modify: `sample_app/static/incident-text.js` (sau `RULES.ADMIN_PIN_RESET`)
- Modify: `docs/LOG_CONVENTION.md` (bảng sự kiện cạnh `ADMIN_PIN_RESET`; bảng khóa DynamoDB thêm `ADMIN_PIN#<auth>:<user>` / `RECOVERY`)
- Test: `tests/unit/test_detector_governance.py`, `tests/unit/test_incident_text.py`

**Interfaces:**
- Consumes: tên sự kiện từ Task 2.
- Produces: `RULES.ADMIN_PIN_RECOVERED`, `RULES.ADMIN_PIN_RECOVERY_LOCKED`.

- [ ] **Step 1: Viết test thất bại**
  - `test_detector_governance.py`: thêm `("ADMIN_PIN_RECOVERED", {"auth": "cognito"})`, `("ADMIN_PIN_RECOVERY_LOCKED", {"auth": "cognito"})` vào parametrize của `test_governance_events_become_high_incidents_without_blocking`.
  - `test_incident_text.py`: thêm vào `GOVERNANCE`:
    - `(gov("ADMIN_PIN_RECOVERED", auth="cognito"), "tài khoản a@x.co", "Tự lấy lại PIN mục Phân quyền bằng câu hỏi bảo mật, mật khẩu và mã 2FA. Nếu không phải chủ tài khoản: đổi mật khẩu và kiểm tra điện thoại 2FA.")`
    - `(gov("ADMIN_PIN_RECOVERY_LOCKED", auth="cognito"), "tài khoản a@x.co", "Trả lời sai câu hỏi bảo mật 5 lần khi lấy lại PIN, bị khóa 15 phút. Nếu không phải chủ tài khoản: phiên đăng nhập có thể đã bị chiếm.")`
  - Đổi `assert len(rules) >= 26` thành `>= 28` (comment: 20 luật + 8 sự kiện phân quyền).

- [ ] **Step 2: Chạy, xác nhận FAIL** — `.venv/Scripts/python -m pytest tests/unit/test_detector_governance.py tests/unit/test_incident_text.py -q`

- [ ] **Step 3: Cài đặt** — thêm hai tên vào `GOVERNANCE_EVENTS` (sửa comment phía trên); hai hàm `RULES` theo mẫu `ADMIN_PIN_LOCKED` (subject `"tài khoản " + d.username`); hai dòng bảng trong `LOG_CONVENTION.md`.

- [ ] **Step 4: Chạy, xác nhận PASS** — hai file trên rồi cả bộ.

- [ ] **Step 5: Commit**

```bash
git add lambda_src/detector.py sample_app/static/incident-text.js docs/LOG_CONVENTION.md tests/unit/test_detector_governance.py tests/unit/test_incident_text.py
git commit -m "Detector: canh bao HIGH khi lay lai PIN va khi bi khoa vi sai cau hoi bao mat"
```

### Task 4: Giao diện mục Phân quyền (đặt câu hỏi, "Quên PIN?")

**Files:**
- Modify: `sample_app/templates/console.html` (`#gov-setpin`, `#gov-unlock`, thêm `#gov-recovery-missing`, `#gov-recover`)
- Modify: `sample_app/static/console.js` (hàm `showGovState` và các handler governance)
- Test: `tests/unit/test_pin_recovery.py` (kiểm tra markup + JS theo mẫu `test_locked_section_tells_the_admin_how_many_accounts_are_waiting`)

**Interfaces:**
- Consumes: Task 2 (`has_recovery`, `recovery_question`, `recovery_questions`, hai route).
- Produces: id `gov-setpin-question` (select), `gov-setpin-answer`, `gov-recovery-missing`, `gov-recovery-form`, `gov-forgot-link`, `gov-recover`, `gov-recover-form` (ô `answer`, `password`, `code`), `gov-recover-question`, `gov-recover-back`.

Hành vi:
- Form đặt PIN có select câu hỏi (option lấy từ `recovery_questions`) + ô câu trả lời, bắt buộc. Gửi `/api/governance/pin` rồi `/api/governance/recovery`; recovery lỗi thì hiện lỗi và để `#gov-recovery-missing` hiện.
- Mục đang mở, `has_pin && !has_recovery`: hiện `#gov-recovery-missing` ("Bạn chưa đặt câu hỏi bảo mật — nếu quên PIN sẽ không tự lấy lại được.") với form chọn câu hỏi + câu trả lời.
- `#gov-unlock` có nút `gov-forgot-link` "Quên PIN?" chỉ khi `authKind === "cognito"`. Bấm: nếu `has_recovery` → hiện `#gov-recover` với câu hỏi đã chọn; nếu không → thông báo "Bạn chưa đặt câu hỏi bảo mật. Nhờ một quản trị viên khác đặt lại PIN."
- `#gov-recover`: câu trả lời, mật khẩu, mã OTP (`inputmode="numeric"`, `maxlength="6"`, KHÔNG có `data-digits`/`name="pin"` — test đếm ô PIN giữ là 4), nút "Lấy lại PIN" và "Quay lại". Thành công → tải lại trạng thái (hiện form đặt PIN mới). Thông báo lỗi tiếng Việt cho `wrong_answer`, `recovery_locked`, `reauth_failed`, `invalid_answer`.

- [ ] **Step 1: Viết test thất bại** — `test_console_has_recovery_controls`: html chứa đủ các id ở Produces; js chứa `"/api/governance/recovery"`, `"/api/governance/pin/recover"`, `"recovery_locked"`, `"wrong_answer"`. `test_every_pin_box_in_the_console_accepts_digits_only` (đã có) phải vẫn qua.
- [ ] **Step 2: Chạy, xác nhận FAIL** — `.venv/Scripts/python -m pytest tests/unit/test_pin_recovery.py -q`
- [ ] **Step 3: Cài đặt** theo Hành vi.
- [ ] **Step 4: Chạy, xác nhận PASS** — cả bộ test; rồi chạy app local (`run` skill / `python sample_app/app.py` với Cognito giả nếu có) hoặc kiểm tra bằng trình duyệt headless như ngày 19/11: đặt PIN + câu hỏi → khóa → "Quên PIN?" → lấy lại → đặt PIN mới.
- [ ] **Step 5: Commit**

```bash
git add sample_app/templates/console.html sample_app/static/console.js tests/unit/test_pin_recovery.py
git commit -m "Console: dat cau hoi bao mat va nut Quen PIN trong muc Phan quyen"
```

### Task 5: Giao diện đăng nhập — nút Quay lại, "Bật 2FA ngay"

**Files:**
- Modify: `sample_app/templates/console.html` (`#panel-mfa`, `#panel-confirm`, `#mfa-required-notice`, thêm `#mfa-nudge` đầu `#app-view`)
- Modify: `sample_app/static/console.js` (handler `.back-to-login` dòng ~373, `showApp`, `loadAccount`, handler `mfa-toggle`)
- Test: `tests/unit/test_console_accounts.py` (thêm test markup)

**Interfaces:**
- Produces: nút `class="ghost back-to-login"` trong `#panel-mfa` và `#panel-confirm`; `#mfa-nudge` (chữ "Bạn chưa bật 2FA." + nút `.mfa-now` "Bật ngay"); nút `.mfa-now` trong `#mfa-required-notice`; hàm `openMfaSetup()` trong `console.js`.

Hành vi:
- "Quay lại" ở `panel-mfa` / `panel-confirm` dùng handler `.back-to-login` sẵn có (về `panel-login`); thêm: xóa ô mã và lỗi của panel vừa rời.
- `openMfaSetup()`: hiện `#account-card`, nếu 2FA chưa bật thì chạy đúng nhánh thiết lập của handler `mfa-toggle` (tách nhánh đó ra thành hàm dùng chung), rồi `scrollIntoView` tới `#mfa-setup`. Mọi `.mfa-now` gọi hàm này.
- `#mfa-nudge` hiện khi đăng nhập Cognito, 2FA chưa bật, và không phải admin bắt buộc 2FA (khi đó đã có `#mfa-required-notice`). Trạng thái 2FA lấy từ `loadAccount()` (đã gọi khi vào app); ẩn lại sau khi bật thành công.

- [ ] **Step 1: Viết test thất bại** — `test_every_login_step_has_a_way_back`: trong html, khối `<section id="panel-mfa"…</section>` và `<section id="panel-confirm"…</section>` mỗi khối chứa `back-to-login`. `test_mfa_setup_is_one_click_away`: html có `id="mfa-nudge"` và ít nhất 2 phần tử `mfa-now`; js có `function openMfaSetup` và `scrollIntoView`.
- [ ] **Step 2: Chạy, xác nhận FAIL** — `.venv/Scripts/python -m pytest tests/unit/test_console_accounts.py -q -k "way_back or one_click"`
- [ ] **Step 3: Cài đặt** theo Hành vi.
- [ ] **Step 4: Chạy, xác nhận PASS** — cả bộ test; kiểm tra trình duyệt: đăng nhập tài khoản có 2FA → Quay lại ở bước OTP → đăng nhập lại được; đăng ký → Quay lại ở bước xác nhận email; tài khoản chưa bật 2FA → "Bật ngay" mở thẳng mã QR.
- [ ] **Step 5: Commit**

```bash
git add sample_app/templates/console.html sample_app/static/console.js tests/unit/test_console_accounts.py
git commit -m "Console: nut Quay lai o buoc OTP va xac nhan email, nut Bat 2FA ngay"
```

### Task 6: Tài liệu và nhật ký

**Files:**
- Modify: `docs/SECURITY_REVIEW.md` mục 7 (rủi ro còn lại: câu hỏi bảo mật là yếu tố yếu, được bù bằng mật khẩu + 2FA; kẻ có cả mật khẩu + điện thoại vẫn lấy lại được PIN — PIN không chặn trường hợp đó)
- Modify: `docs/USER_GUIDE.md` (cách đặt câu hỏi, cách lấy lại PIN)
- Create: `docs/NHAT_KY_2026-11-21.md` (việc đã làm, số test, "có hiệu lực sau `cdk deploy`")

- [ ] **Step 1: Viết tài liệu** như trên.
- [ ] **Step 2: Chạy cả bộ test** — `.venv/Scripts/python -m pytest -q`, ghi số test vào nhật ký.
- [ ] **Step 3: Commit**

```bash
git add docs/SECURITY_REVIEW.md docs/USER_GUIDE.md docs/NHAT_KY_2026-11-21.md
git commit -m "Tai lieu: lay lai PIN bang cau hoi bao mat, nut Quay lai, Bat 2FA ngay"
```
