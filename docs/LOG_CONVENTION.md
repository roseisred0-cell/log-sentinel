# Quy ước log LogSentinel (Bước 2 của kế hoạch)

Đây là "hợp đồng" duy nhất giữa web app (A) và Detector (B). Muốn thêm luật mới thì sửa file này trước rồi mới sửa code.

## Log group

| Log group | Ai ghi | Ai đọc | Retention |
|---|---|---|---|
| `/logsentinel/sample-app` | CloudWatch Agent trên EC2 (chỉ quyền ghi vào đúng group này) | Subscription → `AnomalyDetectorLambda` + 1 MetricFilter | 30 ngày |
| `/logsentinel/cloudtrail` | CloudTrail `AccountActivityTrail` (multi-region) | Subscription (lọc 8 eventName) → Lambda + 1 MetricFilter | 30 ngày |
| `/logsentinel/detector` | Lambda Detector (log + metric EMF `LogSentinel/IncidentsDetected`) | Dashboard `LogSentinel-Overview` | 30 ngày |
| `/logsentinel/governance` | Lambda `GovernanceExecutor` (mỗi thao tác phân quyền 1 dòng `op`, `local`, `status`; không ghi token) | Điều tra (EC2 không sửa được) | 30 ngày |

## Bản ghi JSON của web app (mỗi dòng 1 object)

| Trường | Kiểu | Bắt buộc | Ghi chú |
|---|---|---|---|
| `timestamp` | ISO-8601 UTC | có | |
| `source` | string | có | `sample-webapp` (hoặc `attack-sim` khi bơm log giả) |
| `event_type` | enum | có | xem bảng dưới |
| `client_ip` | IPv4/IPv6 | có | Đã qua `resolve_client_ip`: chỉ tin header khi kết nối đến từ Nginx 127.0.0.1 |
| `status_code` | int | có | |
| `path` | string | có | |
| `username` | string ≤ 64 | tùy | |
| `severity` | `CRITICAL` | tùy | Chỉ có ở sự kiện nghiêm trọng. Detector tự quyết mức độ, không lấy theo trường này |
| `payload` | string ≤ 512 | tùy | Chuỗi tấn công SQLi |
| `otp_length` | int | tùy | **Không bao giờ** ghi mã OTP |
| `target_user` | string | tùy | Email người bị tác động (duyệt, nâng/hạ quyền, vô hiệu hóa, đặt lại PIN) |
| `action` | `promote` \| `demote` \| `disable` | tùy | Thao tác phân quyền |
| `request_id` | string | tùy | Mã yêu cầu chờ duyệt |
| `approvers` | list | tùy | Những người đã đồng ý (`cognito:<email>`, `local:admin`) |
| `bootstrap` | bool | tùy | Thực thi trong chế độ khởi tạo (admin nội bộ tự nâng quyền) |
| `auth` | `local` \| `cognito` | tùy | Loại tài khoản đang thao tác |

## `event_type` và phản ứng

| event_type | Sinh ra khi | Detector | SOAR |
|---|---|---|---|
| `FAILED_LOGIN` | Sai user/mật khẩu, hoặc sai setup token | Đếm nguyên tử theo IP, cửa sổ 60s | Đúng lần thứ 5 → `BRUTE_FORCE_DETECTED` (HIGH) + khóa 24h, 1 lần/cửa sổ |
| `MFA_REQUIRED` | Đúng mật khẩu, thiếu OTP | Bỏ qua | — |
| `MFA_BYPASS_ATTEMPT` | Đúng mật khẩu, sai OTP | CRITICAL | Khóa 24h |
| `SQL_INJECTION` | `/search` khớp mẫu SQLi / path traversal | CRITICAL | Khóa 24h |
| `LOGIN_SUCCESS` | Đăng nhập đủ 2 lớp | Bỏ qua | — |
| `NOT_FOUND` | Request tới đường dẫn không tồn tại (404). `path` là đường dẫn được gọi | Đếm theo IP, cửa sổ 60 giây | Đúng lần thứ 30 → `SCAN_DETECTED` (HIGH) + khóa 24 giờ. Web app tự chặn tạm ở cùng ngưỡng |
| `ADMIN_UNBLOCK` | Quản trị gỡ khóa IP trên SOC Console (`unblocked_ip`, `username`) | Bỏ qua (dấu vết kiểm toán) | — |
| `CHAT_QUESTION` | Một câu hỏi gửi trợ lý AI thành công (`username`, `incident_id`, `question_chars`). **Không** ghi nội dung câu hỏi hay câu trả lời | Bỏ qua (dấu vết kiểm toán) | — |
| `PASSWORD_RESET_REQUEST` / `PASSWORD_RESET_DONE` | Người dùng yêu cầu mã / đặt lại mật khẩu qua email (`username` = email; **không** ghi mã hay mật khẩu) | Bỏ qua (dấu vết kiểm toán) | — |
| `REGISTER_REQUEST` / `REGISTER_CONFIRMED` | Người dùng đăng ký / xác nhận email (`username` = email; **không** ghi mật khẩu) | Bỏ qua (dấu vết kiểm toán) | — |
| `MFA_ENABLED` / `MFA_DISABLED` | Người dùng tự bật / tắt 2FA trong Console (`username`) | Bỏ qua (dấu vết kiểm toán) | — |
| `USER_APPROVED` / `USER_REVOKED` | Quản trị duyệt / thu hồi quyền xem (`username` = người làm, `target_user` = email được duyệt) | Bỏ qua (dấu vết kiểm toán) | — |
| `ROLE_REQUEST_CREATED` | Admin tạo yêu cầu nâng/hạ Quản trị hoặc vô hiệu hóa (`action`, `target_user`, `request_id`) | HIGH (email + Telegram báo các admin khác vào bỏ phiếu) | Không khóa IP |
| `ROLE_REQUEST_REJECTED` | Một admin từ chối, yêu cầu bị hủy | Bỏ qua (dấu vết kiểm toán) | — |
| `ADMIN_ROLE_CHANGED` | Nâng hoặc hạ Quản trị đã đủ phiếu và đã thực thi (`approvers`, `bootstrap`) | HIGH | Không khóa IP |
| `USER_DISABLED` | Vô hiệu hóa tài khoản đã đủ phiếu và đã thực thi | HIGH | Không khóa IP |
| `ROLE_CHANGE_FAILED` | Đủ phiếu nhưng Cognito lỗi khi thực thi; yêu cầu vẫn chờ, bấm Đồng ý lại để thử lại | HIGH | Không khóa IP |
| `ADMIN_PIN_LOCKED` | Sai PIN mục Phân quyền lần thứ 5, PIN bị khóa 15 phút (`auth`) | HIGH | Không khóa IP |
| `ADMIN_PIN_RESET` | Một admin xóa PIN của admin khác để người đó đặt lại (`target_user`) | HIGH | Không khóa IP |

Các sự kiện phân quyền không bao giờ khóa IP vì IP nguồn là của chính quản trị viên. Mã PIN không bao giờ được ghi vào log. Danh sách sự kiện Detector cảnh báo nằm ở `GOVERNANCE_EVENTS` trong `lambda_src/detector.py`.

Khi tắt 2FA, người dùng phải nhập lại mật khẩu + OTP; nhập sai ghi `FAILED_LOGIN` với `reason = "Invalid re-authentication"` (5 lần / 60 giây → `BRUTE_FORCE_DETECTED`, khóa IP).

`SQL_INJECTION` có thêm trường `field` (`username` | `email`) khi payload nằm ở ô đăng nhập thay vì ô tìm kiếm.

`FAILED_LOGIN` còn được Detector đếm theo **`username`** (10 lần / 5 phút, chỉ tính các lần từ IP chưa chạm ngưỡng theo IP) → `ACCOUNT_UNDER_ATTACK` (HIGH, không khóa IP). Web app cũng tự chặn tạm 60 giây ngay tại chỗ khi một IP sai lần thứ 5, không chờ Detector.

Mọi dòng log là JSON thuần ASCII (`\uXXXX` cho ký tự khác): dữ liệu do kẻ tấn công nhập không thể tạo ra dòng log thứ hai.

`FAILED_LOGIN` cũng được đếm trên **toàn hệ thống** (hơn 50 lần / 5 phút, bất kể IP hay tài khoản, kể cả IP đã bị khóa) → `LOGIN_FAILURE_SPIKE` (HIGH, không khóa IP).

Đăng nhập tài khoản Cognito dùng lại đúng các sự kiện ở trên: sai mật khẩu → `FAILED_LOGIN` (tính vào luật brute-force), đúng mật khẩu nhưng sai mã TOTP → `MFA_BYPASS_ATTEMPT` (CRITICAL, khóa IP). `LOGIN_SUCCESS` có thêm trường `auth` (`local` | `cognito`) và `role` (`admin` | `viewer` | `pending`).

## Khóa DynamoDB `IncidentTable` (PK `incident_id`, SK `timestamp`)

| PK | SK | Ý nghĩa | TTL |
|---|---|---|---|
| `<uuid4>` | ISO time | Bản ghi sự cố | 30 ngày |
| `BLOCKED_IP#<ip>` | `ACTIVE` | IP đang bị khóa (ghi lại chỉ gia hạn, không sinh item mới) | 24 giờ — web app tự so `ttl > now` |
| `STATE#FAILED_LOGIN#<ip>` | `WINDOW` | Bộ đếm brute-force (`failure_count`, `window_start`) | 120 giây |
| `STATE#FAILED_LOGIN_SLOW#<ip>` | `WINDOW` | Bộ đếm brute-force chậm (20 lần / 1 giờ) | 2 giờ |
| `STATE#FAILED_LOGIN_USER#<username>` | `WINDOW` | Bộ đếm theo tài khoản (10 lần / 5 phút, nhiều IP) | 10 phút |
| `STATE#CONSOLE_LOGIN_FAILED#<ip>` | `WINDOW` | Bộ đếm đăng nhập AWS Console sai (5 lần / 5 phút) | 10 phút |
| `STATE#FAILED_LOGIN_GLOBAL` | `WINDOW` | Bộ đếm Spike toàn hệ thống (hơn 50 lần / 5 phút) | 10 phút |
| `STATE#NOT_FOUND#<ip>` | `WINDOW` | Bộ đếm dò quét (30 lần 404 / 60 giây) | 120 giây |
| `REVOKED_SESSION#<sid>` | `REVOKED` | Phiên Console đã đăng xuất (web app ghi; cookie cũ bị từ chối) | Hết tuổi thọ phiên + 60 giây |
| `REVOKED_SESSION#user:<auth>:<user>` | `REVOKED` | Hủy mọi phiên của một người đăng nhập trước `revoked_at` (sau khi bị nâng/hạ quyền hoặc vô hiệu hóa) | 8 giờ + 60 giây |
| `ADMIN_PIN#<auth>:<user>` | `PIN` | PIN mục Phân quyền: `hash` (scrypt), `salt`, `failures`, `locked_until`. Xóa = đặt lại PIN | Không |
| `CHAT_QUOTA#<auth>:<user>` | `<ngày UTC>` (`2026-11-19`) | Số câu đã hỏi trợ lý AI trong ngày (`count`), tăng có điều kiện `count < CHAT_DAILY_LIMIT`; AI lỗi thì trả lại lượt (giảm có điều kiện `count > 0`). Chỉ có khi bật `chat_model` | 2 ngày |
| `ROLE_REQ#<id>` | `REQ` | Yêu cầu chờ duyệt: `action`, `target_username`, `target_email`, `initiator`, `approvals` (string set), `status` (`pending` \| `executed` \| `rejected` \| `expired` \| `failed`), `created_at`. Hết hạn 24 giờ kiểm tra trong code | 7 ngày (dọn rác) |
| `ROLE_REQ#LOCK#execute` | `LOCK` | Khóa dùng chung để mỗi lần chỉ thực thi một thao tác phân quyền (`expires_at`, tự hết sau 30 giây) | 1 giờ |

EC2 chỉ được ghi đúng các tiền tố `REVOKED_SESSION#`, `ADMIN_PIN#`, `CHAT_QUOTA#` (khi bật trợ lý AI) và xóa `BLOCKED_IP#`, `ADMIN_PIN#`. Chỉ Lambda `GovernanceExecutor` ghi được `ROLE_REQ#` (yêu cầu, phiếu bầu, khóa thực thi); EC2 chỉ đọc. Điều kiện IAM `dynamodb:LeadingKeys`, kiểm tra trong `tests/unit/test_stack_hardening.py`.

Đặt lại PIN của `admin` nội bộ (khi quên PIN):

```powershell
aws dynamodb delete-item --region ap-southeast-1 --table-name <IncidentTable> `
  --key '{"incident_id":{"S":"ADMIN_PIN#local:admin"},"timestamp":{"S":"PIN"}}'
```

GSI `by_type` (PK `record_type`, SK `timestamp`): bản ghi sự cố có `record_type = INCIDENT`, bản ghi khóa có `record_type = BLOCK`, yêu cầu phân quyền có `record_type = ROLE_REQ`. Bộ đếm `STATE#`, PIN và khóa thực thi không có trường này nên không vào index. SOC Console chỉ Query trên index này.

## Lưu trữ dài hạn

Log ứng dụng chỉ nằm ở CloudWatch `/logsentinel/sample-app` (30 ngày; truy vấn bằng CloudWatch Logs Insights). Log CloudTrail: `s3://<LogArchiveBucket>/AWSLogs/`, tự xóa sau 30 ngày, truy vấn bằng Athena.
