# Quy ước log LogSentinel (Bước 2 của kế hoạch)

Đây là "hợp đồng" duy nhất giữa web app (A) và Detector (B). Muốn thêm luật mới thì sửa file này trước rồi mới sửa code.

## Log group

| Log group | Ai ghi | Ai đọc | Retention |
|---|---|---|---|
| `/logsentinel/sample-app` | CloudWatch Agent trên EC2 (chỉ quyền ghi vào đúng group này) | Subscription → `AnomalyDetectorLambda` + 1 MetricFilter | 7 ngày |
| `/logsentinel/cloudtrail` | CloudTrail `AccountActivityTrail` (multi-region) | Subscription (lọc 8 eventName) → Lambda + 1 MetricFilter | 7 ngày |
| `/logsentinel/detector` | Lambda Detector (log + metric EMF `LogSentinel/IncidentsDetected`) | Dashboard `LogSentinel-Overview` | 7 ngày |

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
| `severity` | `CRITICAL` | tùy | Chỉ có ở sự kiện nghiêm trọng |
| `payload` | string ≤ 512 | tùy | Chuỗi tấn công SQLi |
| `otp_length` | int | tùy | **Không bao giờ** ghi mã OTP |

## `event_type` và phản ứng

| event_type | Sinh ra khi | Detector | SOAR |
|---|---|---|---|
| `FAILED_LOGIN` | Sai user/mật khẩu, hoặc sai setup token | Đếm nguyên tử theo IP, cửa sổ 60s | Đúng lần thứ 5 → `BRUTE_FORCE_DETECTED` (HIGH) + khóa 24h, 1 lần/cửa sổ |
| `MFA_REQUIRED` | Đúng mật khẩu, thiếu OTP | Bỏ qua | — |
| `MFA_BYPASS_ATTEMPT` | Đúng mật khẩu, sai OTP | CRITICAL | Khóa 24h |
| `SQL_INJECTION` | `/search` khớp mẫu SQLi / path traversal | CRITICAL | Khóa 24h |
| `LOGIN_SUCCESS` | Đăng nhập đủ 2 lớp | Bỏ qua | — |
| `ADMIN_UNBLOCK` | Quản trị gỡ khóa IP trên SOC Console (`unblocked_ip`, `username`) | Bỏ qua (dấu vết kiểm toán) | — |
| `PASSWORD_RESET_REQUEST` / `PASSWORD_RESET_DONE` | Người dùng yêu cầu mã / đặt lại mật khẩu qua email (`username` = email; **không** ghi mã hay mật khẩu) | Bỏ qua (dấu vết kiểm toán) | — |
| `REGISTER_REQUEST` / `REGISTER_CONFIRMED` | Người dùng đăng ký / xác nhận email (`username` = email; **không** ghi mật khẩu) | Bỏ qua (dấu vết kiểm toán) | — |
| `MFA_ENABLED` / `MFA_DISABLED` | Người dùng tự bật / tắt 2FA trong Console (`username`) | Bỏ qua (dấu vết kiểm toán) | — |
| `USER_APPROVED` / `USER_REVOKED` | Quản trị duyệt / thu hồi quyền xem (`username` = người làm, `target_user` = email được duyệt) | Bỏ qua (dấu vết kiểm toán) | — |

Khi tắt 2FA, người dùng phải nhập lại mật khẩu + OTP; nhập sai ghi `FAILED_LOGIN` với `reason = "Invalid re-authentication"` (5 lần / 60 giây → `BRUTE_FORCE_DETECTED`, khóa IP).

`SQL_INJECTION` có thêm trường `field` (`username` | `email`) khi payload nằm ở ô đăng nhập thay vì ô tìm kiếm.

`FAILED_LOGIN` còn được Detector đếm theo **`username`** (10 lần / 5 phút, chỉ tính các lần từ IP chưa chạm ngưỡng theo IP) → `ACCOUNT_UNDER_ATTACK` (HIGH, không khóa IP). Web app cũng tự chặn tạm 60 giây ngay tại chỗ khi một IP sai lần thứ 5, không chờ Detector.

Mọi dòng log là JSON thuần ASCII (`\uXXXX` cho ký tự khác): dữ liệu do kẻ tấn công nhập không thể tạo ra dòng log thứ hai.

Đăng nhập tài khoản Cognito dùng lại đúng các sự kiện ở trên: sai mật khẩu → `FAILED_LOGIN` (tính vào luật brute-force), đúng mật khẩu nhưng sai mã TOTP → `MFA_BYPASS_ATTEMPT` (CRITICAL, khóa IP). `LOGIN_SUCCESS` có thêm trường `auth` (`local` | `cognito`) và `role` (`admin` | `viewer` | `pending`).

## Khóa DynamoDB `IncidentTable` (PK `incident_id`, SK `timestamp`)

| PK | SK | Ý nghĩa | TTL |
|---|---|---|---|
| `<uuid4>` | ISO time | Bản ghi sự cố | 7 ngày |
| `BLOCKED_IP#<ip>` | `ACTIVE` | IP đang bị khóa (ghi lại chỉ gia hạn, không sinh item mới) | 24 giờ — web app tự so `ttl > now` |
| `STATE#FAILED_LOGIN#<ip>` | `WINDOW` | Bộ đếm brute-force (`failure_count`, `window_start`) | 120 giây |
| `STATE#FAILED_LOGIN_SLOW#<ip>` | `WINDOW` | Bộ đếm brute-force chậm (20 lần / 1 giờ) | 2 giờ |
| `STATE#FAILED_LOGIN_USER#<username>` | `WINDOW` | Bộ đếm theo tài khoản (10 lần / 5 phút, nhiều IP) | 10 phút |
| `STATE#CONSOLE_LOGIN_FAILED#<ip>` | `WINDOW` | Bộ đếm đăng nhập AWS Console sai (5 lần / 5 phút) | 10 phút |
| `REVOKED_SESSION#<sid>` | `REVOKED` | Phiên Console đã đăng xuất (web app ghi; cookie cũ bị từ chối) | Hết tuổi thọ phiên + 60 giây |

GSI `by_type` (PK `record_type`, SK `timestamp`): bản ghi sự cố có `record_type = INCIDENT`, bản ghi khóa có `record_type = BLOCK`, bộ đếm `STATE#` không có trường này nên không vào index. SOC Console chỉ Query trên index này.

## Lưu trữ dài hạn

Log ứng dụng: `/logsentinel/sample-app` → Firehose → `s3://<LogArchiveBucket>/app-logs/yyyy/MM/dd/` (mỗi bản ghi là 1 khối gzip của CloudWatch Logs; giải nén bằng `gzip -d`). Log CloudTrail: `AWSLogs/`. Cả hai tự xóa sau 30 ngày.
