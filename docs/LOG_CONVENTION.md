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

## Khóa DynamoDB `IncidentTable` (PK `incident_id`, SK `timestamp`)

| PK | SK | Ý nghĩa | TTL |
|---|---|---|---|
| `<uuid4>` | ISO time | Bản ghi sự cố | 7 ngày |
| `BLOCKED_IP#<ip>` | `ACTIVE` | IP đang bị khóa (ghi lại chỉ gia hạn, không sinh item mới) | 24 giờ — web app tự so `ttl > now` |
| `STATE#FAILED_LOGIN#<ip>` | `WINDOW` | Bộ đếm brute-force (`failure_count`, `window_start`) | 120 giây |
