# TÀI LIỆU BÀN GIAO KỸ THUẬT (HANDOVER) — DỰ ÁN LOGSENTINEL
**Từ:** Người A (Cloud Infrastructure & Security Engineer)  
**Đến:** Người B (QA, Documentation & Integration Lead)  
**Trạng thái Hạ tầng & Bảo mật (Phần A):** ĐÃ HOÀN TẤT 100% (`v2.1-soar-complete`)

---

## 1. Những hạng mục Người A đã hoàn thành & kiểm thử
1. **Infrastructure as Code (AWS CDK Python):** Tự động hóa toàn bộ VPC, EC2 Target Web Server (`systemd` tự phục hồi), S3 Log Archive (Lifecycle 30 ngày), KMS Customer Managed Key, DynamoDB `IncidentTable` (bật TTL), CloudWatch Logs (`/logsentinel/sample-app`, `/logsentinel/cloudtrail`), CloudTrail, SNS Email Topic và Secrets Manager.
2. **Bảo mật Ứng dụng & Xác thực 2 lớp (2FA TOTP):** Tích hợp `pyotp` (Google Authenticator QR Code tại `/setup-2fa`) và bảo vệ endpoint `/login`, `/search`.
3. **Engine Phát hiện Bất thường (Lambda Detector):**
   - Phát hiện `SQL_INJECTION`, `MFA_BYPASS_ATTEMPT`, `BRUTE_FORCE_DETECTED` (Stateful tracking >= 5 lần sai/phút).
   - Phát hiện tấn công quản trị AWS CloudTrail (`ConsoleLogin` không MFA, `DeactivateMFADevice`, `StopLogging`).
4. **Cơ chế Phòng vệ Chủ động (SOAR Active Defense / Auto-Remediation):** Tự động khóa IP kẻ tấn công vào DynamoDB (`BLOCKED_IP#<ip>`) trong 24 giờ và chặn trực tiếp ở tầng HTTP Middleware với mã `403 Access Denied by SOAR Active Defense`.

---

## 2. Danh sách Công việc Bàn giao cho Người B (Backlog & Docs)

### Hạng mục 1: Tích hợp Cảnh báo Telegram ChatOps (Tuỳ chọn nâng cao)
- **Hiện trạng:** Người A đã tạo sẵn Secret `logsentinel/telegram_credentials` trên AWS Secrets Manager và cấp quyền đọc (`grant_read`) cho Lambda.
- **Việc cần làm:**
  1. Mở Telegram, nhắn tin cho `@BotFather` -> gõ `/newbot` để lấy `BOT_TOKEN` và lấy `CHAT_ID`.
  2. Cập nhật giá trị thật vào AWS Secrets Manager (`logsentinel/telegram_credentials`).
  3. Bổ sung hàm gửi request HTTP tới `https://api.telegram.org/bot<TOKEN>/sendMessage` trong `lambda_src/detector.py`.

### Hạng mục 2: Truy vấn Log quy mô lớn với Amazon Athena (Tuỳ chọn nâng cao)
- **Hiện trạng:** Toàn bộ log CloudTrail đã được nén và lưu tự động vào S3 `LogArchiveBucket`.
- **Việc cần làm:** Mở Amazon Athena console, tạo bảng trỏ vào S3 `LogArchiveBucket` để chạy các câu lệnh SQL thống kê sự cố phục vụ chụp ảnh báo cáo.

### Hạng mục 3: Hoàn thiện Sơ đồ Kiến trúc & Báo cáo Thuyết trình
1. **Vẽ Sơ đồ Kiến trúc (Draw.io):** Vẽ luồng đi từ EC2 Web App / CloudTrail -> CloudWatch Logs -> Lambda Detector -> DynamoDB (`IncidentTable`) + SNS Email + Cơ chế vòng lặp phản hồi khóa IP (SOAR).
2. **Chụp ảnh Minh chứng (Screenshots):**
   - Giao diện QR Code 2FA (`/setup-2fa`).
   - Kết quả chạy `python attack_suite.py` và `python iam_tamper.py`.
   - Phản hồi chặn IP `403 Access Denied by SOAR Active Defense`.
   - Bảng DynamoDB `IncidentTable` chứa các bản ghi sự cố và `BLOCKED_IP#...`.
   - Email cảnh báo từ AWS SNS.
3. **Viết Báo cáo Word & Slide:** Tổng hợp chi phí (AWS Pricing Calculator ~ $2.15/tháng trong Free Tier) và đóng gói báo cáo cuối kỳ.

---

## 3. Lệnh Thao tác Nhanh cho Người B
```powershell
# 1. Kéo code mới nhất về máy
git pull origin main --tags

# 2. Chạy kiểm thử Unit Test
python -m pytest

# 3. Triển khai hạ tầng lên AWS
cdk deploy --require-approval never

# 4. Chạy kịch bản giả lập tấn công Web & CloudTrail
python attack_suite.py
python iam_tamper.py
