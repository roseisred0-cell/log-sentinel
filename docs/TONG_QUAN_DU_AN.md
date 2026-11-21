# LogSentinel — Tổng hợp dự án

> Hệ thống giám sát log tập trung (SIEM) và phản ứng tự động (SOAR) trên AWS. Đồ án tốt nghiệp AWS First Cloud AI Journey (FCAJ 2026).
> Tài liệu tổng hợp tình trạng đến **12/11/2026**. Số liệu lấy từ code và từ AWS tại thời điểm đó; chi tiết từng mảng nằm ở các tài liệu trong mục 13.

## 1. Dự án là gì

LogSentinel nhìn vào hai nguồn log, phát hiện hành vi bất thường, **tự khóa IP kẻ tấn công** và báo cho người quản trị qua email, Telegram và một giao diện web (SOC Console).

| Nguồn log | Phát hiện được |
|---|---|
| Log của web app (đăng nhập, tìm kiếm, 404) | Đoán mật khẩu, SQL injection, vượt 2FA, dò quét đường dẫn, tấn công hàng loạt |
| CloudTrail (hoạt động của tài khoản AWS) | Đăng nhập root, đăng nhập Console không MFA, gỡ MFA, tắt CloudTrail, vô hiệu hóa khóa KMS, leo thang quyền IAM |

**Đối tượng hướng tới:** doanh nghiệp nhỏ và vừa không có đội SOC riêng. Họ cần biết khi nào bị tấn công mà không phải đọc log thô, và cần hệ thống tự chặn ngay.

**Phân công trong nhóm:** Người A làm hạ tầng và bảo mật (CDK, EC2, CloudTrail); Người B làm phát hiện và SOC (Detector, Telegram, Athena, SOC Console); Người C làm báo cáo, biểu đồ và đối chiếu chi phí.

## 2. Trạng thái hiện tại

| Hạng mục | Trạng thái |
|---|---|
| Hệ thống trên AWS (Singapore `ap-southeast-1`) | **Đã deploy chế độ edge 12/11**: CloudFront + WAF + IP tĩnh `54.251.156.153`. Console: `https://d3szfuj6lp4t8m.cloudfront.net/console` (chứng chỉ thật, không còn cảnh báo). Phát hiện brute-force đã kiểm chứng trên AWS (11/11) |
| Kiểm thử tự động | **737 test qua, 3 xfail** (3 điểm yếu đã biết, ghi lại có chủ đích) |
| Mã nguồn | Repo local `d:\ki6\AWS-project` (4 commit) và nhánh `b/telegram-detection` trên GitHub của nhóm. `main` của nhóm chưa bị đụng |
| Máy EC2 | Được Stop/Start hằng ngày để tiết kiệm. Dịch vụ tự chạy lại, mật khẩu và khóa 2FA giữ nguyên. IP tĩnh nên địa chỉ không đổi (đã thử 12/11, CloudFront vào lại sau 10 giây) |
| Chi phí | Tài khoản ở **gói Free**: tiền thực trả hiện là 0 USD, tín dụng còn khoảng 199 USD, hết hạn 23/3/2027 (kiểm tra ngày 12/11) |

## 3. Kiến trúc

```
Internet ──443──> Nginx (TLS, giới hạn tốc độ, ghi đè X-Forwarded-For)
                    └─> Gunicorn 127.0.0.1:8080 (Flask: web mẫu + SOC Console)
                          └─ access.log ─> CloudWatch Agent ─> /logsentinel/sample-app ─┐
CloudTrail (đa region, mã hóa KMS) ─> S3 + /logsentinel/cloudtrail ────────────────────┤
                                                                                       v
                                     AnomalyDetectorLambda ─> DynamoDB IncidentTable (KMS, TTL 30 ngày)
                                            │                   └─ BLOCKED_IP#<ip> ─> web app trả 403
                                            └─> SNS email + Telegram + metric CloudWatch (EMF)

Người dùng Console ─ Cognito (đăng ký, mật khẩu, 2FA TOTP, nhóm vai trò)
S3 LogArchiveBucket ─ Glue (bảng cloudtrail_logs) ─ Athena (workgroup logsentinel)
```

**Chế độ edge (tùy chọn):** Internet → CloudFront + AWS WAF → máy EC2 (cổng 80, chỉ nhận từ CloudFront). Lambda `waf_sync` chạy mỗi phút, đẩy danh sách IP bị khóa lên WAF để chặn ngay tại biên.

### Ba lớp chặn IP

1. **Tại chỗ (web app):** chặn tạm 60 giây ngay khi một IP sai mật khẩu lần thứ 5 hoặc gặp 404 lần thứ 30, không chờ Lambda.
2. **Detector (Lambda):** ghi `BLOCKED_IP#<ip>` vào DynamoDB, khóa 24 giờ. Web app kiểm tra bảng này mỗi request (có cache trong RAM).
3. **WAF (chế độ edge):** IP bị khóa không còn tới được máy.

IP trong `admin_cidr` không bao giờ bị khóa (chống tự khóa mình khi demo).

## 4. Tài nguyên AWS

| Thành phần | Dịch vụ | Ghi chú |
|---|---|---|
| Web mẫu + SOC Console | EC2 `t3.micro`, Amazon Linux 2023 | IMDSv2 bắt buộc, EBS mã hóa, quản trị qua SSM (không mở cổng 22) |
| Detector | Lambda Python 3.12 | Đăng ký (subscription) vào hai log group |
| Sự cố và IP bị khóa | DynamoDB `IncidentTable` | Chỉ số `by_type`, mã hóa CMK, TTL |
| Log | CloudWatch Logs | 3 nhóm: `/logsentinel/sample-app`, `/cloudtrail`, `/detector`; lưu **30 ngày** |
| Kiểm toán AWS | CloudTrail | Đa region, kiểm tra toàn vẹn file, ghi vào S3 và CloudWatch |
| Lưu trữ | S3 `LogArchiveBucket` | Vòng đời 30 ngày |
| Phân quyền admin | Lambda `GovernanceExecutor` | Nơi duy nhất được đổi nhóm Cognito và ghi phiếu bầu |
| Mã hóa | KMS (1 khóa CMK) | Cho bảng sự cố và log CloudTrail |
| Bí mật | Secrets Manager | `logsentinel/telegram_credentials` (`BOT_TOKEN`, `CHAT_ID`) |
| Cảnh báo | SNS (email), Telegram, 3 CloudWatch Alarm, 1 dashboard | |
| Người dùng Console | Cognito User Pool | Nhóm `soc-viewers`, `soc-admins`; 2FA TOTP tùy chọn |
| Truy vấn log | Glue + Athena | Bảng `cloudtrail_logs`, trần 1 GB mỗi truy vấn, 5 truy vấn mẫu |
| Chi phí | AWS Budgets | Cảnh báo email, mặc định 20 USD/tháng (cần `alert_email`) |
| Biên (edge) | CloudFront, WAF (`us-east-1`), Lambda `waf_sync`, EventBridge, Elastic IP | Đã deploy 12/11 |

## 5. Phát hiện tấn công: 20 luật

Mọi luật ghi sự cố vào DynamoDB, gửi email SNS, Telegram và metric lên dashboard. "Khóa" nghĩa là đồng thời khóa IP 24 giờ.

### Từ log web app (7 luật)

| Luật | Điều kiện | Mức | Khóa IP |
|---|---|---|---|
| `BRUTE_FORCE_DETECTED` | 1 IP sai mật khẩu 5 lần / 60 giây | HIGH | Có |
| `SLOW_BRUTE_FORCE` | 1 IP sai 20 lần / 1 giờ (đoán chậm để né luật trên) | HIGH | Có |
| `ACCOUNT_UNDER_ATTACK` | 1 tài khoản bị sai 10 lần / 5 phút từ nhiều IP | HIGH | Không |
| `LOGIN_FAILURE_SPIKE` | Hơn 50 lần đăng nhập sai toàn hệ thống / 5 phút | HIGH | Không |
| `SCAN_DETECTED` | 1 IP gọi 30 đường dẫn không tồn tại (404) / 60 giây | HIGH | Có |
| `SQL_INJECTION` | Payload SQLi hoặc path traversal ở ô tìm kiếm hoặc ô đăng nhập | CRITICAL | Có |
| `MFA_BYPASS_ATTEMPT` | Đúng mật khẩu nhưng sai mã OTP | CRITICAL | Có |

### Từ CloudTrail (13 luật, không khóa IP vì IP nguồn có thể là dịch vụ AWS)

| Luật | Điều kiện | Mức |
|---|---|---|
| `ROOT_ACCOUNT_LOGIN` | Đăng nhập (kể cả thất bại) bằng tài khoản root | CRITICAL |
| `CONSOLE_LOGIN_NO_MFA` | Đăng nhập AWS Console **thành công** không dùng MFA | HIGH |
| `CONSOLE_BRUTE_FORCE` | 1 IP đăng nhập AWS Console sai 5 lần / 5 phút | HIGH |
| `MFA_TAMPERING` | Gỡ hoặc xóa thiết bị MFA | CRITICAL |
| `CLOUDTRAIL_TAMPERING` | `StopLogging` hoặc `DeleteTrail` | CRITICAL |
| `KMS_KEY_TAMPERING` | Vô hiệu hóa hoặc hẹn xóa khóa KMS | CRITICAL |
| `IAM_ACCESS_KEY_CREATED` | Tạo access key | HIGH |
| `IAM_POLICY_ATTACHED` | Gắn policy cho user, role hoặc group (CRITICAL nếu là `AdministratorAccess`) | HIGH |
| `IAM_INLINE_POLICY_PUT` | Ghi inline policy cho user, role hoặc group | HIGH |
| `IAM_POLICY_VERSION_CREATED` | Sửa nội dung policy đang dùng | HIGH |
| `IAM_TRUST_POLICY_CHANGED` | Sửa trust policy của role | HIGH |
| `IAM_LOGIN_PROFILE_CHANGED` | Đặt hoặc đổi mật khẩu Console của một user | HIGH |
| `IAM_USER_ADDED_TO_GROUP` | Thêm user vào nhóm | HIGH |

Sự cố IAM kèm nhãn `via_service: cloudformation.amazonaws.com` nghĩa là thay đổi đến từ một lần `cdk deploy`. Cố ý không bỏ qua loại này, vì CloudFormation cũng là một đường leo thang quyền quen thuộc.

### Bộ lọc SQL injection
Chuẩn hóa đầu vào trước khi so mẫu (giải mã URL tới 3 vòng, NFKC, bỏ ký tự vô hình), rồi so khoảng 20 mẫu. Đợt red-team đo được: 0/41 kiểu né lọt (trước đó 24/41 lọt), 0/28 câu tìm kiếm bình thường bị chặn nhầm. Đây là lớp phát hiện, **không thay được** truy vấn tham số hóa trong ứng dụng thật.

### Tin Telegram
Định dạng HTML gọn cho điện thoại: biểu tượng mức độ, IP và tài khoản đặt trong thẻ sao chép được. Mọi giá trị do kẻ tấn công nhập đều được escape. Tin quá dài thì gửi bản văn bản thường thay vì cắt ngang thẻ.

## 6. SOC Console

Địa chỉ: `https://<IP>/console` (lấy từ output `SocConsoleUrl`; địa chỉ đổi khi Stop/Start máy). Trình duyệt hiện cảnh báo "Không bảo mật" vì chứng chỉ tự ký; chỉ hết khi dùng chế độ edge.

### Đăng nhập
- **Tài khoản `admin` nội bộ** (dự phòng): mật khẩu và khóa 2FA nằm trong `/etc/logsentinel/webapp.env` trên máy, lấy qua SSM. 2FA bắt buộc.
- **Tài khoản Cognito:** tự đăng ký, xác nhận email, đăng nhập. 2FA tùy chọn.

### Tài khoản người dùng
- **Đăng ký** có thanh độ mạnh mật khẩu 5 mức (Rất yếu → Rất mạnh). Máy chủ chặn dưới mức *Trung bình*, kiểm tra lại độc lập với trình duyệt.
- **Quên mật khẩu** qua mã email.
- **2FA TOTP:** người dùng tự bật; muốn tắt phải nhập lại mật khẩu và mã OTP hiện tại.
- **Vai trò:** *Chờ duyệt* (chưa xem được dữ liệu) → *Người xem* (chỉ xem) → *Quản trị* (xem, gỡ khóa IP, mục Phân quyền; **bắt buộc 2FA**). Người mới đăng ký phải được admin duyệt, nếu không ai trên Internet cũng đăng ký rồi xem được sự cố.
- **Phiên:** Cognito tối đa 30 phút, `admin` nội bộ tối đa 8 giờ. Đăng xuất thu hồi phiên ngay trên máy chủ, nên cookie bị đánh cắp không dùng lại được.

### Màn hình
Bốn ô số (tổng sự cố, CRITICAL, HIGH, IP đang bị khóa), bảng IP đang bị khóa kèm nút **Gỡ khóa**, bảng 50 sự cố gần nhất có lọc theo mức độ, mục **Phân quyền** dành cho admin, mục Tài khoản (bật/tắt 2FA). Tự làm mới mỗi 15 giây.

### Mục Phân quyền (xây 12/11, `sample_app/admin_governance.py`)
- PIN riêng 6 số (chặn mã dễ đoán, băm scrypt), mở 10 phút; sai 5 lần khóa 15 phút + cảnh báo `ADMIN_PIN_LOCKED`.
- Duyệt / thu hồi Người xem: một admin. Nâng / hạ Quản trị: **đa số** trên tất cả admin, tối thiểu 2 phiếu, người bị hạ không bỏ phiếu. Vô hiệu hóa: 2 người. Một phiếu từ chối hủy yêu cầu; yêu cầu hết hạn 24 giờ.
- Luôn tối thiểu 2 admin Cognito. **Chế độ khởi tạo** (dưới 2): `admin` nội bộ được tự nâng một Người xem lên Quản trị; đủ 2 thì chỉ còn xem và gỡ khóa IP.
- Mọi thay đổi chạy trong **Lambda `GovernanceExecutor`**, Lambda tự xác minh người bấm bằng token Cognito; EC2 không còn quyền ghi vào Cognito.
- Thay đổi có hiệu lực ngay: người bị tác động bị đăng xuất mọi phiên. Mọi thao tác sinh cảnh báo HIGH qua email/Telegram, không khóa IP.
- Chi tiết: [USER_GUIDE.md](USER_GUIDE.md) mục Phân quyền, [SECURITY_REVIEW.md](SECURITY_REVIEW.md) mục 6f.

### Bảo mật của Console
Cookie phiên `Secure`, `HttpOnly`, `SameSite=Strict`; token CSRF cho mọi thao tác ghi; CSP `default-src 'self'`; mọi dữ liệu hiển thị chèn bằng `textContent` (payload tấn công không chạy được trong trình duyệt của admin).

## 7. Athena (truy vấn log CloudTrail)

Bảng `cloudtrail_logs` tự nhận ngày và region mới (partition projection), không cần chạy lệnh thêm phân vùng. Workgroup `logsentinel` chặn mỗi truy vấn ở **1 GB** dữ liệu quét (khoảng 0,005 USD). Có 5 truy vấn mẫu: sự cố theo ngày, top hành động, đăng nhập Console thất bại theo IP, thay đổi IAM, lời gọi API bị từ chối. Policy `LogSentinel-AthenaAnalyst` cho người làm báo cáo quyền chỉ đọc; không sửa hay xóa được log.

**Chưa kiểm chứng:** chưa chạy truy vấn nào trên dữ liệu thật.

## 8. Tham số triển khai

| Tham số (`-c`) | Tác dụng | Mặc định |
|---|---|---|
| `alert_email` | Email nhận cảnh báo SNS và cảnh báo chi phí. **Phải bấm xác nhận** trong email AWS gửi | Trống |
| `admin_cidr` | IP quản trị, không bao giờ bị SOAR khóa | Trống |
| `ingress_cidr` | Ai được vào cổng 443 | `0.0.0.0/0` |
| `enable_edge` | Bật CloudFront + WAF | Tắt |
| `console_cidrs` | Chỉ các dải này vào được Console (luật WAF, cần edge) | Trống |
| `monthly_budget_usd` | Ngưỡng cảnh báo chi phí (`0` để tắt) | 20 |
| `detector_max_concurrency` | Trần số Lambda chạy song song | Tắt (tài khoản mới không đủ quota) |
| `chat_model` | Bật trợ lý AI trong Console (OpenAI) với model này. Sau deploy phải tự đặt API key vào secret `logsentinel/openai_api_key` | Tắt |
| `chat_daily_limit` | Số câu hỏi trợ lý AI tối đa mỗi người mỗi ngày | 30 |

### Triển khai

```powershell
cd d:\ki6\AWS-project\log-sentinel-main
.\.venv\Scripts\Activate.ps1
python -m pytest -q
cdk diff   -c alert_email=<email> -c admin_cidr=<ip>/32
cdk deploy --require-approval never -c alert_email=<email> -c admin_cidr=<ip>/32
```

Lấy mật khẩu và khóa 2FA của `admin` (trong phiên SSM, dấu nhắc `sh-5.2$`): `sudo cat /etc/logsentinel/webapp.env`. Nâng tài khoản Cognito đầu tiên lên quản trị: `aws cognito-idp admin-add-user-to-group --user-pool-id <UserPoolId> --username <email> --group-name soc-admins`.

**Khi `cdk deploy` thay máy EC2:** IP đổi, mật khẩu và khóa 2FA của `admin` nội bộ sinh lại.

### Stop/Start hằng ngày
```powershell
aws ec2 stop-instances  --region ap-southeast-1 --instance-ids <id>
aws ec2 start-instances --region ap-southeast-1 --instance-ids <id>
```
Dịch vụ tự chạy lại sau 1–2 phút. Phần giám sát CloudTrail và cảnh báo chạy ở Lambda nên vẫn hoạt động khi máy tắt.

## 9. Kiểm thử

```powershell
python -m pytest -q                                          # toàn bộ: 737 passed, 3 xfailed
python -m pytest tests/unit/test_redteam_scenarios.py -v     # kịch bản tấn công
python attack_sim.py http --target https://<IP> --insecure   # tấn công thật vào hệ thống trên AWS
python attack_sim.py logs                                    # bơm log giả vào CloudWatch
python iam_tamper.py                                         # sự kiện CloudTrail giả (không đổi IAM thật)
```

Chạy các bước tấn công từ **mạng khác** với `admin_cidr` (ví dụ 4G), vì IP trong `admin_cidr` không bao giờ bị khóa.

| Nhóm test | Nội dung |
|---|---|
| Detector (`test_detector_*`) | Bộ đếm brute-force nguyên tử, khóa IP, Telegram, luật CloudTrail, Spike và dò quét |
| Web app (`test_sample_app`, `test_console_accounts`, `test_cognito_identity`, `test_password_strength`) | Chống giả mạo IP, 2FA, đăng ký, vai trò, đăng xuất thu hồi phiên, độ mạnh mật khẩu (Python và JS cho cùng kết quả) |
| Hạ tầng (`test_stack_hardening`, `test_edge_mode`, `test_alarms_b`, `test_log_sentinel_stack`) | IAM tối thiểu, mã hóa, Cognito, Athena, chế độ edge, WAF, lưu 30 ngày |
| Phân quyền (`test_admin_governance`, `test_governance_store`, `test_detector_governance`) | PIN, bỏ phiếu, chế độ khởi tạo, tối thiểu 2 admin, khóa thực thi, store DynamoDB trên `moto` |
| Red-team (`test_redteam_scenarios`) | Khoảng 190 kịch bản tấn công chạy offline, chia theo mục tiêu của kẻ tấn công |

Quy trình viết code từ 11/11: viết test trước, thấy đỏ rồi mới viết code (kỹ năng `tdd`), review hai trục sau khi xong (kỹ năng `code-review`). Review lần gần nhất tìm ra và đã sửa một lỗi thật: bộ đếm Spike không cộng đủ lần sai từ IP đã chạm ngưỡng brute-force.

**Chưa kiểm chứng trên AWS thật:** đăng ký, 2FA, quên mật khẩu, dò quét, Athena, `iam_tamper.py`, gỡ khóa. Cấu hình Nginx chưa chạy `nginx -t`. Chế độ edge chưa deploy lần nào.

## 10. Chi phí

Theo [COST.md](COST.md), ước tính theo giá niêm yết Singapore, cần đối chiếu lại bằng AWS Pricing Calculator.

| Cách chạy | USD/tháng |
|---|---|
| Chế độ trực tiếp, máy bật 24/7 | khoảng 17 |
| Chế độ trực tiếp, chỉ bật khoảng 8 giờ/ngày | khoảng 7–8 |
| Thêm IP tĩnh (Elastic IP, tính cả lúc máy tắt) | cộng khoảng 3,6 |
| Chế độ edge (có WAF) | khoảng 28–30 |
| Hướng mở rộng 2 AZ | khoảng 70 |

Mục tiêu "dưới 5 USD" trong tài liệu bàn giao chỉ đúng khi còn Free Tier cho EC2 và chưa tính phí IP công cộng. Chi phí thực trả hiện là 0 USD nhờ tín dụng của gói Free; **sau 23/3/2027 (hoặc khi tín dụng hết) cần nâng gói hoặc tài khoản bị đóng** (điểm này chưa xác minh, xem trang Billing). Hệ thống 2 AZ sẽ hết tín dụng sau khoảng 2,8 tháng.

Gói Free cũng là lý do Firehose, Bedrock (model Claude) và đăng ký tên miền qua Route 53 bị từ chối. Firehose và trợ lý AI trên Bedrock đã được gỡ khỏi code ngày 12/11 cho gọn; log web app truy vấn trong 30 ngày bằng CloudWatch Logs Insights.

## 11. Đánh giá thẳng thắn về tính ứng dụng

**Dùng tốt cho:**
- Đồ án và portfolio: có hạ tầng dạng code, hơn 500 test, mô hình đe dọa và danh sách rủi ro tự khai báo.
- Giám sát tài khoản AWS nhỏ: phần CloudTrail → cảnh báo dùng ngay, không cần sửa gì, chi phí vài đô mỗi tháng.

**Chưa dùng được cho khách hàng thật:**
1. **Chưa là plugin.** Hệ thống chỉ giám sát ứng dụng mẫu của chính nó. Log group bị gắn cứng, việc kiểm tra IP bị khóa nằm trong code ứng dụng mẫu, chưa có thư viện hay agent cho web của khách, chưa có chế độ "chỉ cảnh báo, không chặn". Đây là rào cản lớn nhất để thương mại hóa.
2. **Mỗi doanh nghiệp cần một lần deploy riêng.** Chưa có đa khách hàng (multi-tenant): một Console là một kho log chung cho mọi người được duyệt.
3. **Console chạy chung máy với ứng dụng bị tấn công**, và chỉ có một máy, không dự phòng.
4. **AWS đã có dịch vụ làm việc tương tự tốt hơn** (GuardDuty, WAF managed rules, Security Hub) với hàng nghìn luật được cập nhật liên tục. Giá trị riêng của LogSentinel là gói gọn đơn giản cho SME, tự khóa IP, chi phí thấp.
5. **Bộ lọc SQL injection là danh sách mẫu**, không phân tích cú pháp; payload mới vẫn có thể lọt.

## 12. Điểm yếu còn lại

Ba điểm sau có test `xfail(strict)` trong nhóm G của bộ red-team; khi ai đó vá xong, test sẽ báo.

1. **Cạn hạn mức email:** khoảng 50 IP đăng ký giả là hết hạn mức email mặc định của Cognito (khoảng 50 thư/ngày), người thật không nhận được mã. Cần Amazon SES và CAPTCHA.
2. **Khóa oan theo NAT:** SOAR khóa theo IP, nên người dùng chung Wi-Fi với kẻ tấn công cũng bị khóa 24 giờ.
3. **Máy web bị chiếm thì giả được sự kiện:** EC2 ghi được vào log group của chính nó và Detector tin mọi dòng trong đó, nên kẻ chiếm máy có thể khiến hệ thống khóa IP bất kỳ (trừ `admin_cidr`).

Các giới hạn khác: tắt máy EC2 thì mất Console và web mẫu (Detector vẫn chạy); chế độ trực tiếp luôn bị trình duyệt cảnh báo chứng chỉ; chặng CloudFront → máy là HTTP trong mạng AWS (chế độ edge); bộ đếm "chặn tại chỗ" nằm riêng từng worker nên thực tế đoán được khoảng 9 lần trước khi bị chặn; Cognito dùng email mặc định (giới hạn khoảng 50 thư/ngày). Danh sách đầy đủ: mục 7 của [SECURITY_REVIEW.md](SECURITY_REVIEW.md).

## 13. Cấu trúc thư mục và tài liệu

```
app.py, log_sentinel/            Hạ tầng CDK (stack chính, stack edge, định nghĩa Athena)
lambda_src/                      detector.py (Detector), waf_sync.py (đồng bộ WAF)
sample_app/                      Web mẫu + SOC Console (Flask)
  app.py, cognito_identity.py, password_strength.py
  templates/, static/            Giao diện Console
  deploy/                        bootstrap.sh, Nginx, systemd, CloudWatch Agent
tests/unit/                      539 test
attack_sim.py, iam_tamper.py     Kịch bản tấn công
docs/                            Tài liệu (bảng dưới)
```

| Tài liệu | Nội dung |
|---|---|
| [README.md](../README.md) | Khởi động nhanh, hai chế độ triển khai |
| [USER_GUIDE.md](USER_GUIDE.md) | Hướng dẫn khách hàng: SOC Console, ý nghĩa từng luật, Athena |
| [LOG_CONVENTION.md](LOG_CONVENTION.md) | Hợp đồng log giữa web app và Detector, khóa DynamoDB |
| [SECURITY_REVIEW.md](SECURITY_REVIEW.md) | Lỗ hổng đã vá, kết quả red-team, rủi ro còn lại, hướng mở rộng |
| [COST.md](COST.md) | Chi phí từng chế độ và khi bị tấn công |
| [NHAT_KY_2026-11-11.md](NHAT_KY_2026-11-11.md) | Nhật ký làm việc, thiết kế phân quyền admin |
| [NHAT_KY_2026-11-12.md](NHAT_KY_2026-11-12.md) | Chốt duyệt nhiều người, xây phân quyền admin, danh sách việc chưa làm |
| [HANDOVER_NGUOI_B.md](../HANDOVER_NGUOI_B.md) | Bàn giao từ Người A sang Người B |

## 14. Việc đã làm và chưa làm

### Đã làm (đến 12/11)
- Phân quyền admin (12/11): PIN riêng, bỏ phiếu đa số, chế độ khởi tạo, admin bắt buộc 2FA, giao diện, review hai trục và sửa theo review.
- Sửa lỗi deploy Firehose (sau đó gỡ hẳn Firehose ngày 12/11).
- SOC Console đầy đủ: đăng ký, độ mạnh mật khẩu, 2FA tùy chọn, quên mật khẩu, vai trò, duyệt người dùng, thu hồi phiên khi đăng xuất.
- Detector từ 9 lên 20 luật; tin Telegram dễ đọc; bộ lọc SQL injection mạnh hơn nhiều.
- Athena, bảng chi phí, lưu log 30 ngày, cảnh báo chi phí.
- Chế độ edge: code và test.
- Bộ kịch bản tấn công và hai vòng review code.
- Đã deploy chế độ trực tiếp lên AWS và xác nhận phát hiện brute-force chạy thật.

### Chưa làm / kế hoạch tiếp theo

| Việc | Ghi chú |
|---|---|
| Bảo mật EC2: kiểm tra trên máy thật | Code xong 12/11 (Lambda thực thi phân quyền, sandbox systemd, tự vá bảo mật, chỉ kết nối ra cổng 443). Xem nhật ký 12/11 mục 4.D |
| Phân quyền admin: thử trên trình duyệt thật | Code và test xong 12/11, chưa deploy |
| **IP tĩnh (Elastic IP)** | `-c static_ip=true`, vì máy được Stop/Start hằng ngày |
| **Bỏ cảnh báo "Không bảo mật"** | Deploy chế độ edge: **CloudFront + WAF** (đã chốt 12/11), ngưỡng chi phí 35 USD/tháng. Phụ thuộc IP tĩnh |
| **Cột Chi tiết / Đối tượng bằng câu tiếng Việt dễ đọc** | Đã chốt thiết kế; dữ liệu gốc thu vào nút "Xem dữ liệu gốc" |
| Biểu đồ và ma trận nhiệt | Hoãn, ưu tiên logic lõi trước |
| Kiểm thử trên AWS thật | Đăng ký, 2FA, quên mật khẩu, dò quét, Athena, `iam_tamper.py`, gỡ khóa |
| Telegram | Code xong; cần điền `BOT_TOKEN` và `CHAT_ID` thật vào Secrets Manager (mặc định là `REPLACE_ME`) |
| Thêm `boto3` vào `requirements-dev.txt` | Để VS Code hết cảnh báo import |
| Gom code lặp trong Detector, gom chuỗi `"logsentinel"` thành hằng | Tồn từ review, không ảnh hưởng chức năng |
| Kiến trúc 2 AZ, tên miền `.net`, HTTPS đầu-cuối | Hướng mở rộng, xem mục 8 của `SECURITY_REVIEW.md` |
| Plugin cho web của khách, đa khách hàng | Chưa quyết (xem mục 11) |

## 15. Quyết định đã chốt và câu hỏi mở

### Thiết kế phân quyền admin (đã chốt và đã làm 12/11)

Luồng: đăng nhập (bắt buộc 2FA với admin) → vào mục **Phân quyền** → nhập **mã PIN riêng**.

- Admin được: duyệt người mới, nâng Người xem lên Quản trị, hạ Quản trị xuống Người xem, vô hiệu hóa tài khoản. Không tự hạ quyền chính mình.
- **Luôn tối thiểu 2 admin** (chặn thao tác làm số admin xuống dưới 2) **và** **duyệt hai người** (thao tác do admin A tạo cần admin B xác nhận). Tài khoản `admin` nội bộ không tính vào 2 admin.
- Admin Cognito chưa bật 2FA chỉ thấy màn hình "Bật 2FA"; admin không có nút "Tắt 2FA".
- PIN đúng 6 chữ số, chặn mã dễ đoán, lưu dạng băm. Nhập đúng thì mục Phân quyền mở **10 phút**. Sai 5 lần khóa 15 phút và sinh sự cố `ADMIN_PIN_LOCKED` (HIGH).
- Quên PIN: admin khác đặt lại; PIN của `admin` nội bộ đặt lại bằng AWS CLI. Mỗi lần nâng quyền admin hoặc đặt lại PIN sinh cảnh báo.

Các câu hỏi về duyệt nhiều người, hạn 24 giờ, chế độ khởi tạo, đặt lại PIN và WAF đã chốt ngày 12/11 (xem [NHAT_KY_2026-11-12.md](NHAT_KY_2026-11-12.md) mục 1 và 4.A).

### Câu hỏi còn mở
1. Đa khách hàng: một bộ riêng cho mỗi doanh nghiệp hay một hệ thống chung? Web của khách dùng công nghệ gì (Nginx, Apache, WordPress, Node...)?

## 16. Lưu ý phối hợp nhóm

- Nhánh `b/telegram-detection` **sửa nhiều phần hạ tầng của Người A** (stack CDK, Nginx, bootstrap). Cần Người A xem trước khi gộp vào `main`.
- AWS CLI trên máy Người B đang dùng IAM user của Người A, không phải `tuan-qa-lead` như tài liệu bàn giao.
- Hai commit đầu trên nhánh GitHub đứng tên Người A theo cấu hình Git của máy.
- Repo local `d:\ki6\AWS-project` chưa nối với GitHub (cấu trúc thư mục khác). Lần sau nên clone repo nhóm, chuyển sang nhánh `b/telegram-detection` và làm việc trực tiếp ở đó.

## Phụ lục A: Điểm vào của web app

| Đường dẫn | Mục đích | Cần đăng nhập |
|---|---|---|
| `GET /health` | Kiểm tra máy còn sống | Không |
| `GET /search` | Ô tìm kiếm mẫu (đối tượng bị tấn công khi demo) | Không |
| `GET /setup-2fa` | Thiết lập 2FA của `admin` nội bộ (cần token trong `webapp.env`) | Token |
| `POST /login` | Đăng nhập `admin` nội bộ (mật khẩu + OTP) | Không |
| `POST /auth/register`, `/confirm`, `/resend` | Đăng ký, xác nhận email, gửi lại mã | Không |
| `POST /auth/login`, `/auth/mfa` | Đăng nhập Cognito, bước mã 2FA | Không |
| `POST /auth/forgot`, `/auth/reset` | Quên mật khẩu | Không |
| `GET /console`, `GET /api/config` | Giao diện và cấu hình | Không |
| `GET /api/session`, `/api/account`, `POST /api/logout` | Phiên và tài khoản | Có |
| `POST /api/mfa/setup`, `/enable`, `/disable` | Bật/tắt 2FA (Cognito) | Có |
| `GET /api/overview` | Sự cố và IP bị khóa | Người xem trở lên |
| `POST /api/unblock` | Gỡ khóa IP | Quản trị |
| `GET /api/users`, `POST /api/users/approve`, `/revoke` | Duyệt và thu hồi người dùng | Quản trị |

## Phụ lục B: Sự kiện web app ghi vào log

| `event_type` | Khi nào | Detector xử lý |
|---|---|---|
| `FAILED_LOGIN` | Sai mật khẩu, sai token thiết lập, xác minh lại thất bại | Đếm theo IP, theo tài khoản, toàn hệ thống |
| `MFA_REQUIRED` | Đúng mật khẩu, chưa nhập OTP | Bỏ qua |
| `MFA_BYPASS_ATTEMPT` | Đúng mật khẩu, sai OTP | CRITICAL + khóa IP |
| `SQL_INJECTION` | Payload độc hại ở ô tìm kiếm hoặc ô đăng nhập | CRITICAL + khóa IP |
| `NOT_FOUND` | Request tới đường dẫn không tồn tại | Đếm theo IP, 30 lần / 60 giây |
| `LOGIN_SUCCESS` | Đăng nhập thành công (có trường `auth` và `role`) | Bỏ qua |
| `REGISTER_REQUEST`, `REGISTER_CONFIRMED`, `PASSWORD_RESET_REQUEST`, `PASSWORD_RESET_DONE` | Vòng đời tài khoản | Bỏ qua (dấu vết kiểm toán) |
| `MFA_ENABLED`, `MFA_DISABLED` | Người dùng bật hoặc tắt 2FA | Bỏ qua (dấu vết kiểm toán) |
| `USER_APPROVED`, `USER_REVOKED`, `ADMIN_UNBLOCK` | Thao tác của quản trị | Bỏ qua (dấu vết kiểm toán) |
| `CHAT_QUESTION` | Hỏi trợ lý AI (không ghi nội dung) | Bỏ qua (dấu vết kiểm toán) |

Chi tiết trường và khóa DynamoDB: [LOG_CONVENTION.md](LOG_CONVENTION.md).
