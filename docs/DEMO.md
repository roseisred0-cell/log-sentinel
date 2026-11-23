# Kịch bản demo LogSentinel

Thời lượng khoảng 15 phút. Các số **(1)**, **(2)**... khớp với số trên [sơ đồ kiến trúc](architecture/logsentinel-architecture.png) và mục Workflow trong [PROPOSAL.md](PROPOSAL.md).

Chỉ tấn công hệ thống của chính mình. Mọi lệnh PowerShell chạy trong thư mục `log-sentinel-main`.

## 0. Thông tin hệ thống

| Thứ | Giá trị hiện tại (23/11) | Cách lấy lại nếu đổi |
|---|---|---|
| SOC Console | `https://dww0e125hyfiv.cloudfront.net/console` | Output `SocConsoleUrl` |
| Địa chỉ web (đích tấn công) | `https://dww0e125hyfiv.cloudfront.net` | Output `TargetVmAttackUrl` |
| Máy EC2 | `i-0dc0d22dad246ff78` | Output `TargetVmInstanceId` |
| Bot Telegram | `Logsentinel_QM3004_bot` | |
| CloudWatch dashboard | `LogSentinel-Overview` | |

Xem lại toàn bộ output (thay máy hoặc deploy lại có thể đổi địa chỉ):

```powershell
aws cloudformation describe-stacks --region ap-southeast-1 --stack-name LogSentinelStack `
  --query "Stacks[0].Outputs[].[OutputKey,OutputValue]" --output table
```

Trong file này, `$URL` là địa chỉ web ở trên:

```powershell
$URL = "https://dww0e125hyfiv.cloudfront.net"
```

## 1. Chuẩn bị (làm trước buổi demo, tốt nhất từ hôm trước)

### 1.1 Hệ thống

- [ ] **Deploy bản code mới nhất**, luôn kèm đủ cờ edge:
  ```powershell
  cdk deploy --all -c enable_edge=true -c static_ip=true -c alert_email=<email> -c admin_cidr=<ip-laptop>/32 -c chat_model=<model>
  ```
  Thiếu `enable_edge` hoặc `static_ip` thì CDK xóa CloudFront và trả lại Elastic IP.
- [ ] **Bật máy** nếu đang tắt, rồi đợi 1–2 phút cho dịch vụ chạy lại:
  ```powershell
  aws ec2 start-instances --region ap-southeast-1 --instance-ids i-0dc0d22dad246ff78
  curl.exe -s -o NUL -w "%{http_code}`n" "$URL/health"     # phải ra 200
  ```
- [ ] **IP laptop trình bày phải nằm trong `admin_cidr`**, nếu không bạn có thể tự khóa mình. Mạng ở phòng bảo vệ thường khác mạng ở nhà, nên so lại hai địa chỉ:
  ```powershell
  curl.exe -s https://checkip.amazonaws.com
  aws lambda get-function-configuration --region ap-southeast-1 `
    --function-name LogSentinelStack-AnomalyDetectorLambda18F9B4C5-1kK4eHnv9MZx `
    --query "Environment.Variables.BLOCK_ALLOWLIST_CIDRS" --output text
  ```
  Nếu khác nhau: deploy lại với `-c admin_cidr=<ip-mới>/32`.
- [ ] Email cảnh báo đã bấm xác nhận (SNS). Telegram đã nhận được tin thử.

### 1.2 Tài khoản (cho phần phân quyền)

Cần sẵn 3 tài khoản Cognito:

| Tài khoản | Vai trò | Ghi chú |
|---|---|---|
| A | Quản trị | Đã bật 2FA, đã đặt PIN |
| B | Quản trị | Đã bật 2FA, đã đặt PIN |
| V | Người xem | Để demo nâng quyền |

Mỗi tài khoản đăng nhập ở **một trình duyệt hoặc cửa sổ ẩn danh riêng** (cookie riêng).

Tài khoản `admin` nội bộ chỉ dùng dự phòng. Mật khẩu và khóa 2FA lấy qua SSM, không cần SSH:

```powershell
aws ssm start-session --region ap-southeast-1 --target i-0dc0d22dad246ff78
# trong phiên (dấu nhắc sh-5.2$):
sudo cat /etc/logsentinel/webapp.env
```

### 1.3 Máy tấn công

- Dùng **mạng khác `admin_cidr`**, ví dụ phát 4G từ điện thoại cho một laptop thứ hai, hoặc mở trình duyệt ngay trên điện thoại. IP trong `admin_cidr` được ghi nhận nhưng **không bao giờ bị khóa**, nên tấn công từ laptop trình bày sẽ không thấy bị chặn.
- Máy tấn công cần Python 3 để chạy `attack_sim.py` (chỉ dùng thư viện chuẩn ở chế độ `http`).

### 1.4 Màn hình

Mở sẵn:
- Console (tài khoản A) ở thẻ **Sự cố gần đây**.
- Telegram trên điện thoại, chiếu được lên màn hình.
- Hộp thư email cảnh báo.
- Sơ đồ kiến trúc.

## 2. Kịch bản

| # | Phần | Bước trên sơ đồ | Thời gian |
|---|---|---|---|
| 2.1 | Giới thiệu kiến trúc | cả sơ đồ | 2 phút |
| 2.2 | Đăng nhập 2FA | 1, 2, 3 | 1 phút |
| 2.3 | Đoán mật khẩu → tự khóa IP | 5, 7, 8, 9, 10, 13 | 3 phút |
| 2.4 | Chặn tại biên, gỡ khóa | 11, 12, 13 | 1,5 phút |
| 2.5 | SQL injection, dò quét | 5, 7, 8 | 2 phút |
| 2.6 | Tấn công tài khoản AWS | 6, 7, 9, 10 | 1,5 phút |
| 2.7 | Trợ lý AI | 14 | 1,5 phút |
| 2.8 | Phân quyền hai người duyệt | 4 | 2 phút |
| 2.9 | Thống kê, Athena | 13, 16 | 1 phút |

### 2.1 Giới thiệu kiến trúc (2 phút)

Đi theo sơ đồ từ trái sang phải:
- Người dùng → CloudFront + WAF → EC2 (web app + Console).
- Log → CloudWatch → Lambda Detector → DynamoDB, email, Telegram.
- WafSync đẩy IP bị khóa lên WAF.

Nhấn mạnh: phần phát hiện và cảnh báo là serverless, nên vẫn chạy khi EC2 tắt.

### 2.2 Đăng nhập Console bằng 2FA (1 phút) — bước 1, 2, 3

1. Mở Console, đăng nhập tài khoản A: email, mật khẩu, rồi mã 6 số trong ứng dụng Authenticator.
2. Chỉ thanh địa chỉ: chứng chỉ thật của CloudFront, không có cảnh báo "Không bảo mật".
3. Giới thiệu nhanh các ô số đầu trang: tổng sự cố, CRITICAL, HIGH, IP đang bị khóa.

**Câu nói:** "Quản trị viên bắt buộc 2FA. Người mới đăng ký phải được duyệt mới xem được dữ liệu."

### 2.3 Đoán mật khẩu → hệ thống tự khóa IP (3 phút) — bước 5, 7, 8, 9, 10, 13

Trên **máy tấn công (4G)**:

```powershell
python attack_sim.py http --target $URL
```

Kết quả mong đợi:

```
[1] Brute-force: 6 lan sai mat khau ...
    lan 1: HTTP 401
    ...
    lan 5: HTTP 401
    lan 6: HTTP 403        <- web app tu chan tam ngay lan sai thu 5, khong cho Lambda
[2] Cho Detector khoa IP (toi da ~20s)...
    [OK] HTTP 403 - Access Denied by SOAR Active Defense
```

Chỉ cho khán giả, theo thứ tự:
1. **Telegram** (vài giây): tin `BRUTE_FORCE_DETECTED`, mức HIGH, IP của máy 4G, giờ Việt Nam.
2. **Email** cùng nội dung.
3. **Console**, tự làm mới mỗi 15 giây:
   - sự cố mới trong bảng, cột **Chi tiết** là câu tiếng Việt, có nút **Xem dữ liệu gốc**;
   - IP xuất hiện trong bảng **IP đang bị khóa**.

**Câu nói:** "5 lần sai trong 60 giây là bị khóa 24 giờ. Cảnh báo chỉ gửi một lần cho mỗi đợt tấn công, không gửi dồn dập."

### 2.4 Chặn ngay tại biên, rồi gỡ khóa (1,5 phút) — bước 11, 12, 13

1. Đợi khoảng 1 phút (WafSync chạy mỗi phút). Trên máy tấn công, mở `$URL` trong trình duyệt: lúc này **CloudFront/WAF trả 403**, request không còn tới EC2.
2. Trên Console (tài khoản A), bấm **Gỡ khóa** cạnh IP đó.
3. Đợi khoảng 1 phút (WAF đồng bộ lại, cache của web app tối đa 60 giây). Máy tấn công vào lại được.

**Câu nói:** "Có ba lớp chặn: web app chặn tạm ngay lập tức, Detector khóa 24 giờ, WAF chặn tại biên trong vòng 1 phút."

### 2.5 SQL injection và dò quét đường dẫn (2 phút) — bước 5, 7, 8

Phải gỡ khóa xong ở 2.4 thì máy tấn công mới tới được web app.

**SQL injection:** trên trình duyệt của máy tấn công, mở:

```
https://dww0e125hyfiv.cloudfront.net/search?q=%27%20OR%201%3D1%20--
```

Trang trả 403 `Forbidden - Phat hien payload doc hai`. Telegram nhận tin `SQL_INJECTION` mức **CRITICAL**, IP bị khóa. Payload hiển thị dạng chữ, không chạy được trong trình duyệt của quản trị viên.

**Dò quét (tùy chọn):** gỡ khóa lại, đợi 1 phút, rồi gọi 35 đường dẫn không tồn tại:

```powershell
1..35 | ForEach-Object { curl.exe -s -o NUL -w "%{http_code} " "$URL/khong-ton-tai-$_" }
```

Khoảng 30 lần đầu là `404`, sau đó là `403`. Console có sự cố `SCAN_DETECTED`.

**Câu nói:** "Bộ lọc chuẩn hóa đầu vào (giải mã URL nhiều vòng, Unicode) trước khi so mẫu. Đợt red-team đo được 0/41 kiểu né lọt qua, và 0/28 câu tìm kiếm bình thường bị chặn nhầm."

### 2.6 Tấn công tài khoản AWS (1,5 phút) — bước 6, 7, 9, 10

Trên **laptop trình bày** (cần AWS CLI đã đăng nhập):

```powershell
python iam_tamper.py
```

Script bơm 6 sự kiện CloudTrail **giả** vào CloudWatch: đăng nhập không MFA, gỡ MFA, tắt CloudTrail, tạo access key, gắn `AdministratorAccess`, ghi inline policy. Không thay đổi IAM thật. Script đợi 10 giây rồi in kết quả, kỳ vọng `So su co moi tu lan chay nay: 6`.

Chỉ trên Telegram/email: 6 cảnh báo, trong đó `CLOUDTRAIL_TAMPERING`, `MFA_TAMPERING` và gắn `AdministratorAccess` là **CRITICAL**.

**Câu nói:** "Sự cố CloudTrail không khóa IP, vì IP nguồn có thể là dịch vụ AWS. Hệ thống cảnh báo để người quản trị xử lý."

### 2.7 Trợ lý AI giải thích sự cố (1,5 phút) — bước 14

1. Trên Console, bấm **Hỏi AI** trong ô Chi tiết của sự cố `BRUTE_FORCE_DETECTED`.
2. Hỏi: *"Sự cố này nghĩa là gì và tôi nên làm gì tiếp theo?"*
3. Chỉ dòng *"Chỉ đọc · không tự gỡ khóa hay đổi quyền"*.

**Câu nói:**
- "AI chỉ đọc: không có quyền thao tác, chỉ hướng dẫn người dùng tự bấm nút."
- "Trước khi gửi đi, email được che và chuỗi dài bị cắt. OpenAI không lưu hội thoại."
- "Mỗi người tối đa 30 câu mỗi ngày."

### 2.8 Phân quyền hai người duyệt (2 phút) — bước 4

1. **Trình duyệt A:** mở mục **Phân quyền**, nhập PIN. Bấm **Đề xuất lên Quản trị** cạnh tài khoản V, nhập PIN xác nhận. Yêu cầu hiện trong **Yêu cầu chờ duyệt** (1/2 phiếu), và các admin khác nhận cảnh báo.
2. **Trình duyệt B:** mở **Phân quyền**, nhập PIN. Bấm **Đồng ý**, nhập PIN xác nhận. Yêu cầu được thực thi.
3. **Trình duyệt V** (nếu đang mở): bị đăng xuất ngay. Đăng nhập lại thì là Quản trị và bị buộc bật 2FA.

**Câu nói:**
- "Đổi quyền Quản trị cần đa số admin. Hệ thống luôn giữ tối thiểu 2 admin. Một phiếu từ chối là hủy."
- "Mọi thay đổi chạy trong một Lambda riêng. Máy web không có quyền ghi vào Cognito."

### 2.9 Thống kê và Athena (1 phút) — bước 13, 16

1. Console, thẻ **Thống kê sự cố**: chuyển **24 giờ / 7 ngày / 30 ngày**. Cột xếp theo mức độ, ma trận luật × thời gian.
2. Tùy chọn: AWS Console → Athena → workgroup `logsentinel` → Saved queries → chạy `LogSentinel - Top hanh dong (7 ngay)`.

Athena đọc log CloudTrail **thật** trên S3. Sự cố giả của `iam_tamper.py` chỉ nằm trong CloudWatch, nên sẽ không xuất hiện ở đây.

## 3. Phương án dự phòng

| Sự cố khi demo | Cách xử lý |
|---|---|
| Không có mạng 4G, hoặc máy tấn công không chạy được | Bơm log giả từ laptop trình bày: `python attack_sim.py logs --ip 198.51.100.23`. Kết quả: 1 `BRUTE_FORCE_DETECTED`, 1 `SQL_INJECTION`, 1 `MFA_BYPASS_ATTEMPT`, IP mẫu bị khóa (dải tài liệu RFC 5737, vô hại) |
| Tấn công từ laptop trình bày mà không thấy bị khóa | IP đó nằm trong `admin_cidr`, đúng thiết kế. Chuyển sang máy 4G hoặc dùng cách ở dòng trên |
| `attack_sim.py http` in `[!] Chua bi khoa` | Đợi thêm 10–20 giây rồi mở Console. Nếu vẫn chưa có: xem log `/logsentinel/detector` trong CloudWatch |
| Telegram không có tin | Email vẫn có. Kiểm tra secret `logsentinel/telegram_credentials` |
| Trợ lý AI báo "tạm thời không trả lời được" | Hết hạn mức OpenAI hoặc key sai. Bỏ qua phần 2.7, nói về thiết kế an toàn |
| Console báo `busy` khi bỏ phiếu | Một thao tác khác đang chạy. Bấm lại sau vài giây |
| Laptop trình bày bị khóa | Vào bằng điện thoại (mạng khác) và bấm **Gỡ khóa**. Hoặc xóa khóa bằng CLI: `aws dynamodb delete-item --region ap-southeast-1 --table-name LogSentinelStack-IncidentTable8CE1664B-9KVG4BC95YVW --key '{\"incident_id\":{\"S\":\"BLOCKED_IP#<ip>\"},\"timestamp\":{\"S\":\"ACTIVE\"}}'` |

Nên quay video hoặc chụp ảnh một lần chạy thành công từ hôm trước, để chiếu nếu mạng ở phòng bảo vệ có vấn đề.

## 4. Sau buổi demo

- [ ] **Gỡ khóa** các IP đã dùng để thử: IP 4G, `198.51.100.23` nếu đã chạy chế độ `logs`.
- [ ] Hạ tài khoản V về Người xem nếu muốn giữ nguyên trạng thái: A bấm **Đề xuất hạ quyền**, B **Đồng ý**. Với 3 admin thì cần 2 phiếu.
- [ ] Tắt máy để tiết kiệm (Detector, CloudTrail và cảnh báo vẫn chạy). Elastic IP vẫn tính phí khoảng 3,6 USD/tháng kể cả khi máy tắt.
  ```powershell
  aws ec2 stop-instances --region ap-southeast-1 --instance-ids i-0dc0d22dad246ff78
  ```

## 5. Câu hỏi hội đồng hay hỏi

| Câu hỏi | Trả lời ngắn |
|---|---|
| Sao không dùng GuardDuty / Security Hub? | Chúng mạnh hơn nhưng khó cấu hình và tốn tiền với SME. LogSentinel gói gọn, tự khóa IP, cảnh báo tiếng Việt, khoảng 28–30 USD/tháng ở chế độ edge |
| Sao chỉ một EC2, một AZ? | Phần phát hiện và cảnh báo là serverless, vẫn chạy khi EC2 chết. Đã thiết kế 2 AZ (ALB + Auto Scaling, khoảng 70 USD/tháng), để làm hướng phát triển |
| CloudFront → EC2 có mã hóa không? | Chưa, chặng đó đi HTTP vì chưa có tên miền riêng. Đã bù bằng security group chỉ nhận từ CloudFront và header bí mật. HTTPS đầu-cuối cần tên miền + ACM |
| Khóa theo IP có khóa oan không? | Có thể, nếu người dùng chung NAT/Wi-Fi với kẻ tấn công. Đã ghi là điểm yếu G4, có test ghi lại và hướng sửa |
| Có CI/CD không? | Chưa. Hạ tầng viết bằng AWS CDK, deploy bằng `cdk deploy`, chạy khoảng 850 test trước mỗi lần deploy. CI/CD qua GitHub Actions + OIDC là hướng phát triển |
| Sao không có OAuth? | Không dùng Hosted UI hay đăng nhập mạng xã hội: backend gọi thẳng API Cognito (mật khẩu + TOTP). Authenticator chỉ sinh mã trên điện thoại |
| Dữ liệu gửi cho AI gồm gì? | Câu hỏi và tối đa 10 sự cố liên quan, đã che email và cắt chuỗi dài. Không gửi mật khẩu, token, khóa 2FA. `store=False` |
