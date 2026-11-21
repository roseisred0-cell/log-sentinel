# LogSentinel — Đánh giá kiến trúc & bảo mật (review 10/11/2026)

Phạm vi: `log-sentinel-main.zip` (code thực tế), tài liệu đặc tả "v2.2-soar-hardened", file `LogSentinel_KeHoach.xlsx`.

## 0. Phát hiện quan trọng nhất: tài liệu và code đang lệch nhau

Tài liệu v2.2 ghi là đã có Nginx TLS 443, Gunicorn bind 127.0.0.1, chống giả mạo IP, cache chặn trên RAM, bộ đếm brute-force nguyên tử chỉ cảnh báo 1 lần, CloudTrail multi-region, không còn secret hardcode, IMDSv2, EBS mã hóa. **Code trong zip (v2.1) chưa có mục nào trong số đó.** Nếu nộp báo cáo theo tài liệu mà mentor mở code ra kiểm thì sẽ mất điểm phần Security. Bản vá này đưa code về khớp với tài liệu, và thêm test để chứng minh từng mục.

## 1. Các lỗ hổng tìm thấy và cách đã vá

| # | Mức độ | Lỗ hổng trong code cũ | Hậu quả thực tế | Đã vá ở |
|---|---|---|---|---|
| 1 | CRITICAL | `get_client_ip()` tin `X-Forwarded-For` vô điều kiện, cổng 8080 mở ra Internet | Kẻ tấn công đổi header để **né khóa vô hạn**, hoặc ghi IP của người khác (mentor, SOC) vào header để **SOAR khóa nạn nhân 24h**. SOAR thành vũ khí DoS | `resolve_client_ip()` chỉ tin header khi `TRUST_PROXY=true` và kết nối đến từ 127.0.0.1; Nginx ghi đè header; SG chỉ mở 443; Gunicorn bind loopback |
| 2 | CRITICAL | `/setup-2fa` công khai, in TOTP secret **và mã OTP hiện tại**, gửi secret sang `api.qrserver.com` | 2FA vô hiệu hoàn toàn: ai vào trang cũng có mã đúng; bên thứ ba nhận được secret | Bắt buộc `X-Setup-Token` (so sánh hằng thời gian), sai token tính là `FAILED_LOGIN`; QR sinh nội bộ; không hiện OTP; `Cache-Control: no-store` |
| 3 | CRITICAL | Hardcode `TOTP_SECRET`, `CorrectPassword123!`, tên bảng DynamoDB trong `app.py` (đã nằm trên Git) | Lộ thông tin đăng nhập công khai | Secret sinh ngẫu nhiên **trên máy** lúc boot (`/etc/logsentinel/webapp.env`, 0640), lấy qua SSM; app `RuntimeError` nếu thiếu. Không cần "phát hiện pytest" — test truyền config qua `create_app()` |
| 4 | HIGH | Bộ đếm brute-force dùng khóa cố định + `ttl` để "reset"; DynamoDB xóa TTL trễ tới 48h; điều kiện `count >= 5` | Bộ đếm **không bao giờ về 0**: sau lần sai thứ 5, mỗi lần sai tiếp theo sinh 1 sự cố + 1 email + 1 Telegram (bão cảnh báo). Không phải cửa sổ 60s | `count_failed_login()`: `window_start` + 2 lần `update_item` có `ConditionExpression`, nguyên tử kể cả khi nhiều Lambda chạy song song; cảnh báo khi `count == 5` (1 lần/cửa sổ) |
| 5 | HIGH | Handler bắt mọi lỗi rồi `return 500` | Metric `AWS/Lambda Errors` luôn = 0 → `DetectorErrorsAlarm` **không bao giờ kêu**, detector mù mà không ai biết | Envelope hỏng thì `raise`; 1 dòng log lỗi thì bỏ qua dòng đó, xử lý tiếp batch |
| 6 | HIGH | `is_multi_region_trail=False` | Từ 22/11/2021, trail single-region ngoài us-east-1 không còn nhận global service events (IAM, STS, CloudFront). 4/6 luật CloudTrail (IAM + một phần ConsoleLogin) mù trên môi trường thật — chỉ "chạy" khi bơm log giả | `is_multi_region_trail=True`, `include_global_service_events=True`, thêm `enable_file_validation`, mã hóa log bằng CMK |
| 7 | HIGH | EC2 role dùng `CloudWatchAgentServerPolicy` (ghi được **mọi** log group) | Web server bị chiếm có thể bơm sự kiện CloudTrail giả hoặc spam log → Lambda (Denial of Wallet) | Chỉ `CreateLogStream/PutLogEvents/DescribeLogStreams` trên `/logsentinel/sample-app` |
| 8 | HIGH | Luật SQLi so khớp chuỗi con: `SELECT`, `DROP`, `--` | Người dùng thật tìm "how to select a laptop" hay "drop shipping" bị **khóa 24h** | Regex có ranh giới từ; test cả mẫu tấn công lẫn mẫu lành tính |
| 9 | HIGH | Flask dev server chạy bằng root, `0.0.0.0:8080`, `chmod 777` thư mục log | Một lỗi RCE trong app là chiếm luôn quyền root | Gunicorn 4 workers dưới user `webapp`, sandbox systemd (`ProtectSystem=strict`, `NoNewPrivileges`), log 0644 |
| 10 | MEDIUM | App gọi DynamoDB `query` **mỗi request**, không cache | 1 IP spam = N lần đọc DynamoDB (Denial of Wallet) | `BlockList`: cache dương (≤ 60s, để gỡ khóa tay có tác dụng), cache âm 5s, giới hạn 10.000 IP chống cạn RAM khi xoay IP |
| 11 | MEDIUM | Không kiểm tra `ttl` khi đọc khóa | Khóa "24h" thực tế kéo dài tới ~72h | App tự so `ttl > now` |
| 12 | MEDIUM | `BLOCKED_IP#<ip>` dùng SK = timestamp | Mỗi lần khóa lại sinh 1 item mới | SK cố định `ACTIVE`, ghi lại chỉ gia hạn |
| 13 | MEDIUM | Không có allowlist | Khi demo, SOAR có thể khóa chính IP quản trị | `-c admin_cidr=x.x.x.x/32` → `BLOCK_ALLOWLIST_CIDRS`; app chỉ khóa tạm 60s, nếu Detector không xác nhận thì tự mở |
| 14 | MEDIUM | Không IMDSv2, EBS không mã hóa | SSRF đọc được credential của role | `require_imdsv2=True`, EBS gp3 `encrypted=True` |
| 15 | MEDIUM | Log JSON có số thực → `float` làm `put_item` lỗi; `json.dumps(Decimal)` làm SNS lỗi; trường do kẻ tấn công kiểm soát không giới hạn độ dài | Mất bản ghi sự cố khi input xấu (Bước 8 của kế hoạch) | `parse_float=Decimal`, `_compact()` cắt chuỗi 512 ký tự, 1 hàm `_render_alert` dùng chung cho mọi kênh |
| 16 | MEDIUM | Lambda có `grant_read_write_data` (Scan/Delete) | Detector bị lạm dụng có thể xóa bằng chứng | Chỉ `PutItem`, `UpdateItem` |
| 17 | LOW | Ghi lại mã OTP sai vào log | Lộ mã gần đúng | Chỉ ghi `otp_length` |
| 18 | LOW | Email thật, Account ID, VPC ID nằm trong code/test | Vi phạm Sanitization Policy (Lát cắt 6) | Email qua `-c alert_email=...`; test dùng `123456789012` |

## 2. Những gì cố ý giữ nguyên (đúng kiến trúc)

- Ba khối dọc Edge → SIEM → SOAR và tên các resource CDK (logical ID không đổi nên `cdk deploy` là cập nhật, không dựng lại DynamoDB/KMS). Riêng EC2 sẽ được thay mới — đó là chủ đích.
- Toàn bộ public API mà test của B dùng trong `detector.py` (`record_incident`, `evaluate_*`, `_telegram_cache`, …). Chỉ sửa 1 test của B (`handler` phải raise thay vì trả 500, lý do ở mục 5) và đổi Account ID sang số mẫu.
- Không thêm NAT Gateway, ALB hay WAF (giữ FinOps).

## 3. Kiến trúc module sau khi vá (deep modules)

```
sample_app/app.py
  load_config_from_env()  -> AppConfig            (fail-fast, không mặc định nhạy cảm)
  resolve_client_ip(peer, headers, trust) -> ip   (hàm thuần, test không cần Flask)
  BlockList.is_blocked(ip) / block_locally(ip)    (ẩn cache TTL + DynamoDB + fail-open)
  is_malicious_query(q) -> bool                   (hàm thuần)
  create_app(config, blocklist) -> Flask          (lắp ráp; test truyền blocklist giả)

lambda_src/detector.py
  handler -> evaluate_webapp_log / evaluate_cloudtrail_log   (rules: chỉ quyết định)
          -> record_incident / auto_block_attacker_ip / count_failed_login  (sink: mọi I/O AWS)

sample_app/deploy/   nginx.conf · webapp.service · bootstrap.sh · cwagent.json
log_sentinel/log_sentinel_stack.py   gửi sample_app lên bằng S3 Asset (không nhồi code vào UserData)
```

Muốn thêm luật mới: sửa `docs/LOG_CONVENTION.md`, thêm 1 nhánh trong `evaluate_*`, viết test trong `tests/unit/`. Không phải động vào sink hay hạ tầng.

## 4. Đối chiếu với bảng kế hoạch & hướng đi tiếp theo

Hôm nay là 10/11. Mọi ô Trạng thái trong sheet đều đang là "Chưa làm", trong khi code đã đi khá xa — nên cập nhật sheet để tiến độ trên sheet khớp với thực tế.

| Bước | Trạng thái thực tế sau bản vá | Việc còn lại / quyết định cần chốt |
|---|---|---|
| 1. App mẫu (API GW + Lambda) | Làm bằng **EC2 + Nginx + Gunicorn** | Sửa mô tả trong kế hoạch/báo cáo thành EC2. Lý do hợp lệ: SOAR cần một tầng biên để chặn IP |
| 2. Quy ước log | Xong: `docs/LOG_CONVENTION.md` | Hai người cùng duyệt |
| 3. CloudTrail → S3, KMS | CloudTrail → S3 mã hóa CMK, file validation | Log app không archive xuống S3 (đã gỡ Firehose 12/11: gói Free không dùng được, không phải lớp bảo vệ). Truy vấn log app trong 30 ngày bằng CloudWatch Logs Insights |
| 4. Bơm log giả | Xong: `python attack_sim.py logs` | |
| 5. Luật web + DynamoDB | Xong, có test | |
| 6. Luật CloudTrail | Xong 6 nhóm luật, `iam_tamper.py` bắn đủ 6 | Sau khi deploy, kiểm tra 1 lần bằng sự kiện IAM thật (tạo access key cho 1 user test) để chứng minh multi-region hoạt động |
| 7. SNS + Telegram | Code xong | Điền `BOT_TOKEN` / `CHAT_ID` thật vào Secrets Manager; xác nhận email subscription |
| 8. Dashboard + test input xấu | Dashboard có: sự cố theo mức độ, alarm, lỗi Lambda, 20 sự cố gần nhất. Có test input xấu | Chụp ảnh dashboard sau GameDay |
| 10. IAM tối thiểu + IaC | Đã siết quyền cho Lambda và EC2 | Sửa chữ "sam deploy" trong kế hoạch thành `cdk deploy` |
| 12. Cost | — | Xem mục 6 |

**Mốc đề xuất:** deploy + GameDay trước 13/11 (khớp hạn bước 5–6), cảnh báo thật trước 15/11 (điểm hẹn), sau 20/11 không thêm tính năng.

## 5. Runbook GameDay (Lát cắt 5)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -v                                  # phải xanh toàn bộ trước khi deploy

cdk deploy --require-approval never \
  -c alert_email=<email-SOC> \
  -c admin_cidr=<IP-quan-tri>/32                     # không để IP máy dùng để tấn công vào đây

# Lấy mật khẩu / TOTP / setup token (không cần SSH, không mở cổng 22):
aws ssm start-session --target <TargetVmInstanceId>
sudo cat /etc/logsentinel/webapp.env

# Đăng ký 2FA:
curl -k -H "X-Setup-Token: <APP_SETUP_TOKEN>" https://<Public-IP>/setup-2fa -o setup.html

# Tấn công thật, chạy từ một mạng KHÁC IP quản trị (ví dụ 4G):
python attack_sim.py http --target https://<Public-IP> --insecure
python iam_tamper.py
```

Gỡ khóa bằng tay (có tác dụng sau tối đa 60 giây):
```bash
aws dynamodb delete-item --table-name <IncidentTableName> \
  --key '{"incident_id":{"S":"BLOCKED_IP#<ip>"},"timestamp":{"S":"ACTIVE"}}'
```

Nếu không thấy log đổ về CloudWatch, xem `/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log` trên EC2 (role đã bị thu hẹp quyền, nên đây là chỗ đầu tiên cần nhìn).

## 6. Lưu ý FinOps cho bảng Cost (Bước 12)

Con số ~$2.15/tháng trong handover đang bỏ sót mấy khoản:
- **Public IPv4**: từ 1/2/2024, AWS tính $0.005/IP/giờ cho mọi IPv4 public (≈ $3.6/tháng). Free Tier EC2 cho 750 giờ/tháng trong 12 tháng đầu. Cần ghi rõ tài khoản còn Free Tier hay không.
- **KMS CMK** ~$1/tháng/key, **Secrets Manager** ~$0.40/secret/tháng.
- Trail multi-region sẽ tăng nhẹ lượng ingest vào CloudWatch Logs. Bản sao management events đầu tiên của CloudTrail thì miễn phí.
- Metric EMF `IncidentsDetected` (2 chiều Severity) cộng 2 metric filter vẫn nằm trong 10 custom metric miễn phí.
- Không có NAT Gateway, vì EC2 nằm ở public subnet và chỉ mở 443.

## 6b. Bổ sung v2.3 (11/11/2026)

- **SOC Console** tại `/console`: đăng nhập mật khẩu + OTP, cookie phiên `Secure` / `HttpOnly` / `SameSite=Strict`, CSRF token cho thao tác ghi, CSP `default-src 'self'`, dữ liệu chèn bằng `textContent` (payload tấn công không thể chạy trong trình duyệt của quản trị viên).
- **GSI `by_type`** để Console liệt kê sự cố bằng Query. EC2 chỉ được `DeleteItem` với khóa `BLOCKED_IP#*`, không xóa được bản ghi sự cố.
- **Firehose → S3** cho log ứng dụng (Bước 3 của kế hoạch). *Đã gỡ ngày 12/11/2026.*
- **Luật `ROOT_ACCOUNT_LOGIN`** (CRITICAL).
- **Giới hạn concurrency cho Lambda**: tùy chọn, `-c detector_max_concurrency=5`. Mặc định tắt vì tài khoản mới thường không đủ quota để reserve.
- Chi phí thêm: GSI tính theo lượt ghi/đọc on-demand.

## 6c. Bổ sung v2.4: tài khoản người dùng bằng Amazon Cognito

- **Đăng ký + xác nhận email**, chính sách mật khẩu của Cognito (≥ 8 ký tự, hoa/thường/số). Giao diện chấm 5 mức độ mạnh; máy chủ chấm lại cùng quy tắc và từ chối dưới *Trung bình* (không tin trình duyệt).
- **2FA TOTP tùy chọn** (`Mfa.OPTIONAL`, không SMS): người dùng tự bật/tắt; sự kiện `MFA_ENABLED` / `MFA_DISABLED` được ghi log để kiểm toán.
- **Vai trò = nhóm Cognito** (`soc-viewers`, `soc-admins`). Người mới đăng ký **không thuộc nhóm nào → "Chờ duyệt"**, không đọc được dữ liệu sự cố (nếu không, bất kỳ ai trên Internet cũng đăng ký được rồi xem IP/payload của khách).
- Brute-force/OTP sai trên tài khoản Cognito đi qua đúng các luật Detector sẵn có (`FAILED_LOGIN`, `MFA_BYPASS_ATTEMPT`); đăng ký/xác nhận có giới hạn tốc độ theo IP; phản hồi đăng ký/gửi lại mã giống nhau dù email đã tồn tại hay chưa (chống dò email).
- Phiên Cognito hết hạn tuyệt đối sau 30 phút (vai trò chỉ đọc lúc đăng nhập → thu hồi quyền có hiệu lực ≤ 30 phút).
- **Quên mật khẩu** qua mã email (Cognito `ForgotPassword`): phản hồi giống nhau cho email có/không tồn tại, giới hạn 5 yêu cầu và 10 lần thử mã / 10 phút / IP, mật khẩu mới phải đạt tối thiểu *Trung bình*.
- **Tắt 2FA phải xác minh lại**: yêu cầu mật khẩu + OTP hiện tại. Cognito không cho kiểm tra riêng một mã TOTP nên máy chủ đăng nhập lại để Cognito tự hỏi thử thách MFA (chặt hơn chỉ hỏi OTP). Sai → `FAILED_LOGIN`, đi qua luật brute-force sẵn có. Kẻ chỉ có cookie phiên không tắt được 2FA.
- Tài khoản `admin` nội bộ (mật khẩu + TOTP trong `webapp.env`) giữ làm tài khoản dự phòng khi Cognito/email gặp sự cố.

## 6d. Bổ sung v2.5: đợt red-team (`tests/unit/test_redteam_scenarios.py`)

Chạy: `python -m pytest tests/unit/test_redteam_scenarios.py -v`. Mỗi nhóm test là một mục tiêu của kẻ tấn công.

| Phát hiện | Mức | Đã xử lý |
|---|---|---|
| 24/41 payload SQLi/path traversal lọt bộ lọc (mã hóa kép `%2527`, `1 AND 1=1`, `/etc/passwd`, `xp_cmdshell`, `pg_sleep`, byte NUL, UTF-8 overlong) | Cao | Chuẩn hóa đầu vào (giải mã URL tới 3 vòng, NFKC, bỏ ký tự vô hình) rồi so 20 mẫu. 0/41 lọt, 0/28 câu bình thường bị chặn nhầm |
| Payload đặt ở ô tên đăng nhập / email không bị quét | Trung bình | Quét cả hai ô, ghi `SQL_INJECTION` kèm `field` |
| Khoảng trễ phát hiện brute-force: web app chờ Lambda (vài giây đến vài chục giây), trong lúc đó đoán được ~200 lần | Cao | Web app tự chặn tạm ở lần sai thứ 5; Nginx giới hạn riêng 30 lần/phút cho `/login`, `/auth/*`, `/setup-2fa` |
| Brute-force phân tán (nhiều IP, mỗi IP dưới ngưỡng) không có cảnh báo | Cao | Luật `ACCOUNT_UNDER_ATTACK`: đếm theo tên tài khoản |
| Đăng nhập AWS Console **thất bại** bị gán nhầm là `CONSOLE_LOGIN_NO_MFA`; không có luật brute-force Console | Trung bình | Tách riêng; thêm `CONSOLE_BRUTE_FORCE` |
| Chỉ bắt leo thang quyền qua *user*; bỏ sót role, group, đặt mật khẩu cho user khác, sửa trust policy | Cao | 9 sự kiện IAM mới + `KMS_KEY_TAMPERING` (vô hiệu hóa CMK là làm mù cả hệ thống) |
| `POST /api/unblock` với body là số/mảng → HTTP 500 | Thấp | Trả 400 |
| Token `/setup-2fa?token=…` bị ghi vào access log của Nginx | Trung bình | `log_format` ghi `$uri` (không có query string) |
| Ký tự ngắt dòng Unicode (U+2028) trong tên đăng nhập được ghi nguyên vào log | Thấp | Log thuần ASCII |
| Luật trong Detector và bộ lọc subscription có thể lệch nhau (luật "chết") | Thấp | Một danh sách `CLOUDTRAIL_WATCHED_EVENTS` + test đối chiếu hai chiều |

Hệ quả cần biết: `cdk deploy` có sửa IAM role sẽ sinh cảnh báo `IAM_*` (đánh dấu `via_service`). Cố ý không bỏ qua, vì CloudFormation là một đường leo thang quyền quen thuộc.

## 6e. Bổ sung v2.6: chống DDoS và lớp biên (`log_sentinel/edge_stack.py`, `lambda_src/waf_sync.py`)

| Hạng mục | Cách làm |
|---|---|
| Thu hẹp ai vào được | Chế độ edge: security group chỉ mở cổng 80 cho dải IP CloudFront (prefix list); Nginx kiểm tra thêm header bí mật `X-Origin-Verify` (lấy từ Secrets Manager lúc khởi động). Tùy chọn `console_cidrs`: luật WAF chỉ cho dải IP đó vào `/console`, `/api/`, `/auth/`, `/login`, `/setup-2fa` |
| Trần chi phí | AWS Budgets gửi email khi chi tiêu tháng đạt 80% và khi dự báo vượt 100% (`monthly_budget_usd`, mặc định 20). `detector_max_concurrency` vẫn là tùy chọn vì tài khoản mới không đủ quota |
| Worker đa luồng | Gunicorn `gthread` 2 × 16: một request chờ Cognito/DynamoDB chỉ giữ một luồng. Mỗi luồng có `Table` boto3 riêng (resource không an toàn khi dùng chung giữa các luồng) |
| CloudFront + WAF | Luật theo thứ tự: IP bị SOAR khóa → (tùy chọn) allowlist Console → 100 request/5 phút/IP vào đường dẫn đăng nhập → 2000 request/5 phút/IP → danh sách IP xấu của AWS → Known Bad Inputs. Cố ý **không** bật bộ luật SQLi của AWS ở chế độ chặn: nếu WAF chặn hết thì web app không còn ghi `SQL_INJECTION` và Detector không thấy gì |
| IP bị khóa lên WAF | `waf_sync` chạy mỗi phút, là nơi duy nhất ghi vào IP set: khóa mới, hết hạn 24 giờ và gỡ khóa từ Console đều tự đồng bộ. Lọc từng địa chỉ (một địa chỉ sai làm WAF từ chối cả danh sách; `/0` sẽ chặn cả Internet). Lỗi liên tục → alarm |

Vá thêm hai điểm yếu của đợt red-team:

- **Brute-force chậm** → luật `SLOW_BRUTE_FORCE` (20 lần sai / 1 giờ / IP).
- **Cookie dùng lại sau đăng xuất** → đăng xuất ghi `REVOKED_SESSION#<sid>` vào DynamoDB; mọi worker từ chối cookie đó trong ≤ 15 giây. Thêm tuổi thọ tuyệt đối 8 giờ cho phiên `admin` nội bộ (trước đây cookie được gia hạn vô hạn).

Giới hạn của chế độ edge cần biết:

- Chặng CloudFront → máy là HTTP (cổng 80) trong mạng AWS, không mã hóa. Muốn mã hóa đầu-cuối cần tên miền riêng + chứng chỉ ACM trên máy hoặc ALB.
- WAF giới hạn tốc độ có độ trễ khoảng 30–60 giây và vẫn tính theo IP: botnet đủ lớn, mỗi IP dưới ngưỡng, vẫn đi qua. Đây là giảm thiểu, không phải miễn nhiễm.
- IP bị khóa lên WAF chậm tối đa 1 phút; trong lúc đó web app tự chặn như cũ.

## 6f. Bổ sung v2.7: phân quyền admin (`sample_app/admin_governance.py`, 12/11/2026)

Thiết kế: nhật ký 11/11 mục 3 và nhật ký 12/11 mục 1, 4.A. Tóm tắt các lớp bảo vệ:

- **Admin bắt buộc 2FA.** Admin Cognito chưa bật 2FA chỉ vào được màn hình bật 2FA; admin không tắt được 2FA.
- **PIN riêng cho mục Phân quyền.** 6 số, chặn mã dễ đoán, băm scrypt (muối riêng), mở 10 phút. Sai 5 lần khóa 15 phút; bộ đếm nằm trong DynamoDB nên dùng chung mọi worker và không mất khi đăng nhập lại. Mỗi phiếu (đồng ý hoặc từ chối) đều phải nhập lại PIN.
- **Bỏ phiếu.** Nâng hoặc hạ Quản trị cần đa số trên tất cả admin (tối thiểu 2 phiếu, người bị hạ không bỏ phiếu); vô hiệu hóa cần 2 người. Một phiếu từ chối hủy yêu cầu. Yêu cầu hết hạn sau 24 giờ. Danh sách người được bỏ phiếu lấy trực tiếp từ Cognito mỗi lần bỏ phiếu.
- **Luôn tối thiểu 2 admin**, kiểm tra cả lúc tạo yêu cầu lẫn ngay trước khi thực thi. Việc thực thi đi qua một khóa dùng chung (`ROLE_REQ#LOCK#execute`), nên hai yêu cầu hạ quyền chạy song song không thể cùng thấy 3 admin.
- **Chỉ đánh dấu "đã thực thi" sau khi Cognito thành công.** Cognito lỗi thì yêu cầu vẫn chờ và có cảnh báo `ROLE_CHANGE_FAILED`.
- **Thay đổi có hiệu lực ngay.** Người bị nâng, hạ quyền hoặc vô hiệu hóa bị hủy mọi phiên (`REVOKED_SESSION#user:...`); worker khác biết trong tối đa 15 giây.
- **Chế độ khởi tạo.** Khi chưa đủ 2 admin Cognito, `admin` nội bộ được bỏ phiếu và tự nâng một Người xem lên Quản trị. Khi đã đủ, tài khoản này chỉ còn xem và gỡ khóa IP.
- **Lambda thực thi phân quyền** (`sample_app/governance_lambda.py`, nhật ký 12/11 mục 4.D1): chỉ Lambda này được ghi vào nhóm Cognito và vào `ROLE_REQ#`. Người gọi được xác định bằng token Cognito do Lambda tự hỏi Cognito (`GetUser`); mọi trường danh tính khác EC2 gửi đều bị bỏ qua. `admin` nội bộ (không có token) chỉ được tin trong chế độ khởi tạo; khi đã đủ 2 admin Cognito, tài khoản này không còn duyệt hay thu hồi Người xem. Lambda ghi dấu vết riêng vào `/logsentinel/governance` (EC2 không sửa được).
- **Mọi thao tác đều có cảnh báo** HIGH qua email/Telegram (`ROLE_REQUEST_CREATED`, `ADMIN_ROLE_CHANGED`, `USER_DISABLED`, `ADMIN_PIN_LOCKED`, `ADMIN_PIN_RESET`, `ROLE_CHANGE_FAILED`), không bao giờ khóa IP.

Giới hạn còn lại: xem mục 7 (máy web bị chiếm và phân quyền). Đặt lại PIN của `admin` nội bộ bằng AWS CLI không sinh cảnh báo (CloudTrail không ghi lệnh dữ liệu DynamoDB nếu chưa bật data events).

## 6h. Bổ sung v2.9: trợ lý AI dùng OpenAI (`sample_app/chat_assistant.py`, 19/11/2026)

Thay cho trợ lý Bedrock đã gỡ (tài khoản gói Free không gọi được model). Bật bằng `-c chat_model=<model>`; mặc định tắt.

| Mối đe dọa | Biện pháp | Test |
|---|---|---|
| Lộ API key | Key nằm trong Secrets Manager `logsentinel/openai_api_key`, chỉ role EC2 đọc; chỉ ARN nằm trong UserData; trình duyệt chỉ gọi `/api/chat` của Console | `test_chat_stack.py` |
| Prompt injection qua log (User-Agent, URL do kẻ tấn công viết) | Trợ lý không có công cụ hay quyền hành động nào; dữ liệu sự cố bọc trong `<du_lieu_log>`, ký tự `<` `>` bị thay để không đóng khối sớm; system prompt cấm làm theo chỉ dẫn trong dữ liệu | `test_chat_assistant.py` |
| Lộ dữ liệu cá nhân ra bên thứ ba | Chỉ gửi sự cố người dùng vốn xem được; che email, cắt chuỗi 500 ký tự, tối đa 10 sự cố; `store=False` để OpenAI không lưu hội thoại; log không ghi nội dung câu hỏi | `test_chat_assistant.py`, `test_chat_route.py` |
| Đốt tiền (Denial of Wallet) | Hạn mức mỗi người mỗi ngày (DynamoDB `CHAT_QUOTA#`, tăng có điều kiện); câu hỏi tối đa 1.000 ký tự; trả lời tối đa 800 token; Nginx 6 câu/phút/IP; hạn mức tháng trên OpenAI (người dùng tự đặt) | `test_chat_quota_store.py`, `test_chat_stack.py` |
| Treo Console (mỗi câu giữ một luồng tới 25 giây) | Mỗi người một câu đang chờ; timeout OpenAI 25 giây, không thử lại; Nginx `proxy_read_timeout 30s` riêng cho `/api/chat` | `test_chat_assistant.py` |
| XSS qua câu trả lời của AI | Hiển thị bằng `textContent`; CSP `default-src 'self'` | `test_chat_route.py` |
| Lộ chi tiết lỗi nhà cung cấp | Lỗi OpenAI chỉ trả "tạm thời không trả lời được" (503); log máy chủ chỉ ghi tên loại lỗi | `test_chat_assistant.py` |

Còn thiếu: luật Detector cảnh báo lạm dụng chatbot (`CHAT_ABUSE`); hội thoại chưa có trí nhớ (mỗi câu hỏi độc lập, đỡ một đường giả mạo lịch sử). Giới hạn "một câu đang chờ" tính trong từng tiến trình Gunicorn (2 tiến trình).

## 7. Rủi ro còn lại (ghi vào báo cáo để thể hiện tư duy)

Ba mục đầu có test `xfail(strict)` ở nhóm G của bộ red-team: khi ai đó vá xong, test sẽ báo.

- **Cạn hạn mức email**: giới hạn đăng ký/quên mật khẩu tính theo IP. Một botnet ~50 IP làm hết hạn mức email mặc định của Cognito trong ngày, người thật không nhận được mã. Cần SES + CAPTCHA/WAF.
- **Khóa oan theo NAT**: SOAR khóa theo IP, nên người dùng chung Wi-Fi/NAT với kẻ tấn công cũng bị khóa 24 giờ.
- **Máy web bị chiếm thì giả được sự kiện**: EC2 có quyền ghi vào log group của chính nó, Detector tin mọi dòng trong đó → kẻ chiếm máy có thể khiến hệ thống khóa IP bất kỳ (trừ `admin_cidr`).
- Bộ đếm "chặn tại chỗ" nằm riêng từng Gunicorn worker: trường hợp xấu nhất kẻ tấn công đoán được ~9 lần (2 worker) trước khi bị chặn, thay vì 5.
- **Chưa có cách tích hợp cho ứng dụng của khách**: hệ thống vẫn chỉ giám sát ứng dụng mẫu của chính nó. Đây là rào cản lớn nhất để thương mại hóa (cần thư viện/middleware ghi log đúng chuẩn và kiểm tra danh sách chặn).
- **Console chạy chung máy với ứng dụng được bảo vệ** và chỉ có một máy, không có dự phòng.
- Bộ lọc SQLi là danh sách mẫu (regex), không phải bộ phân tích cú pháp: payload mới chưa có trong danh sách vẫn có thể lọt. Đây là lớp phát hiện, không thay được truy vấn tham số hóa trong ứng dụng thật.

- **Máy web bị chiếm và phân quyền** (đã giảm thiểu 12/11, mục 6f): EC2 không còn quyền ghi vào Cognito hay vào `ROLE_REQ#`. Mọi thay đổi đi qua Lambda `GovernanceExecutor`, Lambda tự xác minh người bấm bằng token Cognito. Rủi ro còn lại:
  - Kẻ chiếm máy đúng lúc một admin đăng nhập lấy được token của admin đó (token nằm trong phiên trên máy), và bỏ phiếu thay người đó được trong thời hạn token (tối đa 1 giờ).
  - Trong chế độ khởi tạo (dưới 2 admin Cognito), Lambda tin yêu cầu `{"local": true}`, nên kẻ chiếm máy lúc này tự nâng được một tài khoản lên Quản trị. Khoảng thời gian này chỉ có lúc mới dựng hệ thống.
  - PIN kiểm tra trên EC2: kẻ chiếm máy bỏ qua được PIN (nhưng vẫn cần token như trên) và đặt lại được PIN của admin khác (`ADMIN_PIN#`).
- Cognito dùng email mặc định (tối đa ~50 mã/ngày, gồm cả mã đăng ký và mã quên mật khẩu). Bản thương mại nên cấu hình SES.
- Giới hạn tốc độ đăng ký/quên mật khẩu nằm trong RAM từng Gunicorn worker (thực tế ≈ 4 × giới hạn).
- Access token Cognito nằm trong cookie phiên (đã ký, `HttpOnly`, `Secure`, nhưng không mã hóa).

- Chế độ trực tiếp dùng chứng chỉ TLS tự ký, chỉ cho lab. Production dùng chế độ edge (`-c enable_edge=true`).
- TOTP chưa chống replay trong cùng 30 giây.
- Cache chặn nằm riêng trong từng Gunicorn worker. Một IP bị khóa ở worker A vẫn có thể lọt vào worker B trong tối đa 5 giây, cho tới khi Lambda ghi xong DynamoDB.
- Luật root mới chỉ bắt lần đăng nhập Console; chưa bắt lời gọi API bằng access key của root.
- SOC Console chạy chung máy với ứng dụng mục tiêu.
- SNS topic chưa mã hóa KMS.
- `cdk.context.json` chứa VPC ID và Account ID thật. Che đi trước khi để repo public.

## 8. Hướng mở rộng trong tương lai

### 8.1 Kiến trúc 2 AZ (đã thiết kế, chưa triển khai)

```
Người dùng → CloudFront + WAF → ALB (2 AZ) → 2 máy EC2 (mỗi AZ một máy, Auto Scaling Group)
Dùng chung: DynamoDB, Cognito, Secrets Manager, S3, Lambda (các dịch vụ này đã chạy nhiều AZ sẵn)
```

Các quyết định đã chốt với chủ dự án (11/2026):

| Quyết định | Lựa chọn | Lý do |
|---|---|---|
| Phạm vi | Chỉ trong chế độ edge; chế độ trực tiếp vẫn 1 máy | Chế độ trực tiếp là lab, không có ALB để chia tải |
| Vị trí máy | Subnet public, security group chỉ nhận từ ALB | Subnet private cần NAT Gateway, khoảng 40 USD/tháng mỗi cái |
| Bí mật | Mật khẩu admin, khóa 2FA, khóa ký cookie chuyển sang Secrets Manager | Hiện sinh riêng từng máy nên 2 máy không dùng chung cookie được |
| Bộ đếm đăng nhập sai | Chuyển sang DynamoDB, mọi máy đếm chung; ngưỡng thành tham số deploy | Bộ đếm trong RAM bị nhân theo số máy |
| Số máy | Chưa chốt: 2 máy cố định, hoặc 1 máy tự phục hồi trên 2 AZ | Console chỉ là dashboard; máy chết thì Detector và cảnh báo vẫn chạy |

Việc phải làm khi triển khai: miễn kiểm header `X-Origin-Verify` cho `/health` (ALB health check không mang header
này); đổi cách lấy IP thật sang header `CloudFront-Viewer-Address` vì có thêm ALB ở giữa, rồi chạy lại test
B1 và F9 của bộ red-team; thay `user_data_causes_replacement` bằng rolling update. Chi phí: xem `COST.md` mục 3.

Lý do hoãn: chi phí khoảng 70 USD/tháng, gấp 4 lần chế độ mặc định, trong khi mục tiêu hiện tại là đồ án.

### 8.2 Tên miền riêng và HTTPS đầu-cuối

`logsentinel.com` đã có chủ. Phương án: `logsentinel.net`, DNS trên Route 53, chứng chỉ ACM. Tài khoản AWS gói
Free Tier không đăng ký được tên miền qua Route 53; phải nâng gói hoặc mua ở nhà đăng ký khác rồi trỏ về.
Khi có tên miền và ALB, chặng CloudFront → máy chuyển từ HTTP sang HTTPS.

### 8.3 Tích hợp ứng dụng của khách hàng

Hệ thống hiện chỉ giám sát ứng dụng mẫu của chính nó. Hướng đề xuất: agent đọc access log Nginx/Apache kèm chế độ
"chỉ cảnh báo", dùng WAF sẵn có để chặn; sau đó mới tới thư viện cho từng framework.

### 8.4 Vá ba điểm yếu nhóm G của bộ red-team

Ba điểm yếu ở mục 7 có test `xfail(strict)` trong `tests/unit/test_redteam_scenarios.py` (G3, G4, G5). Khi vá xong
một điểm, test tương ứng báo `XPASS`; lúc đó bỏ dấu `xfail` để nó thành test thường.

| Test | Điểm yếu | Hướng sửa | Sửa được tới đâu |
|---|---|---|---|
| G3 | Botnet làm cạn hạn mức email Cognito (~50 thư/ngày) vì giới hạn đăng ký tính theo IP | Bước 1: thêm giới hạn **tổng** lượt đăng ký/quên mật khẩu mỗi ngày, đếm chung trong DynamoDB, chừa phần cho quên mật khẩu. Bước 2: gửi mail qua Amazon SES và thêm CAPTCHA (AWS WAF) | Dứt điểm sau bước 2. Bước 1 chỉ code, đủ để test G3 qua |
| G4 | Người dùng chung NAT/Wi-Fi với kẻ tấn công bị khóa oan 24 giờ | Lỗi nhẹ (1 lần SQLi, dò quét): chỉ chặn request và khóa phiên/tài khoản, không khóa IP. Chỉ khóa IP khi tấn công lặp lại hoặc nghiêm trọng, thời gian ngắn hơn. Thêm nút gỡ khóa nhanh trên Console | Chỉ giảm nhẹ: hệ thống chỉ thấy IP thì không tách được hai người chung IP. Đổi lại, kẻ tấn công được thử thêm vài lần trước khi bị khóa. Cần chủ dự án chốt mức đánh đổi |
| G5 | Máy web bị chiếm thì ghi được sự kiện giả vào `/logsentinel/sample-app`, khiến hệ thống khóa IP bất kỳ | Đối chiếu với nguồn log máy EC2 không ghi được: ở chế độ edge, chỉ khóa IP có xuất hiện thật trong log CloudFront/WAF. Thêm trần thiệt hại: sự kiện từ máy web chỉ khóa tối đa N IP/giờ, vượt ngưỡng thì dừng tự khóa và báo "nghi máy web bị chiếm" | Chỉ giảm nhẹ. Ký log bằng HMAC không giúp được vì kẻ chiếm máy lấy được luôn khóa ký |

Thứ tự đề xuất: G3 bước 1 → trần thiệt hại của G5 → G4 (sau khi chốt mức đánh đổi) → SES, CAPTCHA và đối chiếu
log CloudFront.
