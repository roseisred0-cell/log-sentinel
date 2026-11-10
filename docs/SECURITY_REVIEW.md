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
| 3. CloudTrail/Firehose → S3, KMS | CloudTrail → S3 mã hóa CMK, file validation | **Chốt với mentor**: log app hiện không archive xuống S3. Nếu bắt buộc thì thêm subscription filter thứ 2 → Firehose → S3 (chi phí thấp) |
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

## 7. Rủi ro còn lại (ghi vào báo cáo để thể hiện tư duy)

- Chứng chỉ TLS tự ký chỉ dùng cho lab. Production thì dùng ALB + ACM, có thể thêm AWS WAF.
- TOTP chưa chống replay trong cùng 30 giây.
- Cache chặn nằm riêng trong từng Gunicorn worker. Một IP bị khóa ở worker A vẫn có thể lọt vào worker B trong tối đa 5 giây, cho tới khi Lambda ghi xong DynamoDB.
- Chưa có luật cho việc dùng root account (CIS 1.7) và chưa giới hạn `reserved_concurrency` cho Lambda. Đây là hai việc nên làm tiếp nếu còn thời gian trước 20/11.
- SNS topic chưa mã hóa KMS.
- `cdk.context.json` chứa VPC ID và Account ID thật. Che đi trước khi để repo public.
