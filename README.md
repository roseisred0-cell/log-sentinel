# LogSentinel — SIEM + SOAR trên AWS (FCAJ)

Giám sát log tập trung, phát hiện tấn công web/IAM và tự động khóa IP kẻ tấn công.
SOC Console có đăng ký tài khoản (Amazon Cognito, chấm độ mạnh mật khẩu, 2FA tùy chọn), phân vai trò và duyệt người dùng.
Region: `ap-southeast-1`. IaC: AWS CDK (Python).

```
Internet ──443──> Nginx (TLS, rate-limit, ghi đè X-Forwarded-For)
                    └─> Gunicorn 127.0.0.1:8080 (Flask, 2FA TOTP, BlockList cache)
                          └─ access.log ─> CloudWatch Agent ─> /logsentinel/sample-app ─┐
CloudTrail (multi-region, KMS) ─> S3 + /logsentinel/cloudtrail ─────────────────────────┤
                                                                                        v
                                         AnomalyDetectorLambda ─> DynamoDB IncidentTable (KMS, TTL)
                                                │                   └─ BLOCKED_IP#<ip> ─> web app 403
                                                └─> SNS email + Telegram + metric EMF/Dashboard
```

| Tài liệu | Nội dung |
|---|---|
| `docs/SECURITY_REVIEW.md` | Lỗ hổng đã vá, đối chiếu kế hoạch, runbook GameDay, ghi chú FinOps |
| `docs/USER_GUIDE.md` | Hướng dẫn cho khách hàng: SOC Console (`/console`), ý nghĩa từng luật |
| `docs/LOG_CONVENTION.md` | Hợp đồng log giữa web app và Detector |
| `HANDOVER_NGUOI_B.md` | Bàn giao A → B |

## Chạy nhanh

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -v
python -m pytest tests/unit/test_redteam_scenarios.py -v   # kịch bản tấn công (red-team), chạy offline
cdk deploy --require-approval never -c alert_email=<email> -c admin_cidr=<ip>/32   # chế độ trực tiếp (lab)
# Output: UserPoolId, UserPoolClientId. Nâng người đăng ký đầu tiên lên quản trị (xem docs/USER_GUIDE.md):
# aws cognito-idp admin-add-user-to-group --user-pool-id <UserPoolId> --username <email> --group-name soc-admins
python attack_sim.py logs                                   # bơm log giả
python attack_sim.py http --target https://<Public-IP> --insecure
python iam_tamper.py
```

## Hai chế độ triển khai

| | Trực tiếp (mặc định) | Edge (`-c enable_edge=true`) |
|---|---|---|
| Đường vào | Internet → IP của máy, cổng 443 | Internet → CloudFront + AWS WAF → máy (cổng 80, chỉ nhận từ CloudFront) |
| Chứng chỉ | Tự ký, trình duyệt cảnh báo | Chứng chỉ thật của `*.cloudfront.net` |
| Địa chỉ | Đổi mỗi lần thay máy | Cố định |
| IP bị SOAR khóa | Bị chặn trong web app (request vẫn tới máy) | Bị chặn tại WAF trong ≤ 1 phút, không tới máy |
| Chống DDoS | Giới hạn theo IP ở Nginx | Thêm giới hạn tốc độ ở biên, danh sách IP xấu của AWS, Shield Standard của CloudFront |
| Chi phí thêm | 0 | WAF khoảng 10 USD/tháng + phí theo request |

```bash
cdk bootstrap aws://<account-id>/us-east-1      # một lần; WAF cho CloudFront bắt buộc nằm ở us-east-1
cdk deploy --all --require-approval never -c enable_edge=true \
    -c alert_email=<email> -c admin_cidr=<ip>/32 \
    -c console_cidrs=<dải-ip-văn-phòng>          # tùy chọn: chỉ dải này vào được Console
```

Tham số khác: `-c monthly_budget_usd=20` (cảnh báo chi phí tài khoản qua email, `0` để tắt), `-c detector_max_concurrency=5` (trần Lambda chạy song song, cần quota tài khoản ≥ 105), `-c enable_app_log_archive=true` (Firehose → S3).

Dọn dẹp: `cdk destroy --all` nếu đã bật edge, hoặc `cdk destroy` (mọi resource đều để `RemovalPolicy.DESTROY`).
