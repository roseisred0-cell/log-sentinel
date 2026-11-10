# LogSentinel — SIEM + SOAR trên AWS (FCAJ)

Giám sát log tập trung, phát hiện tấn công web/IAM và tự động khóa IP kẻ tấn công.
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
| `docs/LOG_CONVENTION.md` | Hợp đồng log giữa web app và Detector |
| `HANDOVER_NGUOI_B.md` | Bàn giao A → B |

## Chạy nhanh

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -v
cdk deploy --require-approval never -c alert_email=<email> -c admin_cidr=<ip>/32
python attack_sim.py logs                                   # bơm log giả
python attack_sim.py http --target https://<Public-IP> --insecure
python iam_tamper.py
```

Dọn dẹp: `cdk destroy` (mọi resource đều để `RemovalPolicy.DESTROY`).
# log-sentinel
