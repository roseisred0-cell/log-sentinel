# Chi phí vận hành LogSentinel (ước tính theo tháng)

> Số liệu là **ước tính** theo giá niêm yết region `ap-southeast-1` tại thời điểm viết (11/2026), làm tròn,
> chưa gồm thuế. Trước khi đưa vào báo cáo hãy đối chiếu lại bằng [AWS Pricing Calculator](https://calculator.aws/).
> Lưu lượng giả định: đồ án / doanh nghiệp nhỏ (vài nghìn request mỗi ngày, vài chục cảnh báo mỗi tháng).

## 1. Chế độ trực tiếp — mặc định (`cdk deploy`)

| Dịch vụ | Cấu hình | USD/tháng | Ghi chú |
|---|---|---|---|
| EC2 | 1 × `t3.micro`, chạy 24/7 | 9,6 | 0 nếu tài khoản còn Free Tier 12 tháng |
| Địa chỉ IPv4 công cộng | 1 địa chỉ | 3,7 | AWS tính phí mọi IPv4 công cộng từ 02/2024 |
| EBS | 8 GB gp3, mã hóa | 0,8 | |
| KMS | 1 khóa CMK | 1,0 | Mã hóa bảng sự cố và log CloudTrail |
| Secrets Manager | 1 secret (Telegram) | 0,4 | |
| CloudWatch | 3 alarm, log 30 ngày, 1 dashboard | 0,5 – 1 | 3 dashboard đầu miễn phí |
| CloudTrail | 1 trail sự kiện quản trị | 0 | Trail đầu tiên miễn phí |
| Lambda, DynamoDB, SNS, S3, Cognito, Athena | Theo lượt dùng | < 1 | Nằm trong hạn mức miễn phí ở lưu lượng này |
| **Tổng** | | **≈ 17** | **≈ 6 – 7 nếu còn Free Tier EC2** |

## 2. Chế độ edge — tùy chọn (`-c enable_edge=true`)

| Thêm so với mục 1 | USD/tháng | Ghi chú |
|---|---|---|
| AWS WAF | ≈ 11 | 5 (web ACL) + 1 × 6 luật, cộng 0,6 cho mỗi triệu request |
| CloudFront | ≈ 0 | Hạn mức miễn phí 1 TB và 10 triệu request mỗi tháng |
| Secrets Manager (header gốc) | 0,4 | |
| Lambda đồng bộ WAF | ≈ 0 | ~43.800 lượt chạy mỗi tháng, trong hạn mức miễn phí |
| **Tổng chế độ edge** | **≈ 28 – 30** | |

## 3. Hướng mở rộng: 2 AZ (chưa triển khai, xem `SECURITY_REVIEW.md` mục 8)

| Thêm so với mục 2 | USD/tháng |
|---|---|
| Application Load Balancer (gồm 2 IPv4) | ≈ 26 |
| Máy EC2 thứ hai + EBS + IPv4 | ≈ 14 |
| **Tổng 2 AZ** | **≈ 70** |

Tên miền riêng (nếu dùng): `.net` khoảng 15 – 17 USD/năm, Route 53 hosted zone 0,5 USD/tháng, chứng chỉ ACM miễn phí.

## 4. Chi phí tăng khi bị tấn công

| Tình huống | Thứ tăng | Trần bảo vệ |
|---|---|---|
| Flood request vào web | Log CloudWatch (≈ 0,7 USD/GB), lượt chạy Lambda, lượt ghi DynamoDB | Giới hạn tốc độ Nginx; `-c detector_max_concurrency=5`; WAF ở chế độ edge |
| Xoay vòng nhiều IP | Lượt đọc DynamoDB (kiểm tra danh sách chặn) | Cache trong RAM: mỗi IP tối đa 1 lượt đọc / 5 giây |
| Bất kỳ | Tổng hóa đơn | AWS Budgets gửi email ở 80% thực tế và 100% dự báo (`-c monthly_budget_usd=`) |

## 5. So với mục tiêu ban đầu của đồ án

Tài liệu bàn giao ghi "dưới 5 USD/tháng". Con số đó chỉ đúng khi tài khoản còn Free Tier cho EC2 và chưa tính
phí IPv4 công cộng. Không có Free Tier, mức thực tế của chế độ mặc định là khoảng 17 USD/tháng.

Cách giảm khi chỉ demo: tắt máy EC2 ngoài giờ demo (Detector, CloudTrail và cảnh báo vẫn chạy vì nằm ở Lambda),
hoặc `cdk destroy` sau buổi bảo vệ.
