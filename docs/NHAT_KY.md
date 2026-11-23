# Nhật ký dự án LogSentinel

Tổng quan và trạng thái hệ thống: [PROPOSAL.md](PROPOSAL.md). Quyết định thiết kế đã chốt nằm ở cuối file.

## 11/11/2026

- Gói Free không dùng được Firehose: chuyển phần lưu log web xuống S3 thành tùy chọn (12/11 gỡ hẳn).
- SOC Console có tài khoản Cognito: đăng ký, xác nhận email, thanh độ mạnh mật khẩu 5 mức, 2FA TOTP tùy chọn, quên mật khẩu, ba vai trò (Chờ duyệt, Người xem, Quản trị), thu hồi phiên khi đăng xuất.
- Detector tăng từ 9 lên 20 luật: brute-force chậm và phân tán, `LOGIN_FAILURE_SPIKE`, `SCAN_DETECTED`, `CONSOLE_BRUTE_FORCE`, 9 sự kiện leo thang quyền IAM, `KMS_KEY_TAMPERING`.
- Bộ lọc SQL injection: trước để lọt 24/41 kiểu né, nay 0/41. Tin Telegram chuyển sang dạng HTML gọn cho điện thoại.
- Hạ tầng:
  - Athena: bảng `cloudtrail_logs`, giới hạn 1 GB mỗi truy vấn, 5 truy vấn mẫu.
  - Log CloudWatch và bản ghi sự cố lưu 30 ngày (trước là 7).
  - Viết code chế độ edge.
  - Nginx giới hạn tốc độ riêng cho các đường dẫn đăng nhập.
- Viết `COST.md`. 539 test.
- Deploy chế độ trực tiếp lần đầu. Phát hiện brute-force chạy thật trên AWS.

## 12/11/2026

- **Phân quyền admin** (viết test trước, 6 seam A–F). Có giao diện, review hai trục rồi sửa theo review:
  - chỉ đánh dấu "đã thực thi" sau khi Cognito thành công;
  - khóa thực thi dùng chung;
  - hủy mọi phiên của người bị đổi quyền ngay lập tức.
- **Bảo mật EC2:**
  - Lambda `GovernanceExecutor` là nơi duy nhất được ghi vào Cognito.
  - Sandbox systemd đạt điểm 1.5 OK.
  - `dnf-automatic` tự cài bản vá bảo mật.
  - Máy chỉ được kết nối ra qua cổng 443.
- **IP tĩnh + chế độ edge** (CloudFront + WAF, bootstrap `us-east-1`), đã deploy. Kiểm chứng:
  - Stop/Start máy giữ nguyên IP, CloudFront vào lại sau 10 giây.
  - Vào thẳng bằng IP bị chặn.
  - `nginx -t` OK.
- **Kiểm thử trên AWS:**
  - Brute-force bắt đúng ở lần sai thứ 5, ghi IP thật của người dùng (không phải IP CloudFront).
  - `SCAN_DETECTED` bắt đúng ở lần 404 thứ 30.
  - `iam_tamper.py` cho 6/6 sự cố đúng luật.
  - Athena chạy trên dữ liệu thật, quét 3,1 MB.
- Cột Chi tiết / Đối tượng hiển thị câu tiếng Việt cho đủ 26 luật (`incident-text.js`), có nút "Xem dữ liệu gốc".
- **Trợ lý AI trên Bedrock:** đã làm và deploy, nhưng tài khoản gói Free không gọi được model Claude nào (404 / 403 / AccessDenied, kể cả sau khi chấp nhận thỏa thuận Marketplace). Không phải lỗi code. Đã gỡ trợ lý này cùng Firehose cho gọn code. 789 test.

## 19/11/2026

- Vẽ sơ đồ kiến trúc.
- Phân tích bảo mật, chưa sửa. Các điểm yếu theo thứ tự nên sửa:
  1. WAF thiếu `CommonRuleSet` / `SQLiRuleSet`.
  2. Nginx tin `X-Forwarded-For` từ mọi nguồn. (23/11 đính chính: không khai thác được, vì chỉ CloudFront vào được máy, có header bí mật, và `real_ip_recursive off` chỉ lấy địa chỉ CloudFront tự nối vào.)
  3. CloudFront → EC2 đi HTTP.
  4. Chỉ có một EC2.
- **Trợ lý AI dùng OpenAI** (5 seam TDD): `sample_app/chat_assistant.py`, route `POST /api/chat`, hạn mức trong DynamoDB, chỉ đọc. Biện pháp bảo mật ghi ở `SECURITY_REVIEW.md` mục 6.
- **Thẻ Thống kê sự cố:**
  - Ba khoảng 24 giờ / 7 ngày / 30 ngày.
  - Cột xếp chồng theo mức độ và ma trận nhiệt luật × thời gian.
  - Máy chủ tổng hợp sẵn (`/api/stats`), lưu kết quả 5 phút.
- **Telegram chạy thật** (bot `Logsentinel_QM3004_bot`): nhận đủ 3 tin trong vài giây, chống trùng lặp đúng. Tin và email chuyển sang tiếng Việt có dấu, giờ Việt Nam.
- **Sự cố deploy:** lệnh deploy thiếu `--all -c enable_edge=true -c static_ip=true`, nên CDK chuyển về chế độ trực tiếp, xóa CloudFront và trả lại Elastic IP cũ. Cùng lúc, `openai>=3.55` đòi Python ≥ 3.10 trong khi EC2 chạy 3.9. Đã ghim `openai>=2.40,<3` và thêm test.
- Bảng sự cố mặc định hiện 10 dòng, có nút "Xem thêm".
- Sửa giao diện khi quản trị viên chưa đặt PIN: hiện số người đang chờ duyệt, ô PIN chỉ nhận chữ số. 846 test.

## 21/11/2026

- Thiết kế + kế hoạch lấy lại PIN bằng câu hỏi bảo mật và chỉnh giao diện đăng nhập (`docs/superpowers/`). Chưa làm.
- Đưa ba điểm yếu G3, G4, G5 vào hướng phát triển (`SECURITY_REVIEW.md` mục 8.4).

## 23/11/2026

- Vẽ lại sơ đồ theo kiểu đánh số bước 1–17, mọi icon 60×60, đối chiếu với tài nguyên AWS đang chạy:
  - default VPC, `ap-southeast-1a`;
  - EC2 `i-0dc0d22dad246ff78`;
  - Elastic IP `13.215.187.81`;
  - CloudFront `dww0e125hyfiv.cloudfront.net`.
- Viết `PROPOSAL.md`. Gọn tài liệu: gộp 3 nhật ký thành file này, bỏ `TONG_QUAN_DU_AN.md`, cắt phần cũ trong `SECURITY_REVIEW.md`.
- Đẩy lên GitHub hai nhánh `so-do-va-tai-lieu` và `sua-3-loi`.
- Review hai trục (quy chuẩn + đặc tả, kỹ năng `code-review`) toàn bộ code từ baseline. Sửa bằng TDD:
  - Phiếu từ chối hoặc hết hạn chen vào lúc đang thực thi: Cognito đã đổi vai trò mà bản ghi ghi "đã từ chối". Nay mọi lần đóng yêu cầu đi qua cùng một khóa.
  - Khóa thực thi có thể bị nhả bởi worker không giữ nó (worker chậm quá 30 giây). Nay mỗi lần lấy khóa có mã chủ riêng.
  - Thu hồi (hoặc duyệt) Người xem không hủy phiên, người bị thu hồi vẫn đọc được sự cố tới 30 phút. Nay đăng xuất ngay.
  - Sửa nhỏ: chuỗi lỗi hiển thị cho người dùng thiếu dấu, comment và docstring lỗi thời; tài liệu PIN và cảnh báo cho khớp code. 856 test.

## Quyết định thiết kế đã chốt

### Phân quyền admin (11–12/11)

Luồng vào mục Phân quyền: đăng nhập (admin bắt buộc 2FA) → mở mục **Phân quyền** → nhập **mã PIN riêng**.

| Chủ đề | Quyết định |
|---|---|
| Admin được làm gì | Duyệt người mới thành Người xem, nâng lên Quản trị, hạ xuống Người xem, vô hiệu hóa tài khoản. Không được tự hạ quyền hay tự vô hiệu hóa mình |
| Số phiếu | Duyệt Người xem: một admin. Nâng/hạ Quản trị: **đa số trên tất cả admin**, tối thiểu 2 phiếu (2→2, 3→2, 4→3), người bị hạ không bỏ phiếu. Vô hiệu hóa: 2 người |
| Phiếu | Một phiếu từ chối hủy yêu cầu. Mỗi phiếu (kể cả từ chối) phải nhập PIN. Yêu cầu hết hạn sau 24 giờ, hạn này kiểm tra trong code (không dựa vào TTL của DynamoDB) |
| Tối thiểu 2 admin | Chặn mọi thao tác làm số admin Cognito xuống dưới 2. Dưới 2 thì Console hiện cảnh báo đỏ |
| Chế độ khởi tạo | Bật khi có dưới 2 admin Cognito: `admin` nội bộ được tự nâng một Người xem lên Quản trị. Khi đã đủ 2, `admin` nội bộ chỉ còn xem và gỡ khóa IP, không duyệt hay thu hồi Người xem được nữa |
| 2FA | Admin Cognito chưa bật 2FA chỉ thấy màn hình "Bật 2FA". Admin không có nút "Tắt 2FA". Người xem: 2FA tùy chọn |
| PIN | Đúng 6 chữ số, chặn mã dễ đoán, băm scrypt. Nhập đúng thì mục mở 10 phút. Sai 5 lần khóa 15 phút và sinh `ADMIN_PIN_LOCKED` |
| Quên PIN | Một admin khác đặt lại, không cần thêm người duyệt. PIN của `admin` nội bộ đặt lại bằng AWS CLI |
| Thực thi | Mọi thay đổi vai trò (nâng, hạ, vô hiệu hóa, duyệt và thu hồi Người xem) chạy trong Lambda `GovernanceExecutor`, Lambda tự xác minh người bấm bằng token Cognito. Lambda chỉ tin `admin` nội bộ (không có token) trong chế độ khởi tạo. PIN được kiểm tra và đặt lại trên EC2 (rủi ro ghi ở `SECURITY_REVIEW.md` mục 7) |
| Cảnh báo | Nâng/hạ quyền, vô hiệu hóa, đề xuất mới, thực thi thất bại, đặt lại và khóa PIN sinh cảnh báo HIGH qua email/Telegram, không khóa IP. Duyệt, thu hồi Người xem và từ chối yêu cầu chỉ ghi nhật ký kiểm toán |

### Trợ lý AI (19/11)

- Dùng OpenAI vì chủ dự án chỉ có API key OpenAI. Model là tham số deploy `-c chat_model=...`.
- Người dùng: Quản trị và Người xem.
- Trợ lý đọc sự cố để giải thích và hướng dẫn khắc phục. Chỉ đọc, không có quyền thao tác. Trả lời cả đoạn một lần (không stream).

### Hạ tầng

- Chế độ edge gồm CloudFront + WAF + Elastic IP. Ngưỡng cảnh báo chi phí 35 USD/tháng. Không giới hạn Console theo dải IP, vì IP nhà/4G hay đổi.
- Hoãn: kiến trúc 2 AZ (khoảng 70 USD/tháng), tên miền `.net` (`logsentinel.com` đã có chủ), biểu đồ nâng cao.
- **Lệnh deploy phải giữ chế độ edge:**
  `cdk deploy --all -c enable_edge=true -c static_ip=true -c alert_email=<email> -c admin_cidr=<ip>/32 -c chat_model=<model>`

## Việc còn mở

- Lấy lại PIN bằng câu hỏi bảo mật: có thiết kế và kế hoạch, chưa làm.
- Điểm yếu chưa sửa: WAF chưa bật `CommonRuleSet`; G3, G4, G5 (`SECURITY_REVIEW.md` mục 8.4).
- Đa khách hàng và tích hợp web của khách: chủ dự án chưa quyết.
- Lưu ý nhóm: các nhánh của Người B sửa nhiều phần hạ tầng của Người A (stack CDK, Nginx, bootstrap), nên Người A cần xem trước khi gộp vào `main`. AWS CLI trên máy đang dùng IAM user của Người A.
