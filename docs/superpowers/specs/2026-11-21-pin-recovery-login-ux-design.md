# Lấy lại PIN bằng câu hỏi bảo mật + chỉnh giao diện đăng nhập

Ngày: 21/11/2026. Trạng thái: chủ dự án đã duyệt.

## Mục đích

Admin quên PIN mục Phân quyền hiện phải nhờ admin khác hoặc xóa bản ghi `ADMIN_PIN#` bằng AWS CLI. Chủ dự án
muốn admin tự lấy lại PIN được. Cùng lúc, sửa hai chỗ người dùng bị kẹt ở màn hình đăng nhập và cho vào mục bật
2FA nhanh hơn.

## Mục tiêu / không làm / không được xảy ra

- Mục tiêu: admin Cognito tự đặt lại PIN; mọi bước đăng nhập đều có đường quay lại; bật 2FA bằng một cú bấm.
- Không làm: tự lấy lại PIN cho `admin` nội bộ (vẫn dùng AWS CLI, xem `LOG_CONVENTION.md`); nút Back của trình duyệt.
- Không được xảy ra: kẻ chỉ cầm phiên đăng nhập (cookie/token) mà không có mật khẩu và điện thoại 2FA đặt lại
  được PIN.

## Các cách đã cân nhắc

| Cách | Đánh đổi | Kết quả |
|---|---|---|
| A. Chỉ câu hỏi bảo mật | Đơn giản; câu trả lời (quê, tên phụ huynh…) dễ tra trên mạng xã hội | Loại |
| **B. Câu hỏi + mật khẩu + mã 2FA** | Thêm một bước nhập; Cognito không kiểm tra riêng được mã TOTP nên phải đăng nhập lại (`identity.reauthenticate`, như khi tắt 2FA) | **Chủ dự án chọn** |

## Thiết kế

### 1. Lấy lại PIN

- **Câu hỏi** (cố định, mã `idol`, `parent`, `hometown`, `sport`): Thần tượng của bạn là ai? / Tên của phụ huynh
  bạn là gì? / Quê hương của bạn ở đâu? / Môn thể thao bạn ưa thích?
- **Đặt câu hỏi:** form đặt PIN có thêm chọn câu hỏi + câu trả lời (bắt buộc khi đặt PIN mới). Admin đã có PIN nhưng
  chưa có câu hỏi thấy lời nhắc và form bổ sung (cần mục đang mở bằng PIN).
- **Lưu:** bản ghi `ADMIN_PIN#<principal>` / sort key `RECOVERY`: `question`, `hash` (scrypt), `salt`, `failures`,
  `locked_until`. Cùng tiền tố khóa chính `ADMIN_PIN#` nên không đổi quyền IAM của EC2. Admin khác đặt lại PIN chỉ
  xóa sort key `PIN`, giữ câu hỏi.
- **Chuẩn hóa câu trả lời trước khi băm:** bỏ dấu tiếng Việt (gồm `đ` → `d`), chữ thường, gộp khoảng trắng, cắt hai
  đầu. Câu trả lời sau chuẩn hóa dài 2–100 ký tự.
- **Lấy lại:** link "Quên PIN?" cạnh ô mở khóa → hiện câu hỏi đã chọn → nhập câu trả lời, mật khẩu, mã 2FA →
  `POST /api/governance/pin/recover`. Thứ tự kiểm tra: khóa câu hỏi → câu trả lời → `reauthenticate`. Đúng hết:
  xóa PIN, xóa bộ đếm câu hỏi; người dùng đặt PIN mới ngay.
- **Chống đoán:** câu trả lời sai 5 lần khóa 15 phút (giống PIN). Mật khẩu/2FA sai tính như `FAILED_LOGIN` (luật
  brute-force khóa IP), như `/api/mfa/disable`.
- **Cảnh báo:** thành công ghi sự kiện `ADMIN_PIN_RECOVERED` (HIGH, không khóa IP) → email + Telegram; bị khóa vì
  sai câu trả lời ghi `ADMIN_PIN_RECOVERY_LOCKED` (HIGH). Detector thêm hai loại này.
- Chỉ admin Cognito. `admin` nội bộ gọi API nhận `403`.

### 2. Giao diện đăng nhập

- Nút "Quay lại" ở bước nhập mã 2FA (`panel-mfa`) và bước xác nhận email (`panel-confirm`) → về màn hình đăng nhập,
  xóa trạng thái MFA đang dở.
- Chưa bật 2FA: banner "Bạn chưa bật 2FA. [Bật ngay]"; nút mở thẳng phần quét QR (mở thẻ Tài khoản, chạy thiết lập,
  cuộn tới). Áp dụng cho cả thông báo bắt buộc 2FA của admin.

## Để người thực hiện tự quyết

Tên hàm, chữ trên nút, cách hiển thị banner; tên mã lỗi API mới.
