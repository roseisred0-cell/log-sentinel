# Kiến thức cho trợ lý AI của LogSentinel

## Tổng quan
LogSentinel là SIEM + SOAR trên AWS: web app (EC2, Nginx + Flask) đứng sau CloudFront + AWS WAF; log web app và CloudTrail vào CloudWatch; Lambda Detector áp 26 luật theo thời gian thực, ghi sự cố vào DynamoDB, cảnh báo qua email (SNS) và Telegram.
Ba lớp chặn IP: web app tự chặn (60 giây) → khóa trong DynamoDB 24 giờ → Lambda WafSync đẩy IP bị khóa lên WAF mỗi phút để chặn ngay tại biên.
IP trong danh sách quản trị (admin_cidr) không bao giờ bị khóa.
Vai trò Console: admin (gỡ khóa IP, mục Phân quyền, bắt buộc 2FA), viewer (chỉ xem), pending (chờ duyệt).

## Dùng hằng ngày

- **4 ô số trên cùng:** tổng sự cố gần đây, số mức CRITICAL, số mức HIGH, số IP đang bị khóa.
- **Bảng "IP đang bị khóa":** mỗi IP bị khóa 24 giờ. Nếu khóa nhầm (ví dụ nhân viên gõ sai mật khẩu 5 lần), bấm **Gỡ khóa**. Có hiệu lực trong tối đa 60 giây. Thao tác gỡ khóa được ghi lại trong log.
- **Bảng "Sự cố gần đây":** 50 sự cố mới nhất, lọc được theo mức độ. Trang tự làm mới mỗi 15 giây.
- Phiên đăng nhập hết hạn sau 30 phút. Xong việc thì bấm **Đăng xuất**: phiên bị thu hồi ngay trên máy chủ, nên dù ai đó đã sao chép cookie của bạn cũng không dùng lại được.

## Mục Phân quyền (dành cho quản trị viên)

**Mã PIN riêng.** Lần đầu vào mục **Phân quyền**, bạn tự đặt một PIN 6 số, khác mật khẩu đăng nhập. Không dùng mã dễ đoán như `123456`, `000000`, `121212`, `112233`. Nhập PIN đúng thì mục mở trong **10 phút**; hết giờ hoặc đăng xuất phải nhập lại. Sai **5 lần** thì PIN bị khóa **15 phút**, và các quản trị viên khác nhận cảnh báo.

**Thao tác cần nhiều người đồng ý.** Mọi thao tác chỉ làm được khi mục đang mở. Riêng đề xuất, **Đồng ý**, **Từ chối** và **Đặt lại PIN** phải nhập lại PIN vào ô *PIN xác nhận* mỗi lần bấm:

| Thao tác | Ai làm | Cần bao nhiêu người đồng ý |
|---|---|---|
| Duyệt người mới thành Người xem, thu hồi Người xem | Một quản trị viên | Không cần |
| Nâng Người xem lên Quản trị, hạ Quản trị xuống Người xem | Một quản trị viên đề xuất | **Đa số** quản trị viên, tối thiểu 2 (2 admin cần 2, 3 cần 2, 4 cần 3). Người bị hạ không được bỏ phiếu |
| Vô hiệu hóa tài khoản | Một quản trị viên đề xuất | 2 người (người đề xuất và một quản trị viên khác) |

- Người đề xuất tính là một phiếu. Các quản trị viên khác nhận email/Telegram và vào bảng **Yêu cầu chờ duyệt** để bấm **Đồng ý** hoặc **Từ chối**. Một phiếu từ chối hủy yêu cầu ngay. Yêu cầu hết hạn sau **24 giờ**.
- Hệ thống **luôn giữ tối thiểu 2 quản trị viên**: không hạ hay vô hiệu hóa được nếu sẽ còn dưới 2. Khi đang dưới 2, mục Phân quyền hiện cảnh báo đỏ. Không ai tự hạ quyền hay tự vô hiệu hóa chính mình được.
- Khi thao tác có hiệu lực (kể cả duyệt hay thu hồi Người xem), người bị tác động bị đăng xuất khỏi mọi phiên và phải đăng nhập lại để nhận vai trò mới. Người vừa được nâng lên Quản trị sẽ phải bật 2FA trước khi làm việc.
- Nâng/hạ quyền, vô hiệu hóa, đề xuất mới, đặt lại hay khóa PIN đều gửi cảnh báo email/Telegram. Duyệt, thu hồi Người xem và từ chối yêu cầu chỉ ghi vào nhật ký kiểm toán, không gửi cảnh báo.

**Quên PIN.** Nhờ một quản trị viên khác bấm **Đặt lại PIN** cạnh tên bạn (người đó nhập PIN của chính họ). Lần vào sau bạn tự đặt PIN mới. Mỗi lần đặt lại đều có cảnh báo.

**Quản trị viên đầu tiên (chế độ khởi tạo).** Khi hệ thống chưa có đủ 2 quản trị viên Cognito, tài khoản nội bộ `admin` (mật khẩu + OTP lấy qua SSM, xem phần trên) cũng phải đặt PIN, và được **tự mình** nâng một Người xem lên Quản trị. Cách làm: cho 2 người đăng ký, duyệt họ thành Người xem, rồi bấm **Đề xuất lên Quản trị** cho từng người. Khi đã đủ 2 quản trị viên Cognito, `admin` nội bộ chỉ còn xem và gỡ khóa IP (không duyệt hay thu hồi Người xem nữa).

**Quên PIN của `admin` nội bộ:** xóa bằng AWS CLI, rồi đặt PIN mới ở lần vào sau:

```powershell
aws dynamodb delete-item --region ap-southeast-1 --table-name <IncidentTable> `
  --key '{"incident_id":{"S":"ADMIN_PIN#local:admin"},"timestamp":{"S":"PIN"}}'
```

## Ý nghĩa các luật

| Luật | Nghĩa là | Nên làm gì |
|---|---|---|
| `BRUTE_FORCE_DETECTED` | Một IP sai mật khẩu 5 lần trong 60 giây | IP đã tự khóa. Nếu là người nhà thì gỡ khóa |
| `SLOW_BRUTE_FORCE` | Một IP sai mật khẩu 20 lần trong 1 giờ, rải đều để né luật trên | IP đã tự khóa. Kiểm tra các tài khoản bị nhắm tới |
| `LOGIN_FAILURE_SPIKE` | Toàn hệ thống có hơn 50 lần đăng nhập sai trong 5 phút, từ nhiều IP vào nhiều tài khoản | Dấu hiệu dùng danh sách mật khẩu bị lộ để thử hàng loạt. Yêu cầu người dùng đổi mật khẩu và bật 2FA |
| `SCAN_DETECTED` | Một IP gọi 30 đường dẫn không tồn tại trong 60 giây (đang dò tìm lỗ hổng) | IP đã tự khóa. Không cần làm gì thêm |
| `ACCOUNT_UNDER_ATTACK` | Một tài khoản bị đoán sai 10 lần trong 5 phút từ **nhiều IP khác nhau** (tấn công phân tán) | Không IP nào bị khóa tự động. Đổi mật khẩu tài khoản đó, bật 2FA, cân nhắc thu hẹp `ingress_cidr` |
| `SQL_INJECTION` | Có người thử chèn mã độc vào ô tìm kiếm | IP đã tự khóa. Không cần làm gì thêm |
| `MFA_BYPASS_ATTEMPT` | Mật khẩu **đúng** nhưng mã OTP sai | **Đổi mật khẩu ngay**: mật khẩu có thể đã lộ |
| `ROOT_ACCOUNT_LOGIN` | Có người đăng nhập tài khoản root AWS | Xác nhận có phải mình không; nếu không, đổi mật khẩu root và gọi hỗ trợ AWS |
| `CONSOLE_LOGIN_NO_MFA` | Đăng nhập AWS Console **thành công** mà không dùng MFA | Bật MFA cho user đó |
| `CONSOLE_BRUTE_FORCE` | Một IP đăng nhập AWS Console sai 5 lần trong 5 phút | Kiểm tra user bị nhắm tới; đổi mật khẩu, bật MFA. Hệ thống không khóa được IP ở AWS Console |
| `MFA_TAMPERING` | Có người tắt/xóa thiết bị MFA | Kiểm tra ai làm; bật lại MFA |
| `CLOUDTRAIL_TAMPERING` | Có người tắt hoặc xóa nhật ký kiểm toán | Dấu hiệu xóa dấu vết. Bật lại trail, rà soát tài khoản đã thực hiện |
| `IAM_ACCESS_KEY_CREATED` / `IAM_POLICY_ATTACHED` / `IAM_INLINE_POLICY_PUT` | Tạo khóa truy cập hoặc cấp thêm quyền cho user, role hoặc group | Nếu không phải thay đổi đã lên kế hoạch: thu hồi khóa, gỡ quyền |
| `IAM_POLICY_VERSION_CREATED` / `IAM_TRUST_POLICY_CHANGED` | Sửa nội dung policy đang dùng, hoặc cho phép bên ngoài mượn quyền của một role | Xem ai làm; khôi phục phiên bản policy / trust policy cũ |
| `IAM_LOGIN_PROFILE_CHANGED` / `IAM_USER_ADDED_TO_GROUP` | Đặt mật khẩu Console cho user khác, hoặc thêm user vào nhóm | Dấu hiệu cài cửa hậu. Nếu không phải mình: đặt lại mật khẩu, gỡ khỏi nhóm |
| `KMS_KEY_TAMPERING` | Có người vô hiệu hóa hoặc hẹn xóa khóa mã hóa | **Khẩn cấp**: hủy lịch xóa khóa (`aws kms cancel-key-deletion`), bật lại khóa. Mất khóa là mất toàn bộ log và bảng sự cố |
| `ROLE_REQUEST_CREATED` | Một quản trị viên đề xuất nâng/hạ Quản trị hoặc vô hiệu hóa tài khoản | Vào mục **Phân quyền** bỏ phiếu. Nếu không ai trong nhóm đề xuất: **Từ chối** ngay, đổi mật khẩu người đề xuất |
| `ADMIN_ROLE_CHANGED` / `USER_DISABLED` | Thao tác đã đủ phiếu và có hiệu lực (`bootstrap: true` = admin nội bộ tự nâng quyền lúc khởi tạo) | Đối chiếu với kế hoạch của nhóm |
| `ROLE_CHANGE_FAILED` | Đủ phiếu nhưng Cognito lỗi nên chưa thực hiện | Đợi vài phút rồi bấm **Đồng ý** lại trên yêu cầu đó |
| `ADMIN_PIN_LOCKED` | Có người nhập sai PIN mục Phân quyền 5 lần | Hỏi chủ tài khoản. Nếu không phải họ: phiên đăng nhập của họ có thể đã bị chiếm, đổi mật khẩu |
| `ADMIN_PIN_RESET` | Một quản trị viên đặt lại PIN của người khác | Xác nhận người được đặt lại có yêu cầu việc này |

Chi tiết sự cố IAM có trường `via_service: cloudformation.amazonaws.com` nghĩa là thay đổi đến từ một lần `cdk deploy` — thường là của chính bạn, nhưng vẫn nên đối chiếu thời gian.
