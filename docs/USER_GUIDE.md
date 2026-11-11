# Hướng dẫn sử dụng LogSentinel cho khách hàng (quản trị viên SME)

## Khách hàng dùng hệ thống qua 3 kênh

| Kênh | Dùng để | Cách vào |
|---|---|---|
| **SOC Console** (web) | Xem sự cố, xem IP đang bị khóa, gỡ khóa | `https://<địa-chỉ-máy-chủ>/console` (giá trị `SocConsoleUrl` sau khi deploy) |
| **Email + Telegram** | Nhận cảnh báo ngay khi có sự cố, không cần mở web | Email đăng ký lúc deploy; Telegram qua bot của nhóm |
| **CloudWatch Dashboard** | Biểu đồ xu hướng, trạng thái alarm (cho người có tài khoản AWS) | AWS Console → CloudWatch → Dashboards → `LogSentinel-Overview` |

## Lần đầu sử dụng

1. Người triển khai gửi cho quản trị viên: địa chỉ Console, mật khẩu, và trang đăng ký 2FA.
2. Mở Google Authenticator (hoặc Microsoft Authenticator), quét mã QR trên trang đăng ký 2FA.
3. Vào `https://<địa-chỉ>/console`. Trình duyệt sẽ cảnh báo chứng chỉ (bản lab dùng chứng chỉ tự ký): chọn **Advanced → Proceed**.
4. Nhập tài khoản `admin`, mật khẩu, và mã 6 số trong Authenticator.

## Đăng ký tài khoản cá nhân (dành cho nhân viên của khách hàng)

1. Mở `/console` → tab **Đăng ký** → nhập email và mật khẩu. Thanh **Độ mạnh** hiện năm mức: *Rất yếu, Yếu, Trung bình, Mạnh, Rất mạnh*. Hệ thống chỉ chấp nhận từ **Trung bình** trở lên; hãy đạt **Mạnh** nếu được (từ 12 ký tự, có chữ hoa, chữ thường, số, ký tự đặc biệt, không chứa tên email, không là mật khẩu phổ biến).
2. Cognito gửi mã 6 số tới email. Nhập mã ở bước **Xác nhận email**.
3. Đăng nhập. Tài khoản mới ở trạng thái **Chờ duyệt**: chưa xem được sự cố. Quản trị viên vào mục **Người dùng → Chờ duyệt → Duyệt**. Lần đăng nhập kế tiếp bạn sẽ thấy dữ liệu (tối đa 30 phút sau khi được duyệt nếu đang đăng nhập sẵn).

| Vai trò | Quyền |
|---|---|
| Chờ duyệt | Chỉ thấy trang **Tài khoản** (bật/tắt 2FA) |
| Người xem | Xem sự cố và IP bị khóa |
| Quản trị | Như người xem + gỡ khóa IP + duyệt/thu hồi người dùng |

**Bật / tắt 2FA:** bấm **Tài khoản** → **Bật 2FA** → quét QR bằng Google/Microsoft Authenticator (hoặc nhập khóa thủ công) → nhập mã 6 số. Từ lần đăng nhập sau, hệ thống hỏi thêm mã OTP. Muốn tắt thì bấm **Tắt 2FA** ở cùng chỗ; hệ thống hỏi lại **mật khẩu và mã OTP hiện tại** (để người nhặt được máy đang đăng nhập không tự tắt được lớp bảo vệ của bạn). 2FA là **tùy chọn** với tài khoản đăng ký; tài khoản nội bộ `admin` luôn bắt buộc 2FA.

**Quên mật khẩu:** ở màn hình đăng nhập bấm **Quên mật khẩu?** → nhập email → nhập mã 6 số nhận qua email và mật khẩu mới (cùng thanh độ mạnh, tối thiểu *Trung bình*). Hệ thống luôn báo "nếu email đã đăng ký thì mã đã được gửi", dù email có tồn tại hay không. Nhập sai mã nhiều lần hoặc yêu cầu liên tục sẽ bị chặn tạm thời.

**Quản trị viên đầu tiên:** tài khoản nội bộ `admin` (mật khẩu + OTP lấy qua SSM, xem phần trên) duyệt được người xem. Muốn một tài khoản Cognito thành **Quản trị** thì làm bằng AWS CLI (web app cố ý không cho tự nâng quyền admin):

```bash
aws cognito-idp admin-add-user-to-group --user-pool-id <UserPoolId> --username <email> --group-name soc-admins
```

## Dùng hằng ngày

- **4 ô số trên cùng:** tổng sự cố gần đây, số mức CRITICAL, số mức HIGH, số IP đang bị khóa.
- **Bảng "IP đang bị khóa":** mỗi IP bị khóa 24 giờ. Nếu khóa nhầm (ví dụ nhân viên gõ sai mật khẩu 5 lần), bấm **Gỡ khóa**. Có hiệu lực trong tối đa 60 giây. Thao tác gỡ khóa được ghi lại trong log.
- **Bảng "Sự cố gần đây":** 50 sự cố mới nhất, lọc được theo mức độ. Trang tự làm mới mỗi 15 giây.
- Phiên đăng nhập hết hạn sau 30 phút. Xong việc thì bấm **Đăng xuất**: phiên bị thu hồi ngay trên máy chủ, nên dù ai đó đã sao chép cookie của bạn cũng không dùng lại được.

## Ý nghĩa các luật

| Luật | Nghĩa là | Nên làm gì |
|---|---|---|
| `BRUTE_FORCE_DETECTED` | Một IP sai mật khẩu 5 lần trong 60 giây | IP đã tự khóa. Nếu là người nhà thì gỡ khóa |
| `SLOW_BRUTE_FORCE` | Một IP sai mật khẩu 20 lần trong 1 giờ, rải đều để né luật trên | IP đã tự khóa. Kiểm tra các tài khoản bị nhắm tới |
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

Chi tiết sự cố IAM có trường `via_service: cloudformation.amazonaws.com` nghĩa là thay đổi đến từ một lần `cdk deploy` — thường là của chính bạn, nhưng vẫn nên đối chiếu thời gian.

## Giới hạn của bản lab

- Một tài khoản quản trị duy nhất, chứng chỉ tự ký, Console chạy chung máy với ứng dụng được bảo vệ.
- Bản thương mại nên tách Console ra riêng (CloudFront + Cognito), có tên miền và chứng chỉ ACM, nhiều tài khoản và phân quyền.
