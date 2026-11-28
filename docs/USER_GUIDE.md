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
3. Đăng nhập. Tài khoản mới ở trạng thái **Chờ duyệt**: chưa xem được sự cố. Quản trị viên vào mục **Phân quyền → Chờ duyệt → Duyệt**. Lần đăng nhập kế tiếp bạn sẽ thấy dữ liệu (tối đa 30 phút sau khi được duyệt nếu đang đăng nhập sẵn).

| Vai trò | Quyền |
|---|---|
| Chờ duyệt | Chỉ thấy trang **Tài khoản** (bật/tắt 2FA) |
| Người xem | Xem sự cố và IP bị khóa |
| Quản trị | Như người xem + gỡ khóa IP + mục **Phân quyền** (duyệt/thu hồi Người xem, đề xuất và bỏ phiếu nâng/hạ Quản trị, vô hiệu hóa tài khoản, đặt lại PIN). **Bắt buộc 2FA** |

**Bật / tắt 2FA:** bấm **Tài khoản** → **Bật 2FA** → quét QR bằng Google/Microsoft Authenticator (hoặc nhập khóa thủ công) → nhập mã 6 số. Từ lần đăng nhập sau, hệ thống hỏi thêm mã OTP. Muốn tắt thì bấm **Tắt 2FA** ở cùng chỗ; hệ thống hỏi lại **mật khẩu và mã OTP hiện tại** (để người nhặt được máy đang đăng nhập không tự tắt được lớp bảo vệ của bạn). 2FA là **tùy chọn** với Người xem; **bắt buộc** với Quản trị viên (chưa bật thì chỉ thấy màn hình bật 2FA, và không có nút tắt) và với tài khoản nội bộ `admin`.

**Quên mật khẩu:** ở màn hình đăng nhập bấm **Quên mật khẩu?** → nhập email → nhập mã 6 số nhận qua email và mật khẩu mới (cùng thanh độ mạnh, tối thiểu *Trung bình*). Hệ thống luôn báo "nếu email đã đăng ký thì mã đã được gửi", dù email có tồn tại hay không. Nhập sai mã nhiều lần hoặc yêu cầu liên tục sẽ bị chặn tạm thời.

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
- Khi thao tác có hiệu lực (kể cả duyệt hay thu hồi Người xem), người bị tác động bị đăng xuất khỏi mọi phiên và phải đăng nhập lại để nhận vai trò mới.
- Nâng/hạ quyền, vô hiệu hóa, đề xuất mới, đặt lại hay khóa PIN đều gửi cảnh báo email/Telegram. Duyệt, thu hồi Người xem và từ chối yêu cầu chỉ ghi vào nhật ký kiểm toán, không gửi cảnh báo. Người vừa được nâng lên Quản trị sẽ phải bật 2FA trước khi làm việc.

**Quên PIN.** Nhờ một quản trị viên khác bấm **Đặt lại PIN** cạnh tên bạn (người đó nhập PIN của chính họ). Lần vào sau bạn tự đặt PIN mới. Mỗi lần đặt lại đều có cảnh báo.

**Quản trị viên đầu tiên (chế độ khởi tạo).** Khi hệ thống chưa có đủ 2 quản trị viên Cognito, tài khoản nội bộ `admin` (mật khẩu + OTP lấy qua SSM, xem phần trên) cũng phải đặt PIN, và được **tự mình** nâng một Người xem lên Quản trị. Cách làm: cho 2 người đăng ký, duyệt họ thành Người xem, rồi bấm **Đề xuất lên Quản trị** cho từng người. Khi đã đủ 2 quản trị viên Cognito, `admin` nội bộ chỉ còn xem và gỡ khóa IP (không duyệt hay thu hồi Người xem nữa).

**Quên PIN của `admin` nội bộ:** xóa bằng AWS CLI, rồi đặt PIN mới ở lần vào sau:

```powershell
aws dynamodb delete-item --region ap-southeast-1 --table-name <IncidentTable> `
  --key '{"incident_id":{"S":"ADMIN_PIN#local:admin"},"timestamp":{"S":"PIN"}}'
```

## Truy vấn log bằng Athena (cho người làm báo cáo và điều tra)

Log CloudTrail lưu trên S3 truy vấn được bằng SQL, không cần máy chủ.

1. Người triển khai gắn quyền chỉ đọc cho IAM user của bạn (ARN lấy ở output `AthenaAnalystPolicyArn`):
   `aws iam attach-user-policy --user-name <user> --policy-arn <AthenaAnalystPolicyArn>`
2. Mở AWS Console → **Athena** (region Singapore) → chọn workgroup **`logsentinel`**, database **`logsentinel`**.
3. Tab **Saved queries** có sẵn 5 truy vấn: sự kiện theo ngày (vẽ biểu đồ xu hướng), top hành động, đăng nhập Console thất bại theo IP, thay đổi IAM, lời gọi API bị từ chối.
4. Khi tự viết truy vấn, luôn lọc theo cột `day` (dạng `2026/11/11`) để Athena chỉ đọc những ngày cần thiết:

```sql
SELECT eventtime, eventname, sourceipaddress
FROM cloudtrail_logs
WHERE day >= '2026/11/01' AND region = 'us-east-1' AND eventname = 'ConsoleLogin'
```

Lưu ý: mỗi truy vấn bị giới hạn 1 GB dữ liệu quét (khoảng 0,005 USD) để một câu SQL viết sai không gây tốn kém. Log chỉ được giữ 30 ngày. CloudTrail ghi file lên S3 chậm khoảng 5–15 phút so với thực tế. Sự kiện IAM và đăng nhập Console nằm ở `region = 'us-east-1'`.

## Dùng hằng ngày

- **4 ô số trên cùng:** tổng sự cố gần đây, số mức CRITICAL, số mức HIGH, số IP đang bị khóa.
- **Bảng "IP đang bị khóa":** mỗi IP bị khóa 24 giờ. Nếu khóa nhầm (ví dụ nhân viên gõ sai mật khẩu 5 lần), bấm **Gỡ khóa**. Có hiệu lực trong tối đa 60 giây. Thao tác gỡ khóa được ghi lại trong log.
- **Bảng "Sự cố gần đây":** 50 sự cố mới nhất, lọc được theo mức độ. Trang tự làm mới mỗi 15 giây.
- Phiên đăng nhập hết hạn sau 30 phút. Xong việc thì bấm **Đăng xuất**: phiên bị thu hồi ngay trên máy chủ, nên dù ai đó đã sao chép cookie của bạn cũng không dùng lại được.

## Trợ lý AI (khi được bật)

Thẻ **Trợ lý AI** nằm dưới bảng sự cố, dùng được cho cả Quản trị và Người xem.

- Bấm **Hỏi AI** ở một dòng sự cố để hỏi riêng về sự cố đó (ví dụ: "Sự cố này là gì, có nguy hiểm không, khắc phục thế nào?"). Bấm **Bỏ chọn** để hỏi chung về các sự cố gần đây hoặc cách dùng hệ thống.
- Trợ lý **chỉ đọc**: không tự gỡ khóa IP, không đổi quyền. Khi cần thao tác, nó hướng dẫn bạn tự bấm nút.
- Mỗi người hỏi tối đa 30 câu mỗi ngày (quản trị có thể đổi khi deploy). Mỗi câu hỏi tối đa 1.000 ký tự, mỗi lần chỉ một câu đang chờ.
- Dữ liệu sự cố được rút gọn và **che email** trước khi gửi tới OpenAI. Câu trả lời do AI tạo, có thể sai: đối chiếu trước khi làm theo.

Người triển khai bật trợ lý bằng `cdk deploy -c chat_model=<tên model OpenAI>`, rồi tự đặt API key (không gửi key cho ai, không dán vào chat):

```
aws secretsmanager put-secret-value --region ap-southeast-1 --secret-id logsentinel/openai_api_key --secret-string "<API key>"
```

Key có hiệu lực từ câu hỏi kế tiếp, không cần khởi động lại máy. Nên đặt hạn mức chi tiêu tháng trên platform.openai.com.

## Ý nghĩa các luật

| Luật | Nghĩa là | Nên làm gì |
|---|---|---|
| `BRUTE_FORCE_DETECTED` | Một IP sai mật khẩu 5 lần trong 60 giây | IP đã tự khóa. Nếu là người nhà thì gỡ khóa |
| `SLOW_BRUTE_FORCE` | Một IP sai mật khẩu 20 lần trong 1 giờ, rải đều để né luật trên | IP đã tự khóa. Kiểm tra các tài khoản bị nhắm tới |
| `LOGIN_FAILURE_SPIKE` | Toàn hệ thống có hơn 50 lần đăng nhập sai trong 5 phút, từ nhiều IP vào nhiều tài khoản | Dấu hiệu dùng danh sách mật khẩu bị lộ để thử hàng loạt. Yêu cầu người dùng đổi mật khẩu và bật 2FA |
| `SCAN_DETECTED` | Một IP gọi 30 đường dẫn không tồn tại trong 60 giây (đang dò tìm lỗ hổng) | IP đã tự khóa. Không cần làm gì thêm |
| `ACCOUNT_UNDER_ATTACK` | Một tài khoản bị đoán sai 10 lần trong 5 phút từ **nhiều IP khác nhau** (tấn công phân tán) | Không IP nào bị khóa tự động. Đổi mật khẩu tài khoản đó, bật 2FA, cân nhắc thu hẹp `ingress_cidr` |
| `SQL_INJECTION` | Có người thử chèn mã độc vào ô tìm kiếm | IP đã tự khóa. Không cần làm gì thêm |
| `MFA_BYPASS_ATTEMPT` | Mật khẩu **đúng** nhưng sai mã OTP **5 lần trong 60 giây** (gõ nhầm 1–4 lần không bị khóa) | **Đổi mật khẩu ngay**: mật khẩu có thể đã lộ |
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

## Giới hạn của bản lab

- Một tài khoản quản trị duy nhất, chứng chỉ tự ký, Console chạy chung máy với ứng dụng được bảo vệ.
- Bản thương mại nên tách Console ra riêng (CloudFront + Cognito), có tên miền và chứng chỉ ACM, nhiều tài khoản và phân quyền.
