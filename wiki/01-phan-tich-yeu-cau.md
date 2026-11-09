# 01 - Phân tích yêu cầu đề tài

## 1. Thông tin đề tài

| Mục | Nội dung |
| --- | --- |
| **Tên đề tài** | Secured Network Service Configuration with SCP, SFTP and SSH |
| **Loại** | Bài tập lớn môn Linux / Quản trị mạng |
| **Nền tảng chạy** | Ubuntu Server trên máy ảo VMware Workstation |
| **Ngôn ngữ triển khai** | Python 3 (không phụ thuộc thư viện ngoài cho phần lõi SCP) |

## 2. Mục tiêu bài học

Bài toán gồm hai mảng kiến thức tách biệt cần phối hợp:

1. **Quản trị dịch vụ SSH** — cấu hình máy chủ sao cho an toàn nhưng vẫn
   dùng được: khóa công khai, chặn root, giới hạn forwarding, chống brute
   force, ghi log, audit.
2. **Truyền file an toàn** — triển khai và sử dụng SCP/SFTP với kiểm soát
   đường dẫn để người dùng không thể ghi ra ngoài vùng được phép.

Điểm mấu chốt của đề tài là chữ **Secured**: mọi thứ phải *an toàn*, không
chỉ *hoạt động*. Vì vậy suốt dự án, mọi đường dẫn do peer đưa vào đều đi
qua một lớp kiểm tra tập trung.

## 3. Phân tích chức năng

### 3.1. Nhóm A - Cấu hình dịch vụ SSH (server side)

| # | Yêu cầu | Mức độ | Thực hiện tại |
| --- | --- | --- | --- |
| A1 | Cấu hình `sshd` bằng file drop-in, không sửa file gốc | Bắt buộc | `btl/security/sshd_config.py` → `/etc/ssh/sshd_config.d/00-btl-hardening.conf` |
| A2 | Chỉ xác thực bằng khóa công khai | Bắt buộc | `PasswordAuthentication no`, `KbdInteractiveAuthentication no` |
| A3 | Cấm đăng nhập root | Bắt buộc | `PermitRootLogin no` |
| A4 | Giới hạn nhóm tài khoản được đăng nhập | Bắt buộc | `AllowGroups sshusers` |
| A5 | Chống brute force (giới hạn số lần thử) | Bắt buộc | `MaxAuthTries 3`, `LoginGraceTime 30`, `MaxStartups 10:30:60` |
| A6 | Tự động chặn IP tấn công | Bắt buộc | `btl/security/defense.py` → fail2ban jail |
| A7 | Tường lửa chỉ mở cổng cần thiết | Nên có | `ufw` script sinh tự động |
| A8 | Ghi log và kiểm toán thay đổi cấu hình | Nên có | `auditd` rules |
| A9 | Banner cảnh báo trước khi đăng nhập | Tùy chọn | `Banner /etc/ssh/banner.txt` |
| A10 | Đóng các tính năng không cần (X11, agent, TCP forwarding) | Bắt buộc | Tất cả đặt `no` |
| A11 | Chính sách mã hoá mạnh | Nên có | Chỉ để lại ChaCha20-Poly1305 và AES-GCM |
| A12 | Kiểm định cấu hình sau khi áp dụng | Bắt buộc | `btl audit` so với `BASELINE` |

> **Điểm kỹ thuật quan trọng:** OpenSSH lấy **giá trị đầu tiên** đọc được cho
> mỗi chỉ thị, và thư mục `sshd_config.d/` được đọc **trước** file chính.
> Vì vậy file drop-in phải đặt tên bắt đầu bằng số `00-` để thắng các
> file `50-cloud-init.conf` mặc định của Ubuntu.

### 3.2. Nhóm B - Triển khai SCP

| # | Yêu cầu | Mức độ | Thực hiện tại |
| --- | --- | --- | --- |
| B1 | Hiểu và mô tả đúng giao thức SCP (source/sink) | Bắt buộc | `btl/scp/protocol.py` mô tả đầy đủ ở docstring |
| B2 | Mã hoá/giải mã thông điệp điều khiển | Bắt buộc | `encode_*` / `decode_message` |
| B3 | Client tải file lên (push) | Bắt buộc | `SCPClient.put` |
| B4 | Client tải file về (pull) | Bắt buộc | `SCPClient.get` |
| B5 | Truyền đệ quy thư mục | Bắt buộc | `C`/`D`/`E` message + đệ quy |
| B6 | Giữ nguyên quyền và thời gian sửa | Nên có | `-p` → `T` message + `chmod`/`utime` |
| B7 | Chống path traversal | Bắt buộc | `validate_relative_name` + `SafePath` |
| B8 | Chống symlink escape | Bắt buộc | `realpath` trong `SafePath.resolve` |
| B9 | Server nhận file đẩy lên (sink mode) | Bắt buộc | `SCPServer.handle_channel` |
| B10 | Xử lý lỗi và phản hồi đúng chuẩn | Bắt buộc | `\x00` OK, `\x01` cảnh báo, `\x02` lỗi chí mạng |

### 3.3. Nhóm C - Triển khai SFTP

| # | Yêu cầu | Mức độ | Thực hiện tại |
| --- | --- | --- | --- |
| C1 | Client SFTP cơ bản (list, get, put) | Bắt buộc | `btl/sftp/client.py` |
| C2 | Ràng buộc đường dẫn vào một thư mục gốc | Bắt buộc | `SFTPClient(root=...)` |
| C3 | Tải lên đệ quy | Nên có | `puttree` |
| C4 | Tiếp tục (resume) file bị gián đoạn | Tùy chọn | `resume=True` dùng `seek` |
| C5 | Tạo/xoá/đổi tên thư mục, đặt quyền | Bắt buộc | `mkdir`, `rmdir`, `rename`, `chmod` |
| C6 | Server SFTP giới hạn theo thư mục | Bắt buộc | `btl/sftp/server.py` → `SFTPServer` |
| C7 | Tạo "chroot jail" cho tài khoản chuyển file | Bắt buộc | `chroot_jail()` + `Match User` block |
| C8 | Tài khoản SFTP không được mở shell | Bắt buộc | `ForceCommand internal-sftp`, `PermitTTY no` |

### 3.4. Nhóm D - Quản lý khóa và máy chủ

| # | Yêu cầu | Mức độ | Thực hiện tại |
| --- | --- | --- | --- |
| D1 | Sinh cặp khóa Ed25519 | Bắt buộc | `scripts/generate-keys.sh` |
| D2 | Lưu trữ và quản lý host key tin cậy | Bắt buộc | `btl/ssh/hostkeys.py` |
| D3 | Phát hiện host key bị thay đổi (MITM) | Bắt buộc | `HostKeyStatus.CHANGED` → ném lỗi |
| D4 | Từ chối host key lạ (không tự động tin) | Bắt buộc | `auto_accept=False` mặc định |
| D5 | Xác thực bằng agent / key file / mật khẩu | Bắt buộc | `AuthConfig` |
| D6 | Provision máy chủ Ubuntu mới | Bắt buộc | `btl provision` |
| D7 | Provisioning idempotent (chạy lại không hỏng) | Bắt buộc | Các script kiểm tra trạng thái trước khi sửa |

### 3.5. Nhóm E - Kiểm thử và tài liệu

| # | Yêu cầu | Mức độ | Thực hiện tại |
| --- | --- | --- | --- |
| E1 | Unit test cho lớp giao thức | Bắt buộc | `tests/test_scp_protocol.py` |
| E2 | Unit test cho bảo mật đường dẫn | Bắt buộc | `tests/test_paths.py` |
| E3 | Unit test cho cấu hình hardening | Bắt buộc | `tests/test_security.py` |
| E4 | Tài liệu wiki | Bắt buộc | Thư mục `wiki/` |
| E5 | Báo cáo kỹ thuật | Bắt buộc | `wiki/05-bao-cao-ky-thuat.md` |

## 4. Yêu cầu phi chức năng

| Yêu cầu | Cách đáp ứng |
| --- | --- |
| **Bảo mật là ưu tiên số 1** | Mọi đường dẫn đều qua lớp kiểm tra tập trung; mặc định từ chối |
| **Không mất khả năng truy cập khi cấu hình sai** | `sshd -t` kiểm tra trước khi reload; provisioning không đóng phiên hiện tại |
| **Chạy được trên Ubuntu thật** | Tất cả cấu hình sinh ra đều là cú pháp `sshd`/`ufw`/`fail2ban`/`auditd` thật |
| **Kiểm thử tự động** | `pytest`, 98 test, không cần mạng |
| **Tài liệu song ngữ** | Wiki tiếng Việt, code tiếng Anh |
| **Có thể kiểm chứng cấu hình** | `btl audit` đối chiếu `sshd -T` với baseline |

## 5. Phân tích rủi ro

| Rủi ro | Mức độ | Biện pháp |
| --- | --- | --- |
| Khóa mất truy cập sau khi tắt mật khẩu | Cao | `btl provision` không đổi cấu hình trước khi kiểm tra key hoạt động; kiểm tra `sshd -t` trước `reload` |
| Host key MITM | Cao | Từ chối key lạ; key đổi luôn là lỗi chí mạng |
| Path traversal qua SCP/SFTP | Cao | `validate_relative_name` + `SafePath` (lexical + `realpath`) |
| Symlink escape khỏi jail | Trung bình | `realpath` kiểm tra sau khi resolve |
| Chroot jail bị thoát | Trung bình | Thư mục gốc jail `root:root` + `755`, thư mục ghi `user:user` + `700` |
| SFTP bị chặn bởi `internal-sftp` | Trung bình | `Match User` + `ForceCommand internal-sftp -d /upload` |
| Đăng nhập bị khóa do `AllowGroups` sai | Trung bình | Group tạo tự động trong provisioning, user được `usermod -aG` |
| Log bị xoá để che dấu | Thấp | `auditd` ghi ở mức syscall, tách khỏi `auth.log` |

## 6. Phạm vi

### Có trong phạm vi
- Máy chủ Ubuntu 22.04/24.04 chạy OpenSSH.
- Tài khoản quản trị (được đăng nhập shell) và tài khoản SFTP bị jail.
- Truyền file một chiều qua SCP và hai chiều qua SFTP.
- Giám sát và audit cấu hình.

### Ngoài phạm vi
- Triển khai quản lý tập trung (Puppet/Ansible) — dự án cung cấp script
  idempotent để có thể đóng gói sau.
- Xác thực hai yếu tố (MFA) — đề xuất trong báo cáo, chưa triển khai.
- Hệ điều hành khác ngoài Ubuntu/Debian.
- Web UI — dự án cố ý giữ giao diện dòng lệnh để phù hợp ngữ cảnh môn học.

## 7. Tiêu chí nghiệm thu

1. `python -m pytest tests/` chạy xanh, ≥ 90 test.
2. `sshd -t` trên máy chủ trả về 0 sau khi provisioning.
3. `btl audit` báo 0 directive yếu, 0 thiếu.
4. Đăng nhập bằng mật khẩu bị từ chối; đăng nhập bằng key thành công.
5. `ssh user@host` với tài khoản SFTP bị từ chối, `sftp user@host` chạy được.
6. Tài khoản SFTP không nhìn thấy `/etc` và không ghi ra ngoài `/upload`.
7. SCP tải lên tệp có tên `../../etc/passwd` bị từ chối và ghi log.
8. fail2ban ban IP sau 3 lần đăng nhập sai.
