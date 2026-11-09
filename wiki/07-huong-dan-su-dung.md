# 07 - Hướng dẫn sử dụng

## 1. Cài đặt

```bash
cd d:\BTL_Linux
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate      # Linux / macOS
pip install -r requirements.txt
pip install -e .
```

Kiểm tra: `btl --version`

## 2. Cú pháp chung

```
btl [--verbose] [--log-file FILE] <nhóm lệnh> [tuỳ chọn]
```

| Tuỳ chọn toàn cục | Tác dụng |
| --- | --- |
| `-v`, `--verbose` | Bật log mức DEBUG |
| `--log-file FILE` | Ghi thêm log ra tệp |

## 3. Nhóm `ssh`

Chạy lệnh từ xa và xem kết quả.

```bash
btl ssh <host> [lệnh] [tuỳ chọn]
```

| Tuỳ chọn | Tác dụng |
| --- | --- |
| `-p`, `--port` | Cổng SSH (mặc định 22) |
| `-u`, `--user` | Tài khoản (mặc định root) |
| `-i`, `--identity` | Tệp khóa riêng |
| `--agent` | Dùng SSH agent (mặc định) |
| `--password` | Mật khẩu (khuyến nghị tránh) |
| `--passphrase` | Passphrase của khóa |
| `--known-hosts` | Đường dẫn kho khóa host |
| `--auto-accept-host-key` | Chấp nhận khóa lạ (nguy hiểm) |
| `--timeout` | Thời gian chờ (giây) |
| `--info` | In thông tin năng lực của máy chủ |

### Ví dụ

```bash
# Chạy lệnh
btl ssh 192.168.118.128 -u btladmin -i ~/.ssh/id_ed25519 "uptime"

# Xem thông tin máy chủ
btl ssh 192.168.118.128 -u btladmin -i ~/.ssh/id_ed25519 --info
```

Output `--info`:

```json
{
  "remote_version": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
  "cipher": "chacha20-poly1305@openssh.com",
  "mac": "hmac-sha2-512-etm@openssh.com",
  "compression": false,
  "host_key_types": ["ssh-ed25519", "ecdsa-sha2-nistp256", ...],
  "allowed_auth_methods": ["publickey"]
}
```

## 4. Nhóm `scp`

```bash
btl scp <host> <đường dẫn cục bộ> <đường dẫn từ xa> [tuỳ chọn]
```

| Tuỳ chọn | Tác dụng |
| --- | --- |
| `-r`, `--recursive` | Sao chép thư mục |
| `--preserve-times` | Giữ thời gian sửa |
| `--download` | Tải về thay vì tải lên |

> **Lưu ý về thứ tự tham số.** Vị trí của hai đường dẫn **không đổi** khi
> thêm `--download`: tham số thứ nhất luôn là *đường dẫn cục bộ*, tham số
> thứ hai luôn là *đường dẫn từ xa*. Khi tải về, đường dẫn từ xa được viết
> theo dạng quen thuộc `[user@]host:/duong/dan`; phần `user@host` được bỏ qua
> vì kết nối đã dùng `--host` và `--user`.

### Ví dụ

```bash
# Tải lên
btl scp 192.168.118.128 -u btladmin -i ~/.ssh/id_ed25519 \
       ./bao-cao.pdf /home/btladmin/

# Tải về — đường dẫn từ xa ở tham số thứ hai
btl scp 192.168.118.128 -u btladmin -i ~/.ssh/id_ed25519 \
       --download ./bao-cao.pdf btladmin@192.168.118.128:/home/btladmin/bao-cao.pdf

# Thư mục đệ quy
btl scp 192.168.118.128 -u btladmin -i ~/.ssh/id_ed25519 \
       -r ./data /home/btladmin/
```

## 5. Nhóm `sftp`

```bash
btl sftp <host> [tuỳ chọn] [đường dẫn cục bộ] [đường dẫn từ xa]
```

| Tuỳ chọn | Tác dụng |
| --- | --- |
| `--root` | Giới hạn mọi đường dẫn vào thư mục này trên máy chủ |
| `--download` | Tải về |
| `--upload` | Tải lên |
| `--resume` | Tiếp tục file bị gián đoạn |
| `--path` | Thư mục cần liệt kê (mặc định `.`) |

### Ví dụ

```bash
# Liệt kê
btl sftp 192.168.118.128 -u ftpsvc -i ~/.ssh/id_ed25519_sftp --path /

# Tải lên
btl sftp 192.168.118.128 -u ftpsvc -i ~/.ssh/id_ed25519_sftp \
       --upload ./data.csv /upload/

# Tải về có ràng buộc thư mục
btl sftp 192.168.118.128 -u ftpsvc -i ~/.ssh/id_ed25519_sftp \
       --root /upload --download /upload/data.csv ./
```

Output liệt kê:

```
- rw-r--r--     1.2 KiB report.csv
d rwxr-xr-x        --   images/
```

## 6. Nhóm `hostkey`

Quản lý kho khóa máy chủ tin cậy.

```bash
btl hostkey list
btl hostkey add <hostname> --key-file <tệp.pub>
btl hostkey remove <hostname>
```

| Tuỳ chọn | Tác dụng |
| --- | --- |
| `--known-hosts` | Đường dẫn kho (mặc định `~/.ssh/known_hosts`) |
| `--port` | Cổng (cho cổng khác 22) |
| `--key-file` | Tệp khóa công khai cần tin |

### Ví dụ

```bash
$ btl hostkey add 192.168.118.128 --key-file ./hostkey.pub
Trusted ssh-ed25519 SHA256:1/JqM79jcWPtezAoDBn9HNXLVTiuVDkp72ztAIfbVJA for 192.168.118.128

$ btl hostkey list
192.168.118.128 ssh-ed25519 SHA256:1/JqM79jcWPtezAoDBn9HNXLVTiuVDkp72ztAIfbVJA
```

> `add` chấp nhận cả tệp `.pub` lẫn tệp khóa riêng.

## 7. Nhóm `audit`

Kiểm định cấu hình sshd hiệu lực trên máy đang chạy.

```bash
# Chạy trên máy chủ
btl audit [--json]

# Hoặc kiểm định từ xa (chạy `sshd -T` qua SSH)
btl audit <host> --user <user> --identity <key> [--sudo-password <pwd>]
```

| Tuỳ chọn | Tác dụng |
| --- | --- |
| `--json` | Xuất JSON để xử lý tự động |
| `--user` | Tài khoản SSH dùng để kết nối (chế độ từ xa) |
| `--identity` | Đường dẫn khoá riêng (chế độ từ xa) |
| `--sudo-password` | Mật khẩu sudo, nếu cần |

### Ví dụ

```
$ btl audit
[   WEAK] passwordauthentication: expected 'no', got 'yes'
[ MISSING] maxauthtries: expected '3', got '<not set>'

Checked 18 directives: 16 compliant, 1 weak, 1 missing.
```

Trên máy chủ đã cấu hình đúng:

```
$ btl audit
Checked 18 directives: 18 compliant, 0 weak, 0 missing.
```

Mã thoát: `0` nếu tuân thủ hoàn toàn, `1` nếu có vấn đề.

> Lệnh này phải chạy **trên máy chủ** vì nó dùng `sshd -T`. Ở chế độ từ xa,
> lệnh chạy `sshd -T` qua SSH (cần quyền root nếu muốn đọc cả cấu hình
> drop-in ở chế độ root).

> **Lưu ý về alias:** `ChallengeResponseAuthentication` là alias đã lỗi
> thời của `KbdInteractiveAuthentication`. OpenSSH 10.x chỉ in **tên chuẩn**
> ra output của `sshd -T`, nên auditor sẽ tra bảng alias và kiểm định
> `kbdinteractiveauthentication` — tránh báo động giả cho một chỉ thị đã
> được đặt đúng.

## 8. Nhóm `render`

Sinh cấu hình mà không cần kết nối máy chủ.

```bash
btl render <loại> [tuỳ chọn]
```

| Loại | Nội dung |
| --- | --- |
| `sshd` | File hardening chính |
| `sshd-sftp` | Khối `Match User` cho tài khoản SFTP |
| `fail2ban` | File jail.local |
| `firewall` | Script ufw |
| `audit` | File audit rules |

| Tuỳ chọn | Tác dụng |
| --- | --- |
| `--port` | Cổng SSH |
| `--groups` | Nhóm được phép, phân tách bằng dấu phẩy |
| `--users` | Tài khoản được phép |
| `--sftp-users` | Tài khoản SFTP bị jail |

### Ví dụ

```bash
btl render sshd --port 2222 --groups sshusers,ops
btl render sshd-sftp --sftp-users alice,bob
```

## 9. Nhóm `provision`

Cấu hình máy chủ Ubuntu mới.

```bash
btl provision --host <host> --user <user> [tuỳ chọn]
```

| Tuỳ chọn | Tác dụng |
| --- | --- |
| `--host` | Địa chỉ máy chủ (bắt buộc) |
| `--admin-users` | Tài khoản quản trị, phân tách bằng dấu phẩy |
| `--sftp-users` | Tài khoản SFTP, phân tách bằng dấu phẩy |
| `--admin-public-key` | Khoá công khai cài cho tài khoản quản trị |
| `--sftp-public-key` | Khoá công khai cài cho tài khoản SFTP |
| `--fail2ban-ignore` | Dải IP quản trị không bao giờ bị fail2ban ban |
| `--ufw-limit-ssh` | Dùng `ufw limit` thay vì `ufw allow` cho cổng SSH |
| `--no-firewall` | Không cấu hình ufw |
| `--sudo-password` | Mật khẩu cho `sudo -S` |
| `--group` | Nhóm SSH (mặc định `sshusers`) |
| `--dry-run` | Chỉ xem, không thay đổi |

### Ví dụ

```bash
# Xem trước
btl provision --host 192.168.118.128 --user tuananh \
              --identity ~/.ssh/id_ed25519 \
              --admin-users btladmin --sftp-users ftpsvc \
              --admin-public-key ~/.ssh/id_ed25519.pub \
              --sftp-public-key ~/.ssh/id_ed25519_sftp.pub \
              --fail2ban-ignore 192.168.118.0/24 \
              --dry-run

# Thực thi
btl provision --host 192.168.118.128 --user tuananh \
              --identity ~/.ssh/id_ed25519 \
              --sudo-password '<mật khẩu sudo>' \
              --admin-users btladmin --sftp-users ftpsvc \
              --admin-public-key ~/.ssh/id_ed25519.pub \
              --sftp-public-key ~/.ssh/id_ed25519_sftp.pub \
              --fail2ban-ignore 192.168.118.0/24
```

> `--admin-public-key` và `--sftp-public-key` là bắt buộc trong quy trình thật:
> provisioning **khoá mật khẩu** tài khoản quản trị và bật
> `PasswordAuthentication no`, nên không cài khoá công khai thì tài khoản không
> bao giờ đăng nhập được.

## 10. Quy trình đầy đủ

```bash
# 1. Sinh khóa
./scripts/generate-keys.sh

# 2. Tin cậy host key (làm TRƯỚC khi hardening)
ssh-keyscan -t ed25519 192.168.118.128 > /tmp/hostkey.pub
ssh-keygen -lf /tmp/hostkey.pub          # đối chiếu với console VM
btl hostkey add 192.168.118.128 --key-file /tmp/hostkey.pub

# 3. Provision (kèm khoá công khai để không khoá chính mình ra)
btl provision --host 192.168.118.128 --user tuananh \
              --identity ~/.ssh/id_ed25519 \
              --sudo-password '<mật khẩu sudo>' \
              --admin-users btladmin --sftp-users ftpsvc \
              --admin-public-key ~/.ssh/id_ed25519.pub \
              --sftp-public-key ~/.ssh/id_ed25519_sftp.pub \
              --fail2ban-ignore 192.168.118.0/24

# 4. Kiểm định (từ máy trạm)
btl audit 192.168.118.128 --user tuananh --identity ~/.ssh/id_ed25519 \
     --sudo-password '<mật khẩu sudo>'

# 5. Chạy bộ test E2E
./scripts/test-e2e.sh 192.168.118.128 tuananh ~/.ssh/id_ed25519
```

> **Lưu ý:** bước 3 tự động cài `authorized_keys` cho cả tài khoản quản trị,
> tài khoản SFTP và tài khoản dùng để provision. Không còn cần `ssh-copy-id`
> thủ công nữa.

## 11. Xử lý sự cố thường gặp

| Triệu chứng | Nguyên nhân | Xử lý |
| --- | --- | --- |
| `Host key verification failed` | Khóa chưa tin cậy hoặc đã đổi | `btl hostkey list`, rồi `remove` + `add` |
| `Permission denied (publickey)` | Chưa copy key cho user | `ssh-copy-id` |
| `Too many authentication failures` | Agent có nhiều key | `ssh -o IdentitiesOnly=yes -i <key>` |
| `bash: btl: command not found` | Chưa cài trên máy chủ | `pip install -e .` trên máy chủ, hoặc dùng `python -m btl.cli` |
| `sudo: a password is required` | User chưa có quyền sudo | `sudo usermod -aG sudo <user>` |
| `btl audit` báo nhiều `MISSING` | Drop-in chưa được đọc | Kiểm tra tên file bắt đầu bằng `00-` |
| SFTP không thấy thư mục | `ChrootDirectory` không đúng quyền | `sudo chown root:root /opt/sftp-jails/<user>` |
