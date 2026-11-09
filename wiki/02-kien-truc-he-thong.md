# 02 - Kiến trúc hệ thống

## 1. Tổng quan

```
┌──────────────────────────────────────────────────────────────────┐
│                     Máy trạm (Windows / Linux)                     │
│                                                                   │
│   btl/cli.py  ──►  btl.ssh.connection.SSHConnection               │
│        │                    │                                     │
│        │                    ├──► btl.ssh.hostkeys  (known_hosts)  │
│        │                                                          │
│        ├──►  btl.scp.client.SCPClient ──► giao thức scp1         │
│        │                    │                                     │
│        ├──►  btl.sftp.client.SFTPClient (virtual root)           │
│        │                                                          │
│        └──►  btl.provision  ──►  ghi tệp cấu hình + script bash  │
│                                                                   │
│   btl.security  ──► sinh sshd.conf / fail2ban / ufw / auditd     │
└───────────────────────────────┬──────────────────────────────────┘
                                │ SSH (TCP 22 hoặc 2222)
┌───────────────────────────────▼──────────────────────────────────┐
│              Máy chủ Ubuntu (máy ảo VMware)                        │
│                                                                   │
│  sshd  ── /etc/ssh/sshd_config.d/00-btl-hardening.conf            │
│        ── /etc/ssh/sshd_config.d/10-btl-sftp.conf  (Match User)   │
│                                                                   │
│  fail2ban  ── /etc/fail2ban/jail.d/btl-sshd.local                 │
│  ufw       ── quy tắc tường lửa                                    │
│  auditd    ── /etc/audit/rules.d/50-btl.rules                     │
│                                                                   │
│  /opt/sftp-jails/<user>/upload   ← thư mục ghi, thuộc user        │
│  /home/<user>/                                            ← nhà  │
│                                                                   │
│  Tài khoản admin  : nhóm sshusers, đăng nhập shell bằng key       │
│  Tài khoản SFTP   : ForceCommand internal-sftp, chroot jail       │
└───────────────────────────────────────────────────────────────────┘
```

## 2. Phân tầng mô đun

Dự án chia theo nguyên tắc: **tầng dưới không biết tầng trên**, và mọi
tầng đều kiểm thử được độc lập.

```
tầng 4   btl.cli                     giao diện dòng lệnh
          btl.provision               điều phối provisioning
              │
tầng 3   btl.scp.client              btl.sftp.client
          btl.sftp.server             btl.security.*
              │
tầng 2   btl.ssh.connection          btl.ssh.hostkeys
          btl.scp.protocol (codec thuần, không I/O)
              │
tầng 1   btl.utils.errors            btl.utils.logging
          btl.utils.paths             ← điểm kiểm soát tập trung
```

### Tầng 1 — `btl.utils`

| Mô đun | Trách nhiệm |
| --- | --- |
| `errors.py` | Cây exception. Mọi lỗi kế thừa `BTLException` để bắt bằng một lớp. `PermissionDeniedError` tách riêng khỏi `AuthError` vì "đã xác thực được nhưng chính sách chặn" là hai việc khác nhau. |
| `logging.py` | `setup_logging()` là điểm vào duy nhất để cấu hình log. Thư viện **không** tự cấu hình log khi import. Ghi ra `stderr` để `stdout` giữ sạch cho kết quả máy đọc được. |
| `paths.py` | **Trái tim của phần bảo mật.** `SafePath` bắt buộc mọi đường dẫn đi qua kiểm tra chứa chứa (lexical + `realpath`). |

### Tầng 2 — Giao thức và vận chuyển

`btl/scp/protocol.py` cố ý **không** phụ thuộc vào socket hay Paramiko. Nó
chỉ là codec thuần túy, nhận và trả về các callback `read_line`,
`read_exactly`, `write`. Nhờ vậy:

- Toàn bộ logic đóng khung (framing) được test bằng pytest mà không cần mạng.
- Có thể dùng lại codec cho kênh SSH khác, cho mô phỏng, hoặc để viết
  công cụ kiểm tra giao thức.

`btl/ssh/connection.py` bọc Paramiko và áp chính sách:

- `RejectPolicy` của Paramiko — không bao giờ tự động tin host key.
- Sau khi kết nối, chính sách riêng của dự án (`HostKeyPolicy`) kiểm tra lại
  host key so với kho `known_hosts` của dự án.

### Tầng 3 — Nghiệp vụ

| Mô đun | Trách nhiệm |
| --- | --- |
| `btl/scp/client.py` | `SCPClient` (put/get), `SCPServer` (sink). |
| `btl/sftp/client.py` | `SFTPClient` với **virtual root** và hỗ trợ resume. |
| `btl/sftp/server.py` | `SFTPServer` giới hạn theo thư mục, `chroot_jail()`. |
| `btl/security/sshd_config.py` | `SSHDPolicy` → file `sshd_config`; `audit_config()` so với `BASELINE`. |
| `btl/security/defense.py` | `Fail2BanPolicy`, `FirewallPolicy`, `AuditPolicy`. |
| `btl/provision/provisioner.py` | Sinh script bash idempotent, ghi file cấu hình, apply. |

### Tầng 4 — Giao diện

`btl/cli.py` dùng `argparse` với subcommand: `ssh`, `scp`, `sftp`, `hostkey`,
`audit`, `render`, `provision`.

Lệnh `render` đặc biệt hữu ích: nó sinh cấu hình mà **không cần kết nối**
máy chủ, nên có thể dùng để xem trước hoặc kiểm tra bằng mắt.

## 3. Giao thức SCP — chi tiết kỹ thuật

SCP là giao thức **một chiều theo vai trò**, không phải mô hình request/response
như SFTP. Một bên là *source* (`scp -f`, bên gửi), bên kia là *sink*
(`scp -t`, bên nhận).

### 3.1. Bắt tay

Sink **luôn nói trước** bằng một byte `\x00` để báo "tôi sẵn sàng".

Hai chiều đối xứng, và đây là điểm dễ sai nhất:

| Hướng | Bên nào là sink | Ai gửi byte ready | Bên kia phải làm gì |
| --- | --- | --- | --- |
| Tải lên (`scp -t` ở máy chủ) | Máy chủ | Máy chủ gửi `\x00` | Client **đọc** byte ready trước khi gửi thông điệp đầu tiên |
| Tải về (`scp -f` ở máy chủ) | Client | Client gửi `\x00` | Máy chủ **đọc** byte ready trước khi gửi thông điệp đầu tiên |

Nói cách khác: **bên sink luôn gửi byte ready, bên còn lại luôn đọc nó**.
Nhầm chiều sẽ khiến một lệnh bị treo vô hạn.

### 3.2. Thông điệp điều khiển

Dạng chung: `<ký tự><mode 4 chữ số octal> <kích thước> <tên>\n`

| Byte | Ý nghĩa | Ví dụ |
| --- | --- | --- |
| `C` | Tạo file | `C0644 299 group\n` |
| `D` | Bắt đầu thư mục | `D0755 0 docs\n` |
| `E` | Kết thúc thư mục | `E\n` |
| `T` | Thời gian sửa/truy cập | `T1183828267 0 1183828267 0\n` |

Sau `C` đúng `size` byte dữ liệu thô sẽ đến. **Không có khung framing cho
nội dung file** — bên đọc buộc phải đọc đúng số byte đã công bố. Đây là lý do
mọi lệnh đọc trong dự án đều dựa trên độ dài.

Sau nội dung file, bên gửi ghi thêm **một byte `\x00`** làm dấu kết thúc dữ
liệu, rồi mới chờ xác nhận. Bên nhận phải đọc đúng byte đó trước khi gửi
xác nhận, nếu không hai bên sẽ lệch pha.

### 3.3. Xác nhận

| Byte | Ý nghĩa |
| --- | --- |
| `\x00` | Thành công |
| `\x01` | Cảnh báo (kèm text) |
| `\x02` | Lỗi chí mạng → phải đóng kết nối |

### 3.4. Luồng SCP tải lên (push)

```
Client                                     Server (scp -t)
  │                                              │
  │─────── exec "scp -t /dest" ─────────────────▶│
  │◀────────────────────────────── \x00 (sẵn sàng)
  │      (client đọc byte này trước)              │
  │─────── C0644 11 hello.txt ─────────────────▶│
  │◀────────────────────────────── \x00 (OK)    │
  │─────── "hello world" (11 byte) ────────────▶│
  │─────── \x00 (đánh dấu hết dữ liệu) ────────▶│
  │◀────────────────────────────── \x00 (OK)    │
  │                                              │
```

### 3.5. Luồng SCP tải về (pull)

```
Client                                     Server (scp -f)
  │                                              │
  │─────── exec "scp -f /remote" ───────────────▶│
  │─────── \x00 (sẵn sàng) ────────────────────▶│
  │      (máy chủ đọc byte này trước)            │
  │◀────────────────────────────── C0644 11 f   │
  │─────── \x00 (OK) ───────────────────────────▶│
  │◀────────────────────────────── "hello world" │
  │◀────────────────────────────── \x00 (hết)    │
  │─────── \x00 (OK) ───────────────────────────▶│
```

### 3.6. Luồng thư mục

Thông điệp `D` mở một thư mục, `E` đóng lại. Vì luồng là phẳng, bên nhận
phải tự giữ một **ngăn xếp thư mục** để biết nội dung tiếp theo thuộc thư
mục nào. `E` ở cấp ngoài cùng là dấu kết thúc toàn bộ luồng — bên nhận
phải **dừng lại** thay vì chờ thêm dữ liệu.

### 3.7. Rủi ro và cách xử lý

| Rủi ro | Xử lý trong dự án |
| --- | --- |
| Tên file chứa `../` | `validate_relative_name()` **từ chối**, không phải làm sạch |
| Tuyệt đối `/etc/passwd` | Bị hiểu là đường dẫn tương đối trong jail → vẫn bên trong |
| Symlink trỏ ra ngoài | `os.path.realpath()` kiểm tra sau khi resolve |
| Ký tự điều khiển trong tên | Escape theo ký hiệu `^X` khi encode |
| File khổng lồ | Giới hạn `MAX_FILE_SIZE` = 8 GiB |
| Byte đến lẫn lộn trong gói TCP | Một `ChannelReader` duy nhất giữ buffer chung |


## 4. SFTP — virtual root

SFTP là giao thức request/response với framing độc lập, nên an toàn hơn SCP
(không phụ thuộc shell từ xa). Dự án bổ sung **virtual root** ở phía client:

```
SFTPClient(sftp, root="/home/alice")

  client.get("../../../etc/passwd", "local.txt")
  → ValidationError: path contains a parent directory reference
```

Điểm quan trọng: ràng buộc này nằm ở **client**, nên nó bảo vệ cả khi máy
chủ bị cấu hình sai hoặc bị xâm nhập. Ở phía server, `ChrootDirectory` +
`ForceCommand internal-sftp` là lớp phòng thủ thứ hai.

## 5. Mô hình phòng thủ nhiều lớp

```
Lớp 1  Mật khẩu      Không dùng mật khẩu. Chỉ khóa Ed25519.
Lớp 2  Danh tính     known_hosts nghiêm ngặt. Key đổi = báo động đỏ.
Lớp 3  Phân quyền   AllowGroups sshusers. Tài khoản SFTP chỉ được SFTP.
Lớp 4  Đường dẫn    SafePath: lexical + realpath, trong cả SCP và SFTP.
Lớp 5  Mạng         ufw chặn mọi thứ trừ SSH. fail2ban ban IP tấn công.
Lớp 6  Phiên        Không forwarding, không X11, giới hạn số phiên.
Lớp 7  Ghi nhận     auditd theo dõi thay đổi sshd_config và authorized_keys.
```

Không lớp nào đủ một mình. Điểm yếu của lớp trước được lớp sau bù đắp:
 ví dụ "mật khẩu bị lộ" được lớp 2 và 3 giảm thiểu, "ứng dụng có lỗ hổng
traversal" được lớp 4 chặn.

## 6. Quy trình provisioning

```
btl provision --host H --user U --identity K --admin-users A --sftp-users S
   │
   ├─ 1. cài package:  openssh-server, fail2ban, ufw, auditd, python3-paramiko
   ├─ 2. tạo group sshusers
   ├─ 3. tạo user admin, thêm vào group, khóa mật khẩu
   ├─ 4. tạo user SFTP + jail /opt/sftp-jails/<user>/upload
   ├─ 5. ghi 00-btl-hardening.conf, 10-btl-sftp.conf, jail.local, audit rules
   ├─ 6. sshd -t   ← nếu sai thì DỪNG, không reload
   ├─ 7. systemctl reload ssh
   └─ 8. augenrules --load
```

Mỗi bước đều kiểm tra trạng thái hiện tại trước khi thay đổi, nên chạy lại
nhiều lần vẫn cho cùng kết quả (idempotent).
