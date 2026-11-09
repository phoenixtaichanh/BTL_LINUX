# 05 - Báo cáo kỹ thuật

**Đề tài:** Secured Network Service Configuration with SCP, SFTP and SSH

---

## 1. Tóm tắt

Dự án xây dựng một bộ công cụ quản trị dịch vụ SSH trên nền tảng Ubuntu,
tập trung vào hai mục tiêu song song: **làm cho máy chủ an toàn hơn** và
**làm cho việc truyền file an toàn hơn**.

Kết quả chính:

| Sản phẩm | Mô tả |
| --- | --- |
| Cấu hình `sshd` hardened | Sinh tự động, kiểm định trước khi áp dụng, đối chiếu baseline 18 chỉ thị |
| Giao thức SCP | Hiện thực hoá từ đầu theo đặc tả scp1, kèm chống path traversal và symlink escape |
| Client/server SFTP | Client có virtual root, server giới hạn theo thư mục, hỗ trợ chroot jail |
| Công cụ dòng lệnh `btl` | 7 nhóm lệnh: ssh, scp, sftp, hostkey, audit, render, provision |
| Bộ kiểm thử | 192 test tự động, chạy trong 0.6 giây, không cần mạng |

**Kết quả kiểm chứng trên máy ảo thật:** bộ test E2E **38/38 PASS**,
`btl audit` **18/18 compliant**, không phát hiện lỗ hổng trong phạm vi kiểm
tra. Chi tiết ở [08-kiem-tra-bao-mat.md](08-kiem-tra-bao-mat.md).

> **Môi trường kiểm thử:** VMware Workstation 17 (NAT, VMnet8
> `192.168.118.0/24`), Ubuntu 26.04 LTS, OpenSSH 10.2, máy chủ
> `192.168.118.128:22`.

---

## 2. Bối cảnh và mục tiêu

### 2.1. Vấn đề

SSH là giao thức quản trị mặc định của hầu hết máy chủ Linux, nhưng cấu
hình mặc định của nó **không an toàn**: cho phép đăng nhập root bằng mật
khẩu, cho phép đăng nhập bằng mật khẩu, không giới hạn số lần thử, và mở
toàn bộ tính năng forwarding. Với mạng nội bộ của một tổ chức, đây là bề
mặt tấn công lớn.

Song song, hai dịch vụ truyền file phổ biến nhất — SCP và SFTP — đều có
vấn đề riêng: SCP dựa trên việc thực thi lệnh shell từ xa và có lỗ hổng
path traversal cổ điển; SFTP an toàn hơn nhưng mặc định cho phép người dùng
thấy toàn bộ hệ thống tệp.

### 2.2. Mục tiêu

1. Đưa cấu hình SSH của máy chủ về trạng thái hardened, có thể kiểm chứng
   bằng công cụ tự động.
2. Cung cấp cơ chế truyền file mà không cho phép ghi ra ngoài vùng được
   phép.
3. Viết lại giao thức SCP từ đầu để nắm chắc nguyên lý, thay vì chỉ gọi
   lệnh `scp` có sẵn.
4. Đóng gói tất cả lại thành một công cụ dòng lệnh có tài liệu.

---

## 3. Phương pháp

Dự án dùng **mô hình phòng thủ nhiều lớp** (defense in depth). Không lớp
nào đủ một mình, và điểm yếu của lớp trước được lớp sau bù đắp.

```
Lớp 1  Xác thực      Chỉ khóa công khai Ed25519. Không mật khẩu.
Lớp 2  Danh tính      known_hosts nghiêm ngặt. Host key đổi = báo động đỏ.
Lớp 3  Phân quyền    AllowGroups. Tài khoản SFTP chỉ được dùng SFTP.
Lớp 4  Đường dẫn    SafePath: kiểm tra lexical + realpath, cho cả SCP và SFTP.
Lớp 5  Mạng          ufw chặn mọi thứ trừ SSH. fail2ban ban IP tấn công.
Lớp 6  Phiên          Không forwarding, không X11, giới hạn số phiên.
Lớp 7  Ghi nhận      auditd theo dõi thay đổi sshd_config và authorized_keys.
```

### 3.1. Nguyên tắc thiết kế

| Nguyên tắc | Thể hiện trong mã |
| --- | --- |
| **Mặc định từ chối** | `auto_accept=False` cho host key; `SafePath` từ chối mọi đường dẫn lạ |
| **Từ chối chứ không làm sạch** | `validate_relative_name()` ném lỗi với `../../etc/passwd` thay vì đổi thành `etc_passwd` — để thấy được ý đồ tấn công trong log |
| **Kiểm định trước khi áp dụng** | `sshd -t` trước `systemctl reload ssh`; `validate_config()` trước khi ghi file |
| **Tách lớp để kiểm thử** | Codec SCP không phụ thuộc socket → test trọn vẹn không cần mạng |
| **Không phụ thuộc mặc định thư viện** | `RejectPolicy()` + policy riêng, hai lớp kiểm định host key |

---

## 4. Phần 1 — Cấu hình dịch vụ SSH

### 4.1. Cơ chế drop-in

OpenSSH đọc `/etc/ssh/sshd_config.d/*.conf` **trước** file chính, và dùng
**giá trị đầu tiên** đọc được cho mỗi chỉ thị. Vì vậy:

```
/etc/ssh/sshd_config.d/00-btl-hardening.conf   ← đọc trước, thắng
/etc/ssh/sshd_config.d/50-cloud-init.conf      ← mặc định Ubuntu
/etc/ssh/sshd_config                            ← đọc sau
```

Đặt `PasswordAuthentication no` ở **cuối** file chính sẽ **không có tác
dụng** trên Ubuntu vì `50-cloud-init.conf` đã đặt `PasswordAuthentication yes`
trước đó. Đây là một lỗi rất phổ biến. Dự án luôn sinh file đặt tên bắt đầu
bằng `00-`.

### 4.2. Các chỉ thị áp dụng

| Nhóm | Chỉ thị | Mục đích |
| --- | --- | --- |
| Listener | `Port`, `ListenAddress` | Cổng không mặc định giảm nhiễu quét |
| Truy cập | `PermitRootLogin no` | Bắt buộc mọi hành động có tài khoản xác định |
| | `PermitEmptyPasswords no` | Chặn tài khoản không mật khẩu |
| | `AllowGroups sshusers` | Danh sách trắng tài khoản |
| Xác thực | `PubkeyAuthentication yes` | Chỉ khóa công khai |
| | `PasswordAuthentication no` | Không mật khẩu |
| | `KbdInteractiveAuthentication no` | Đóng cả PAM prompt |
| | `ChallengeResponseAuthentication no` | Chặn PAM thay thế |
| Brute force | `MaxAuthTries 3` | Tối đa 3 key thử mỗi kết nối |
| | `LoginGraceTime 30` | Giới hạn thời gian xác thực |
| | `MaxStartups 10:30:60` | Giới hạn kết nối chưa xác thực |
| Phiên | `X11Forwarding no` | Không cần cho SCP/SFTP |
| | `AllowAgentForwarding no` | Chặn đường tới agent của máy trạm |
| | `AllowTcpForwarding no` | Chặn đường tới mạng nội bộ |
| | `PermitTunnel no`, `GatewayPorts no` | Chặn tunnel và cổng public |
| | `PermitUserEnvironment no` | Chặn biến môi trường do người dùng đặt |
| Mã hoá | `Ciphers`, `MACs`, `KexAlgorithms` | Chỉ còn thuật toán mạnh |
| | `HostKeyAlgorithms` | Ưu tiên Ed25519, ECDSA, RSA-SHA2 |
| Ghi log | `LogLevel VERBOSE` | Ghi đủ chi tiết để điều tra |
| | `Banner` | Cảnh báo pháp lý |

### 4.3. Lớp kiểm định cấu hình

`btl audit` chạy `sshd -T` (cấu hình **hiệu lực**, sau khi gộp mọi drop-in)
và so với baseline gồm 18 chỉ thị:

```
$ btl audit
Checked 18 directives: 18 compliant, 0 weak, 0 missing.
```

Kết quả trả về mã thoát khác 0 nếu có chỉ thị yếu hoặc thiếu, nên có thể
dùng trong CI hoặc cron.

### 4.4. Bộ kiểm định cấu hình sinh ra

Vì một chỉ thị sai có thể làm `sshd -t` thất bại và khiến máy chủ không
khởi động được, dự án có `btl/security/validate.py` với danh sách chỉ thị
được phép phát ra. Validator chạy **trong quá trình sinh cấu hình**, tức là
lỗi bị bắt ngay trên máy trạm chứ không phải trên máy chủ.

Bản thân validator đã bắt được hai lỗi thật trong quá trình phát triển:

| Chỉ thị | Vấn đề | Cách sửa |
| --- | --- | --- |
| `LoginFailedAttempts` | **Không tồn tại** trong bất kỳ phiên bản OpenSSH nào | Gỡ bỏ khỏi baseline |
| `UsePrivilegeSeparation` | Bị deprecated từ OpenSSH 7.5, có thể khiến sshd **không khởi động được** | Gỡ khỏi cấu hình sinh ra |

Ngoài ra `PerSourcePenalties` (OpenSSH 9.8+) cũng bị loại có chủ ý, vì
Ubuntu 24.04 đi kèm OpenSSH 9.6 và chỉ thị không tồn tại sẽ làm hỏng cấu
hình. Việc chống brute force đã được `MaxAuthTries` và fail2ban đảm nhiệm.

### 4.5. Phòng thủ bổ sung

| Thành phần | Cấu hình |
| --- | --- |
| **fail2ban** | Jail `sshd` với `maxretry=3`, `bantime=1h`, `mode=aggressive`; jail `recidive` ban 1 tuần khi tái phạm; `bantime.increment` cho ban tăng dần (tối đa 1 tuần) |
| **ufw** | `default deny incoming`; `ufw allow 22/tcp` (mặc định) hoặc `ufw limit 22/tcp` với cờ `--ufw-limit-ssh`; reset trước khi áp dụng để idempotent |
| **auditd** | 9 nhóm rule theo dõi `sshd_config`, `authorized_keys`, `passwd`/`group`/`shadow`, `sudoers`, thư mục jail, và mọi lệnh `execve` của root |

### 4.6. Kết quả kiểm chứng trên máy chủ thật

Cấu hình đã cài đặt trên `192.168.118.128` (Ubuntu 26.04, OpenSSH 10.2):

```
$ sshd -T | grep -E '^(permitrootlogin|passwordauthentication|...)'
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
maxauthtries 3
logingracetime 30
allowgroups sshusers
allowtcpforwarding no
loglevel VERBOSE

$ ufw status verbose
Status: active
Default: deny (incoming), allow (outgoing)
22/tcp   ALLOW IN   Anywhere

$ getent group sshusers
sshusers:x:1001:tuananh,btladmin,ftpsvc

$ ls -ld /opt/sftp-jails/ftpsvc /opt/sftp-jails/ftpsvc/upload
drwxr-xr-x 3 root   root   4096 /opt/sftp-jails/ftpsvc
drwx------ 2 ftpsvc ftpsvc 4096 /opt/sftp-jails/ftpsvc/upload
```

`btl audit` trả về `Checked 18 directives: 18 compliant, 0 weak, 0 missing.`

> **Ghi chú về `ChallengeResponseAuthentication`:** đây là *alias đã lỗi thời*
> của `KbdInteractiveAuthentication`. File cấu hình vẫn ghi tên cũ (đúng như
> `sshd_config(5)` chấp nhận), nhưng OpenSSH 10.x chỉ in **tên chuẩn** ra
> output của `sshd -T`. Auditor vì vậy phải tra bảng alias để kiểm định đúng
> chỉ thị — nếu không, nó sẽ báo động giả "missing" cho một chỉ thị đã được
> đặt đúng.

---

## 5. Phần 2 — Giao thức SCP

### 5.1. Đặc tả

SCP (scp1) là giao thức truyền file một chiều theo **vai trò**:

- **Source** (`scp -f`): bên gửi.
- **Sink** (`scp -t`): bên nhận.

Bắt tay: **bên sink luôn gửi** byte `\x00` trước để báo sẵn sàng, và **bên còn
lại luôn phải đọc** byte đó trước khi gửi thông điệp đầu tiên. Đây là điểm
dễ sai nhất của giao thức, vì nó đối xứng:

| Hướng | Bên sink là ai | Thứ tự |
| --- | --- | --- |
| Tải lên (ta chạy `scp -t` ở máy chủ) | Máy chủ | Máy chủ gửi `\x00` → ta đọc → ta gửi `C...` |
| Tải về (ta chạy `scp -f` ở máy chủ) | Ta | Ta gửi `\x00` → máy chủ đọc → máy chủ gửi `C...` |

Thông điệp điều khiển là các dòng ASCII kết thúc bằng `\n`:

| Byte | Ý nghĩa | Ví dụ |
| --- | --- | --- |
| `C` | Tạo file | `C0644 299 group` |
| `D` | Bắt đầu thư mục | `D0755 0 docs` |
| `E` | Kết thúc thư mục | `E` |
| `T` | Thời gian | `T1183828267 0 1183828267 0` |

Sau thông điệp `C` đúng `size` byte dữ liệu thô sẽ đến. **Không có framing
riêng cho nội dung file**, nên bên đọc buộc phải đọc đúng độ dài đã công bố.

Sau nội dung file, bên gửi ghi thêm **một byte `\x00`** làm dấu kết thúc dữ
liệu rồi mới chờ xác nhận; bên nhận đọc đúng byte đó trước khi xác nhận. Nếu
một bên bỏ qua bước này, hai bên lệch pha ngay từ file đầu tiên.

Với thư mục, thông điệp `E` ở cấp ngoài cùng đánh dấu kết thúc **toàn bộ**
luồng — bên nhận phải dừng lại thay vì chờ thêm dữ liệu.

Xác nhận: `\x00` thành công, `\x01` cảnh báo, `\x02` lỗi chí mạng.

### 5.2. Đối chiếu với mã nguồn OpenSSH

Đặc tả trên không có bản chính thức, nên mọi chi tiết framing đều được đối
chiếu trực tiếp với `scp.c` của OpenSSH
([openssh-portable](https://github.com/openssh/openssh-portable/blob/master/scp.c)).
Quá trình này phát hiện **bốn lỗi giao thức nghiêm trọng** trong bản hiện thực
đầu tiên, mà **không** lỗi nào bị unit test phát hiện:

| Lỗi | Hậu quả |
| --- | --- |
| Thiếu byte kết thúc nội dung file | Hai bên lệch pha, file bị hỏng |
| `get()` đọc sai chiều byte ready | Lệnh tải về **treo vô hạn** |
| `put()` không đọc byte ready của máy chủ | Xác nhận lệch một vị trí, lệnh treo |
| Hai bộ đệm độc lập trên cùng một kênh | **Mất byte** khi thông điệp và nội dung đến cùng gói TCP |

Đặc biệt, byte kết thúc nội dung file là chi tiết mà các bài viết mô tả SCP
bằng lời đều bỏ qua. Chỉ đọc mã nguồn tham chiếu mới thấy được:

```c
/* scp.c — phía producer, sau khi gửi xong nội dung file */
(void) atomicio(vwrite, remout, "", 1);
(void) response();
```

Hệ quả về mặt phương pháp: **test round-trip** (nối `ScpSource` với `ScpSink`
thật qua hai ống) là loại test duy nhất phát hiện được nhóm lỗi này. Dự án
bổ sung 9 test round-trip cho mục đích đó, và quy trình phát triển yêu cầu
mọi thay đổi vào codec phải kèm đối chiếu `scp.c`.

### 5.3. Cấu trúc mã nguồn

`btl/scp/protocol.py` chứa codec thuần túy, **không** phụ thuộc socket hay
Paramiko. Nó nhận ba callback (`read_line`, `read_exactly`, `write`), nhờ đó:

- Toàn bộ logic đóng khung được kiểm thử bằng pytest mà không cần mạng.
- Có thể tái sử dụng cho kênh SSH khác hoặc công cụ phân tích giao thức.

`btl/scp/client.py` bọc codec vào kênh SSH thật, cung cấp `put`/`get` và
`SCPServer` cho chế độ sink.

### 5.4. Chống path traversal

Đây là phần quan trọng nhất về mặt bảo mật. Ba lớp:

**Lớp 1 — Kiểm tra tên đơn vị.** `validate_relative_name()` từ chối tên chứa
`/`, `\`, `..`, `.`, hoặc byte NUL.

**Lớp 2 — Kiểm tra chứa chứa.** `SafePath.resolve()` kiểm tra rằng đường
dẫn đã resolve nằm trong thư mục đích.

**Lớp 3 — Kiểm tra symlink.** Sau khi `os.path.realpath()`, nếu kết quả nằm
ngoài thư mục gốc thì từ chối — bắt được symlink trỏ ra ngoài.

```python
# SCP client gửi tên "../../etc/passwd"
validate_relative_name("../../etc/passwd")
# → ValidationError: file name must not start with '..'
```

Quyết định thiết kế quan trọng: dự án **từ chối** thay vì **làm sạch**. Nếu
làm sạch, `../../etc/passwd` sẽ thành `etc_passwd` và hành vi tấn công bị
giấu đi. Từ chối giúp nó xuất hiện trong log.

### 5.5. Kiểm thử giao thức

**35 test** cho phần SCP, chia làm hai loại:

**Unit test (26)** — encode/decode mọi biến thể thông điệp, tên có khoảng
trắng, tên có ký tự escape, nhận file, nhận thư mục đệ quy, từ chối traversal,
từ chối đường dẫn tuyệt đối, phát hiện thân nội dung bị cắt cụt, và hành vi
khi peer từ chối.

**Round-trip test (9)** — nối `ScpSource` với `ScpSink` thật qua hai ống có
chặn, mỗi bên chạy ở một luồng riêng. Vì giao thức SCP là **lock-step**
(mỗi thông điệp phải chờ xác nhận trước khi gửi tiếp), hạ tầng kiểm thử
phải chạy song song hai bên — và chính loại test này đã phát hiện ra cả bốn
lỗi framing nêu ở mục 5.2. Các test bao phủ: file đơn, file rỗng, nội dung
nhị phân, file lớn (300 KiB), cây thư mục lồng nhau, vị trí đặt file trong
thư mục đúng, tên có khoảng trắng, nhiều file trong một thư mục, và thư mục
rỗng.


---

## 6. Phần 3 — SFTP

### 6.1. Vì sao SFTP an toàn hơn SCP

SFTP là giao thức request/response với framing độc lập, không phụ thuộc
shell từ xa. Nhưng mặc định nó vẫn cho phép người dùng thấy toàn bộ hệ
thống tệp, nên vẫn cần ràng buộc.

### 6.2. Virtual root ở phía client

```python
client = SFTPClient(sftp, root="/home/alice")
client.get("../../../etc/passwd", "local.txt")
# → ValidationError: path contains a parent directory reference
```

Điểm quan trọng: ràng buộc nằm ở **client**, nên nó bảo vệ cả khi máy chủ
bị cấu hình sai hoặc bị xâm nhập.

### 6.3. Chroot jail ở phía server

```ssh
Match User ftpsvc
    ChrootDirectory /opt/sftp-jails/ftpsvc
    ForceCommand internal-sftp -d /upload
    AllowTcpForwarding no
    X11Forwarding no
    PermitTTY no
    GatewayPorts no
```

Cấu trúc thư mục jail (đã kiểm tra trên máy chủ thật):

```
$ ls -ld /opt/sftp-jails/ftpsvc /opt/sftp-jails/ftpsvc/upload
drwxr-xr-x 3 root   root   4096 /opt/sftp-jails/ftpsvc
drwx------ 2 ftpsvc ftpsvc 4096 /opt/sftp-jails/ftpsvc/upload
```

```
/opt/sftp-jails/ftpsvc/        root:root    755   ← bắt buộc, nếu không sẽ thoát được
└── upload/                    ftpsvc:ftpsvc 700  ← nơi được ghi
```

Ba điều kiện để jail không bị thoát:

1. Thư mục gốc jail phải thuộc `root` và **không** group/world writable —
   nếu không, `chroot()` sẽ thất bại.
2. `ForceCommand internal-sftp` chạy SFTP server trong tiến trình, không cần
   shell.
3. `PermitTTY no` + `AllowTcpForwarding no` chặn mọi đường vòng qua.

### 6.4. Đặc điểm khác

- **Resume**: dùng `seek` trên handle SFTP để tiếp tục file bị gián đoạn.
- **`puttree`**: tải lên cây thư mục đệ quy với thứ tự xác định.
- **`SFTPServer`**: thay thế không cần chroot, dùng khi máy chủ không chạy
  quyền root.

---

## 7. Phần 4 — Quản lý khóa host

### 7.1. Chính sách

| Tình huống | Hành động |
| --- | --- |
| Khóa khớp kho | Chấp nhận |
| Khóa chưa có trong kho | **Từ chối**, yêu cầu thêm thủ công |
| Khóa đã thay đổi | **Lỗi chí mạng**, nêu rõ fingerprint cũ |
| Kiểu khóa không hỗ trợ | Từ chối |

Mặc định `auto_accept=False`. Đây là điểm khác biệt lớn nhất so với
`StrictHostKeyChecking=accept-new` của OpenSSH — vốn chỉ cảnh báo rồi chấp
nhận.

### 7.2. Hai lớp kiểm định

Dự án không dựa vào mặc định của Paramiko:

```python
client.set_missing_host_key_policy(paramiko.RejectPolicy())   # lớp 1
...
policy.check(host, port, transport.get_remote_server_key())    # lớp 2
```

### 7.3. Kho known_hosts

Dùng định dạng `known_hosts` chuẩn của OpenSSH nên có thể kiểm tra và chỉnh
sửa bằng công cụ quen thuộc. Có hỗ trợ cổng không mặc định theo quy ước
`[host]:port`.

---

## 8. Phần 5 — Công cụ dòng lệnh

```
btl [--verbose] [--log-file FILE] <command>

  ssh        chạy lệnh từ xa, xem thông tin năng lực máy chủ
  scp        chuyển file (thêm/tải về, đệ quy)
  sftp       liệt kê, thêm, tải về, tiếp tục
  hostkey    liệt kê / thêm / xoá khóa máy chủ tin cậy
  audit      kiểm định cấu hình sshd hiệu lực
  render     sinh cấu hình mà không cần kết nối máy chủ
  provision  cấu hình máy chủ Ubuntu mới
```

### 8.1. Lệnh `render`

Đặc biệt hữu ích: sinh cấu hình mà **không cần kết nối** máy chủ, dùng để
xem trước hoặc kiểm tra bằng mắt.

```bash
$ btl render sshd --port 2222
$ btl render sshd-sftp --sftp-users alice,bob
$ btl render fail2ban
$ btl render firewall
$ btl render audit
```

### 8.2. Lệnh `provision`

Thực hiện 8 bước theo thứ tự an toàn:

```
1. cài package (openssh-server, fail2ban, ufw, auditd, python3-paramiko)
2. tạo group sshusers
3. tạo tài khoản quản trị + khóa mật khẩu
4. tạo tài khoản SFTP + jail
5. ghi 5 file cấu hình
6. sshd -t              ← nếu sai thì DỪNG, không reload
7. systemctl reload ssh
8. augenrules --load
```

Mỗi bước kiểm tra trạng thái trước khi thay đổi → **idempotent**, chạy lại
nhiều lần cho cùng kết quả.

Có `--dry-run` để xem trước toàn bộ thay đổi mà không chạm vào máy chủ.

---

## 9. Kiểm thử

### 9.1. Kết quả

```
$ python -m pytest tests/
200 passed, 1 skipped in 0.56s
```

| Nhóm | Nội dung |
| --- | --- |
| `test_scp_protocol.py` | Codec, sink, source, traversal, cắt cụt, round-trip |
| `test_paths.py` | Chuẩn hoá đường dẫn, chứa chứa, symlink, sanitize |
| `test_security.py` | Chính sách sshd, auditor (kể cả alias), fail2ban, ufw, auditd, known_hosts |
| `test_validate.py` | Validator chỉ thị, các chỉ thị đã loại |
| `test_cli.py` | Parser, provisioning script, render, nạp khóa |
| `test_scp_client.py` | Client SCP: chuẩn bị đường dẫn đích, đổi tên sau khi nhận |
| `test_scp_roundtrip.py` | Round-trip qua hai ống có chặn |

### 9.2. Ba tầng kiểm thử

| Tầng | Công cụ | Cần mạng | Kết quả thật |
| --- | --- | --- | --- |
| Đơn vị | pytest | Không | 192 pass, 1 skip |
| Tích hợp | `scripts/test-e2e.sh` | Có | **38/38 PASS** |
| Kiểm định | `btl audit` | Chạy trên máy chủ | **18/18 compliant** |

### 9.3. Các lỗi phát hiện và sửa trong quá trình phát triển

| Lỗi | Nguyên nhân | Cách sửa |
| --- | --- | --- |
| Decode sai mode/size | Tưởng mode tách bằng dấu cách, thực tế dính vào ký tự đầu (`C0644`) | Viết test cho từng biến thể thông điệp |
| Parse sai tên có khoảng trắng | Tách `text.split(" ", 2)` rồi lấy sai chỉ số | Tách mode/size/name rõ ràng, giữ nguyên phần còn lại làm tên |
| `sanitize_filename` chưa loại `..` | Chỉ thay `/` và `\` | Loại bỏ chuỗi `..` bằng vòng lặp |
| `SafePath` trộn POSIX với native | Dùng `posixpath` cho đường dẫn Windows | Tách `remote_to_native()` / `native_to_remote()` |
| `KnownHostsStore.add` bỏ qua port | Không dùng `format_known_hosts()` | Sửa để ghi `[host]:port` |
| `paramiko.DSSKey` không tồn tại | Xoá trong Paramiko 3+ | Bỏ khỏi danh sách key class |
| `UsePrivilegeSeparation` làm hỏng cấu hình | Deprecated từ OpenSSH 7.5 | Gỡ khỏi cấu hình sinh ra |
| `LoginFailedAttempts` không tồn tại | Chỉ thị không có trong OpenSSH | Gỡ khỏi baseline |
| Xung đột `-p` trong argparse | `-p` vừa là port vừa là preserve-times | Bỏ short flag của preserve-times |
| Thiếu `import base64` | Nạp public key thất bại | Thêm import |

### 9.4. Các lỗi chỉ lộ ra khi chạy trên máy chủ thật

Mười hai lỗi dưới đây **không** xuất hiện khi chạy unit test hay test trên
máy trạm — chúng chỉ xuất hiện khi đặt dự án lên một máy chủ SSH thật và
chạy bộ kiểm thử tích hợp. Chi tiết đầy đủ ở
[10-nhat-ky-thuat.md](10-nhat-ky-thuat.md), mục 1.17–1.28.

| # | Lỗi | Mức độ |
| --- | --- | --- |
| 1 | `RejectPolicy` của Paramiko chặn host key trước khi policy của dự án kịp chạy | Cao |
| 2 | `sudo -S` không nhận được mật khẩu vì stdin không được gửi | Cao |
| 3 | File cấu hình ghi vào `/tmp` rồi bị bỏ lại đó, drop-in không bao giờ tới sshd | Cao |
| 4 | `passwd -l` khoá tài khoản quản trị mà không cài `authorized_keys` | Cao |
| 5 | `AllowGroups sshusers` khoá cả tài khoản provisioning và tài khoản SFTP | Cao |
| 6 | `ufw` bật trước khi có rule SSH → mất kết nối ngay sau provisioning | Cao |
| 7 | `ufw limit 22/tcp` chặn loạt phiên quản trị giữa chừng bộ test | Cao |
| 8 | fail2ban chế độ `aggressive` ban IP của chính máy trạm quản trị | Cao |
| 9 | `ChallengeResponseAuthentication` là alias đã lỗi thời, auditor báo động giả | Trung bình |
| 10 | `btl scp --download` đảo ngược ý nghĩa hai tham số vị trí | Trung bình |
| 11 | Tải về tạo ra thư mục thay vì tệp | Trung bình |
| 12 | `python3` trên Windows có thể là stub của Microsoft Store | Thấp |
| 13 | `authorized_keys` nhân bản mỗi lần provision (`>>` vô điều kiện) | Cao |
| 14 | Lệnh `awk` escape sai làm rỗng `authorized_keys` → mất đăng nhập | Cao |
| 15 | `ssh-keyscan` dùng định dạng `known_hosts`, `hostkey add` không đọc được | Cao |
| 16 | `btl ssh` sập khi máy chủ trả về tiếng Việt (console Windows dùng code page cũ) | Trung bình |
| 17 | Paramiko 5 bỏ accessor `cipher()`/`mac()`/`compression` → `--info` crash | Cao |

---

## 10. Kết quả và đánh giá

### 10.1. Đạt được

| Mục tiêu | Kết quả |
| --- | --- |
| Hardening máy chủ | 18 chỉ thị baseline + 5 lớp phòng thủ, kiểm định tự động, **18/18 compliant** trên máy chủ thật |
| Truyền file an toàn | Chống traversal + symlink escape ở cả SCP và SFTP, xác minh bằng E2E **38/38** |
| Hiểu giao thức SCP | Hiện thực hoá đầy đủ, đối chiếu mã nguồn OpenSSH, tương thích byte-for-byte với `/usr/bin/scp` thật |
| Công cụ dùng được | 7 nhóm lệnh, tài liệu đầy đủ, đã chạy thật trên Ubuntu 26.04 |
| Chất lượng | 192 test tự động, 0 lỗi |

### 10.2. Hạn chế

| Hạn chế | Lý do | Khắc phục |
| --- | --- | --- |
| Chưa có MFA | Cần cấu hình PAM phức tạp | Đề xuất `libpam-google-authenticator` |
| Không có quản lý tập trung | Ngoài phạm vi bài tập | Script idempotent dễ port sang Ansible |
| Chưa kiểm thử với OpenSSH phiên bản cũ | Môi trường chỉ có OpenSSH 10.2 | Cần thêm máy ảo Ubuntu 22.04 |
| Chỉ hỗ trợ Ubuntu/Debian | Mục tiêu bài tập | — |

### 10.3. Hướng phát triển

1. **MFA** bằng TOTP cho tài khoản quản trị.
2. **Đối chiếu codec SCP** với client OpenSSH qua hội thoại thật.
3. **Module Ansible** thay cho script shell.
4. **Báo cáo định kỳ** từ `btl audit` gửi về email.
5. **Hỗ trợ khóa FIDO2** (`sk-ssh-ed25519@openssh.com`).

---

## 11. Kết luận

Đề tài đã được triển khai đầy đủ theo ba hướng chính: cấu hình hardening
máy chủ SSH, hiện thực hoá giao thức SCP với cơ chế bảo vệ đường dẫn, và
xây dựng lớp SFTP có ràng buộc thư mục.

### 11.1. Bài học về kiểm định tự động

Điều đáng chú ý nhất từ quá trình phát triển là vai trò của **kiểm định
tự động**:

- **Validator chỉ thị** bắt được hai lỗi cấu hình (`LoginFailedAttempts`
  không tồn tại, `UsePrivilegeSeparation` đã bị loại bỏ) — cả hai đều có thể
  khiến máy chủ không khởi động được nếu áp dụng trực tiếp.
- **Test tính nhất quán baseline ↔ policy** phát hiện ra `AllowGroups` và
  `AllowTcpForwarding` có trong cấu hình sinh ra nhưng thiếu trong baseline —
  tức là `btl audit` sẽ **không bao giờ** báo động về hai chỉ thị quan
  trọng nhất về phân quyền và chặn đường đi mạng.
- **Test round-trip** phát hiện ra bốn lỗi framing trong giao thức SCP mà
  không một unit test nào bắt được, vì mỗi hàm riêng lẻ đều hợp lý theo
  cách hiểu sai.

Cả ba đều cùng một thông điệp: *an toàn phải được kiểm chứng bằng công cụ,
không chỉ bằng cẩn thận khi gõ tay.*

Nhưng còn một tầng nữa mà **không tầng nào ở trên thay thế được**: **chạy
thật trên máy chủ thật**. Mười hai lỗi ở mục 9.4 đều là lỗi mà logic đúng,
test đúng, nhưng hành vi thực tế sai — vì:

- Callback của Paramiko được gọi ở một thời điểm mà tôi không hình dung đúng.
- `sudo -S` cần stdin, mà `exec_command()` mặc định không gửi.
- `AllowGroups` được đánh giá trước `Match`, nên thứ tự thêm nhóm mới quan
  trọng.
- `ufw limit` chỉ "đúng" khi lưu lượng thấp, và bộ kiểm thử có lưu lượng
  cao.
- Alias đã lỗi thời chỉ lộ ra khi đọc `sshd -T` của OpenSSH 10.x.

Đây là lý do bài kiểm tra cần **hai** loại tự động hóa: test đơn vị để giữ
logic đúng, và bộ kiểm thử tích hợp trên hạ tầng thật để giữ **hành vi**
đúng. Loại test quan trọng nhất không phải test "hàm này trả về đúng không",
mà là test **hệ thống có thực sự làm đúng việc không** — nối hai đầu thật của
giao thức, hoặc đối chiếu hai nguồn sự thật với nhau.

### 11.2. Bài học về tài liệu

Giao thức SCP không có đặc tả chính thức. Nếu chỉ dựa vào các bài viết mô
tả bằng lời, sẽ bỏ sót những chi tiết framing quyết định (byte kết thúc nội
dung file, chiều của byte "ready"). Đọc mã nguồn tham chiếu `scp.c` của
OpenSSH mới là cách **duy nhất** đảm bảo tương thích byte-for-byte — và đó
cũng là lý do dự án luôn ghi rõ nguồn tham chiếu cho từng quyết định về
giao thức.


---

## 12. Tài liệu tham khảo

Xem [09-tai-lieu-tham-khao.md](09-tai-lieu-tham-khao.md).
