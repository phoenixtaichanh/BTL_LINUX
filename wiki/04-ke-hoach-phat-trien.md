# 04 - Kế hoạch phát triển dự án

## 1. Triết lý kế hoạch

Dự án chia thành 6 giai đoạn (G). Mỗi giai đoạn có **tiêu chí hoàn thành**
rõ ràng để có thể kiểm chứng, không chỉ "đã làm xong".

Nguyên tắc: **kiểm thử trước, tích hợp sau**. Phần giao thức được viết
tách biệt khỏi vận chuyển để có thể test trọn vẹn trước khi nối vào SSH.

```
G1 ──▶ G2 ──▶ G3 ──▶ G4 ──▶ G5 ──▶ G6
nền    giao    vận    bảo    tích   đóng
tảng   thức    chuyển  mật   hợp    gói
```

## 2. Lộ trình tổng thể

| Giai đoạn | Nội dung | Thời lượng | Trạng thái |
| --- | --- | --- | --- |
| **G1** | Nền tảng: cấu trúc, error, logging, path safety | 1 ngày | ✅ |
| **G2** | Giao thức SCP thuần + unit test | 1.5 ngày | ✅ |
| **G3** | Vận chuyển SSH: host key, connection | 1 ngày | ✅ |
| **G4** | Bảo mật: sinh cấu hình, auditor, provisioning | 1.5 ngày | ✅ |
| **G5** | Tích hợp: CLI, test tích hợp trên VM | 2 ngày | 🔄 |
| **G6** | Đóng gói: tài liệu, báo cáo, demo | 1 ngày | 🔄 |

## 3. Chi tiết từng giai đoạn

### G1 — Nền tảng ✅

**Mục tiêu:** Dựng khung dự án và các nguyên tắc nền mà mọi phần sau dùng.

| Công việc | Đầu ra | Tiêu chí hoàn thành |
| --- | --- | --- |
| Cây exception | `btl/utils/errors.py` | Mọi lỗi kế thừa `BTLException` |
| Logging | `btl/utils/logging.py` | Thư viện không tự cấu hình log khi import |
| Path safety | `btl/utils/paths.py` | `SafePath` chặn được traversal + symlink escape |

**Rủi ro đã xử lý:** Rất sớm phát hiện việc trộn lẫn quy ước path POSIX
và native Windows khiến `SafePath` sinh ra đường dẫn sai. Đã tách
`remote_to_native()` / `native_to_remote()` để chuyển đổi tường minh.

---

### G2 — Giao thức SCP thuần ✅

**Mục tiêu:** Hiểu và hiện thực hoá giao thức scp1 không phụ thuộc mạng.

| Công việc | Đầu ra | Tiêu chí hoàn thành |
| --- | --- | --- |
| Encode/decode thông điệp | `protocol.py` | Round-trip đúng với tên có khoảng trắng và ký tự escape |
| Sink | `ScpSink` | Nhận file, tạo thư mục, từ chối traversal |
| Source | `ScpSource` | Gửi file/thư mục đệ quy, đọc ack đúng thứ tự |
| Unit test | `tests/test_scp_protocol.py` | 26 test xanh |

**Bài học rút ra:** Bản đầu tiên decode sai vì hiểu sai định dạng — mode
nằm *dính* vào ký tự đầu (`C0644`) chứ không tách bằng dấu cách. Sửa bằng
cách viết test cho từng biến thể thông điệp.

---

### G3 — Vận chuyển SSH ✅

**Mục tiêu:** Kết nối SSH an toàn với kiểm định host key nghiêm ngặt.

| Công việc | Đầu ra | Tiêu chí hoàn thành |
| --- | --- | --- |
| Known hosts | `btl/ssh/hostkeys.py` | Key đổi → lỗi chí mạng; key lạ → từ chối |
| Connection | `btl/ssh/connection.py` | 3 phương thức xác thực; `exec_command` trả exit status |

**Rủi ro đã xử lý:** Paramiko mặc định có thể chấp nhận key lạ. Dự án đặt
`RejectPolicy()` rồi kiểm tra lại bằng policy riêng — hai lớp, không dựa
vào mặc định của thư viện.

---

### G4 — Bảo mật và provisioning ✅

**Mục tiêu:** Sinh cấu hình hardening đúng cú pháp và provisioning idempotent.

| Công việc | Đầu ra | Tiêu chí hoàn thành |
| --- | --- | --- |
| SSHDPolicy | `sshd_config.py` | Sinh ra đúng 18 chỉ thị baseline |
| Auditor | `audit_config()` | So `sshd -T` với baseline, trả về ok/weak/missing |
| Fail2ban/ufw/auditd | `defense.py` | Cú pháp thật, dùng được ngay |
| Provisioning | `provisioner.py` | Chạy lại 2 lần cho cùng kết quả |

**Rủi ro đã xử lý:** Đặt `PasswordAuthentication no` ở cuối file chính
`sshd_config` sẽ **không có tác dụng** trên Ubuntu vì `50-cloud-init.conf`
đã đặt giá trị trước đó. Dự án luôn sinh file `00-btl-hardening.conf`.

---

### G5 — Tích hợp (đang làm) 🔄

**Mục tiêu:** Chứng minh toàn bộ hệ thống chạy đúng trên máy chủ Ubuntu thật.

| Công việc | Đầu ra | Tiêu chí hoàn thành |
| --- | --- | --- |
| CLI | `btl/cli.py` | 7 subcommand hoạt động |
| Script E2E | `scripts/test-e2e.sh` | Chạy xanh trên VM |
| Bài kiểm tra SFTP | `scripts/test-sftp-batch.sh` | Đối chiếu hành vi client OpenSSH |
| Ghi kết quả | `wiki/08-kiem-tra-bao-mat.md` | Có bảng kết quả thực tế |

**Danh sách kiểm tra E2E:**

- [ ] Đăng nhập bằng key thành công
- [ ] Đăng nhập bằng mật khẩu bị từ chối
- [ ] `ssh root@host` bị từ chối
- [ ] Tài khoản ngoài `sshusers` bị từ chối
- [ ] SCP upload 1 file
- [ ] SCP download 1 file
- [ ] SCP upload thư mục đệ quy
- [ ] SCP với tên `../../etc/passwd` bị từ chối
- [ ] SFTP liệt kê thư mục
- [ ] SFTP upload/download
- [ ] Tài khoản SFTP không mở được shell
- [ ] Tài khoản SFTP không thấy `/etc`
- [ ] Tài khoản SFTP không ghi ra ngoài `/upload`
- [ ] fail2ban ban IP sau 3 lần sai
- [ ] `btl audit` báo 0 weak, 0 missing
- [ ] auditd ghi lại thay đổi `sshd_config`

---

### G6 — Đóng gói 🔄

**Mục tiêu:** Hoàn thiện bàn giao.

| Công việc | Đầu ra | Tiêu chí hoàn thành |
| --- | --- | --- |
| `requirements.txt` | Tệp | Khớp với import thực tế |
| `pyproject.toml` | Tệp | `pip install -e .` chạy được |
| `README.md` | Tệp | Cài đặt + sử dụng + cấu trúc |
| Wiki | 10 tài liệu | Đủ 4 mục bắt buộc |
| Báo cáo | `wiki/05-bao-cao-ky-thuat.md` | Có phần đóng góp + kết quả test |
| Slide/thuyết trình | Ghi chú | 15–20 slide |

## 4. Lịch trình chi tiết

### Tuần 1 — Nền tảng và giao thức

| Ngày | Việc | Hoàn thành |
| --- | --- | --- |
| T2 | Cấu trúc dự án, `errors.py`, `logging.py` | ✅ |
| T3 | `paths.py` + test path safety | ✅ |
| T4 | `scp/protocol.py` codec + test | ✅ |
| T5 | Sửa lỗi decode, viết `ScpSink`/`ScpSource` | ✅ |
| T6 | `ssh/hostkeys.py` + test | ✅ |

### Tuần 2 — Vận chuyển, bảo mật, tài liệu

| Ngày | Việc | Hoàn thành |
| --- | --- | --- |
| T2 | `ssh/connection.py` | ✅ |
| T3 | `scp/client.py` put/get đệ quy | ✅ |
| T4 | `sftp/client.py` virtual root | ✅ |
| T5 | `sftp/server.py` chroot jail | ✅ |
| T6 | `security/sshd_config.py` + `defense.py` | ✅ |

### Tuần 3 — Tích hợp và bàn giao

| Ngày | Việc | Hoàn thành |
| --- | --- | --- |
| T2 | `provision/provisioner.py` + `cli.py` | ✅ |
| T3 | Test tổng, sửa lỗi còn lại (98 test) | ✅ |
| T4 | **Tạo máy ảo Ubuntu, chạy E2E** | 🔄 |
| T5 | **Bài kiểm tra SFTP, đối chiếu OpenSSH** | 🔄 |
| T6 | **Hoàn thiện wiki + báo cáo** | 🔄 |

## 5. Chiến lược kiểm thử

| Tầng | Công cụ | Phạm vi | Không cần mạng |
| --- | --- | --- | --- |
| Đơn vị | pytest | Codec, path, cấu hình, known_hosts | ✅ |
| Tích hợp | script bash + `btl` CLI | SCP/SFTP/SSH thật | ❌ (cần VM) |
| Kiểm định | `btl audit` | Cấu hình sshd trên VM | ❌ (chạy trên VM) |
| Thủ công | checklist E2E | Hành vi jail, fail2ban | ❌ |

**Nguyên tắc:** mọi thay đổi hành vi bảo mật phải có test tự động kèm theo.
Không có test nghĩa là chưa xong.

## 6. Quản lý rủi ro theo giai đoạn

| Giai đoạn | Rủi ro chính | Biện pháp |
| --- | --- | --- |
| G1 | Quy ước path không nhất quán | Tách hàm chuyển đổi POSIX ↔ native |
| G2 | Hiểu sai giao thức | Test từng biến thể thông điệp; đối chiếu tài liệu Oracle |
| G3 | Mặc định thư viện quá dễ tin | `RejectPolicy` + policy riêng, hai lớp |
| G4 | Cấu hình không có hiệu lực | Dùng drop-in `00-`; `sshd -t` trước khi reload |
| G5 | Chỉ chạy được trên giả lập | Test E2E bắt buộc, có checklist 16 mục |
| G6 | Tài liệu lệch với code | Rà soát chéo wiki ↔ CLI `--help` |

## 7. Định nghĩa "xong" (Definition of Done)

Một tính năng chỉ được coi là xong khi:

1. ✅ Code hoạt động đúng mô tả trong tài liệu.
2. ✅ Có test tự động (unit hoặc integration) chứng minh.
3. ✅ Xử lý đúng các trường hợp lỗi, không để exception thô.
4. ✅ Có docstring giải thích *tại sao*, không chỉ *cái gì*.
5. ✅ Được phản ánh trong wiki và README.
6. ✅ Với phần bảo mật: đã cân nhắc cách vượt qua và đã chặn.

## 8. Ngoài phạm vi (có chủ ý)

| Tính năng | Lý do không làm |
| --- | --- |
| Giao diện web | Môn học thiên về CLI và quản trị hệ thống |
| MFA/OTP | Cần cấu hình PAM phức tạp, đề xuất trong báo cáo |
| Quản lý tập trung | Quá phạm vi bài tập lớn |
| Hỗ trợ Windows Server | Mục tiêu là Ubuntu |
