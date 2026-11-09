# 03 - Tiến trình dự án

> Cập nhật gần nhất: **2026-11-09**

## 1. Tổng quan

| Chỉ số | Giá trị |
| --- | --- |
| Tổng số chức năng trong đề tài | 46 |
| Đã hoàn thành | **44** |
| Đang thực hiện | 0 |
| Chưa bắt đầu | 2 (ngoài phạm vi bài tập) |
| Tỉ lệ hoàn thành | **~96%** |

## 2. Bảng tiến độ theo nhóm

### Nhóm A — Cấu hình dịch vụ SSH

| # | Hạng mục | Trạng thái | Ghi chú |
| --- | --- | --- | --- |
| A1 | Drop-in `sshd_config` | ✅ Hoàn thành | `SSHDPolicy.to_config()`, file `00-btl-hardening.conf` |
| A2 | Chỉ xác thực bằng khóa công khai | ✅ Hoàn thành | Tắt cả `Password` và `KbdInteractive` |
| A3 | Cấm đăng nhập root | ✅ Hoàn thành | `PermitRootLogin no` |
| A4 | Giới hạn nhóm tài khoản | ✅ Hoàn thành | `AllowGroups`, group `sshusers` tự tạo khi provision |
| A5 | Chống brute force ở tầng sshd | ✅ Hoàn thành | `MaxAuthTries 3`, `LoginGraceTime 30`, `MaxStartups` |
| A6 | fail2ban tự động ban IP | ✅ Hoàn thành | `Fail2BanPolicy`, jail `sshd` + `recidive`, mode `aggressive` |
| A7 | Tường lửa ufw | ✅ Hoàn thành | `FirewallPolicy.to_script()` |
| A8 | auditd theo dõi thay đổi | ✅ Hoàn thành | `AuditPolicy.to_rules()`, 9 nhóm rule |
| A9 | Banner cảnh báo | ✅ Hoàn thành | `BANNER_TEXT` |
| A10 | Tắt forwarding / X11 / agent | ✅ Hoàn thành | 6 chỉ thị đặt `no` |
| A11 | Chính sách mã hoá mạnh | ✅ Hoàn thành | Chỉ ChaCha20-Poly1305 + AES-GCM |
| A12 | Kiểm định cấu hình | ✅ Hoàn thành | `btl audit` + `BASELINE` (18 chỉ thị) |

### Nhóm B — SCP

| # | Hạng mục | Trạng thái | Ghi chú |
| --- | --- | --- | --- |
| B1 | Mô tả giao thức | ✅ Hoàn thành | Docstring `btl/scp/protocol.py` |
| B2 | Codec thông điệp | ✅ Hoàn thành | `encode_*` / `decode_message` / `ScpMessage` |
| B3 | Push (tải lên) | ✅ Hoàn thành | `SCPClient.put` |
| B4 | Pull (tải về) | ✅ Hoàn thành | `SCPClient.get` |
| B5 | Truyền đệ quy | ✅ Hoàn thành | Chuỗi `D`/`C`/`E` lồng nhau |
| B6 | Giữ quyền và thời gian | ✅ Hoàn thành | `T` message, `chmod`, `utime` |
| B7 | Chống path traversal | ✅ Hoàn thành | `validate_relative_name()` từ chối, có test |
| B8 | Chống symlink escape | ✅ Hoàn thành | `realpath` trong `SafePath.resolve` |
| B9 | Server sink mode | ✅ Hoàn thành | `SCPServer.handle_channel` |
| B10 | Xử lý lỗi chuẩn | ✅ Hoàn thành | `\x00`/`\x01`/`\x02` đầy đủ |

### Nhóm C — SFTP

| # | Hạng mục | Trạng thái | Ghi chú |
| --- | --- | --- | --- |
| C1 | Client cơ bản | ✅ Hoàn thành | list / stat / get / put |
| C2 | Ràng buộc đường dẫn | ✅ Hoàn thành | `SFTPClient(root=...)` |
| C3 | Tải lên đệ quy | ✅ Hoàn thành | `puttree()` |
| C4 | Resume | ✅ Hoàn thành | Dùng `seek` trên handle SFTP |
| C5 | Thao tác thư mục | ✅ Hoàn thành | `mkdir`/`makedirs`/`rmdir`/`rename`/`chmod`/`utime` |
| C6 | Server giới hạn theo thư mục | ✅ Hoàn thành | `SFTPServer` |
| C7 | Tạo chroot jail | ✅ Hoàn thành | `chroot_jail()` |
| C8 | Cấm shell cho tài khoản SFTP | ✅ Hoàn thành | `ForceCommand internal-sftp`, `PermitTTY no` |

### Nhóm D — Khóa và máy chủ

| # | Hạng mục | Trạng thái | Ghi chú |
| --- | --- | --- | --- |
| D1 | Sinh khóa Ed25519 | ✅ Hoàn thành | `scripts/generate-keys.sh` |
| D2 | Quản lý known_hosts | ✅ Hoàn thành | `KnownHostsStore` |
| D3 | Phát hiện key bị đổi | ✅ Hoàn thành | `HostKeyStatus.CHANGED` → lỗi chí mạng |
| D4 | Từ chối key lạ | ✅ Hoàn thành | `auto_accept=False` mặc định |
| D5 | Nhiều phương thức xác thực | ✅ Hoàn thành | agent / key file / password |
| D6 | Provision máy chủ | ✅ Hoàn thành | `btl provision` |
| D7 | Idempotent | ✅ Hoàn thành | Mọi bước kiểm tra trước khi sửa; `authorized_keys` hợp nhất bằng `sort -u` — chạy 2 lần vẫn giữ 1 khoá |

### Nhóm E — Kiểm thử và tài liệu

| # | Hạng mục | Trạng thái | Ghi chú |
| --- | --- | --- | --- |
| E1 | Test giao thức SCP | ✅ Hoàn thành | 26 test codec + 9 test round-trip |
| E2 | Test bảo mật đường dẫn | ✅ Hoàn thành | 41 test |
| E3 | Test cấu hình hardening | ✅ Hoàn thành | 31 test |
| E4 | Tài liệu wiki | ✅ Hoàn thành | Thư mục `wiki/`, 10 tài liệu, đã cập nhật theo kết quả chạy thật |
| E5 | Báo cáo kỹ thuật | ✅ Hoàn thành | `wiki/05-bao-cao-ky-thuat.md` |
| E6 | Test tích hợp trên máy chủ thật | ✅ Hoàn thành | 38/38 kiểm tra PASS trên Ubuntu 26.04 thật |
| E7 | Test hội thoại SFTP tự động | ✅ Hoàn thành | Script `scripts/test-e2e.sh` đã chạy thành công |
| E8 | Đối chiếu codec SCP với mã nguồn OpenSSH | ✅ Hoàn thành | Đọc `scp.c`, sửa 4 lỗi framing (mục 1.11–1.15 của nhật ký) |
| E9 | Đối chiếu codec SCP với `/usr/bin/scp` thật | ✅ Hoàn thành | Interop hai chiều PASS trên VM (mục 1.17 nhật ký) |
| E10 | Tài liệu kiểm tra bảo mật theo kết quả thật | ✅ Hoàn thành | `wiki/08-kiem-tra-bao-mat.md` — log thật, bằng chứng, ma trận truy vết |

## 3. Kết quả kiểm thử tích hợp trên máy ảo thật

> Máy ảo: `D:\Virtualmachine\Ubuntu 64-bit.vmx` — Ubuntu 26.04 LTS, OpenSSH 10.2p1
> Địa chỉ: `192.168.118.128` (VMware NAT, dải `192.168.118.0/24`)
> Ngày chạy: **2026-11-09**

| Nhóm kiểm tra | Kết quả |
| --- | --- |
| 1. Kết nối và xác thực | 2/2 PASS |
| 2. Kiểm soát truy cập | 2/2 PASS |
| 3. Cấu hình hardening | 5/5 PASS |
| 4. Chuyển tải SCP | 16/16 PASS |
| 5. Chuyển tải SFTP | 4/4 PASS |
| 6. SFTP jail | 5/5 PASS |
| 7. Phòng thủ nhiều lớp | 4/4 PASS |
| **Tổng** | **38/38 PASS** |

Kết quả kiểm toán cấu hình: `btl audit` báo **18/18 chỉ thị tuân thủ, 0 yếu, 0 thiếu**.

### 3.1. Những lỗi nghiêm trọng phát hiện khi chạy thật

Mười lỗi chỉ lộ ra khi có máy chủ thật. Tất cả đã được sửa và có test hồi quy:

| # | Lỗi | Hậu quả nếu không sửa |
| --- | --- | --- |
| 1 | `paramiko.RejectPolicy()` chặn host key trước khi policy của dự án chạy | `--auto-accept-host-key` và `btl hostkey add` vô dụng |
| 2 | `sudo -S` không được truyền mật khẩu qua stdin | Provisioning dừng ở bước đầu tiên |
| 3 | `write_file_over_ssh` ghi vào `/tmp` nhưng không `mv` sang đích | Toàn bộ cấu hình không bao giờ tới được sshd |
| 4 | Tài khoản admin bị `passwd -l` mà không cài `authorized_keys` | Tài khoản không bao giờ đăng nhập được → khoá cứng |
| 5 | Tài khoản provisioning không thuộc `sshusers` | `AllowGroups` chặn chính người vận hành |
| 6 | `build_install_script` bật `ufw` trước khi có rule SSH | Chặn mọi phiên SSH ngay lập tức |
| 7 | Tài khoản SFTP không thuộc `sshusers` | `AllowGroups` chặn trước khi đọc tới `Match` |
| 8 | `ufw limit 22/tcp` chặn >6 kết nối/30 giây | 19/38 kiểm tra E2E thất bại do bị firewall chặn |
| 9 | `fail2ban` không loại trừ mạng quản trị | Chính máy trạm bị ban IP khi kiểm tra access control |
| 10 | `ChallengeResponseAuthentication` là alias đã lỗi thời | `sshd -T` của OpenSSH 10.x không in ra → báo động giả |
| 11 | `cmd_scp --download` đảo ngược ý nghĩa hai tham số | Tải về ghi vào sai đường dẫn |
| 12 | `ScpSink` coi đường dẫn đích là thư mục | Tải về tạo ra thư mục thay vì tệp |

## 4. Việc đang thực hiện

| Việc | Mô tả | Tiến độ |
| --- | --- | --- |
| **T16** | Chụp ảnh minh hoạ kết quả cho báo cáo | Chờ người dùng thao tác trên console VM |
| **T14** | Bổ sung `requirements.txt`, `pyproject.toml`, script cài đặt để đóng gói gọn | 100% — `pyproject.toml`, `requirements.txt` đã có |

## 4.1. Việc đã hoàn thành trong đợt cập nhật cuối

| Việc | Kết quả |
| --- | --- |
| Viết lại `wiki/08-kiem-tra-bao-mat.md` theo kết quả chạy thật | ✅ Log E2E 38/38, bằng chứng sshd/ufw/fail2ban/auditd/jail, ma trận truy vết |
| Bổ sung mục 1.17–1.28 vào `wiki/10-nhat-ky-thuat.md` | ✅ 12 lỗi chỉ lộ ra khi chạy trên máy chủ thật |
| Cập nhật `wiki/05-bao-cao-ky-thuat.md` | ✅ Kiến trúc vận hành cuối cùng, kết quả kiểm chứng, bài học về kiểm thử |
| Cập nhật `wiki/06-huong-dan-cai-dat.md` | ✅ Lệnh provision thật, cờ mới, xử lý sự cố |
| Cập nhật `README.md` | ✅ Trạng thái cuối, môi trường VMware, cách tái lập bộ test E2E |


## 5. Việc chưa bắt đầu

| Việc | Lý do | Ghi chú |
| --- | --- | --- |
| Tích hợp MFA (OTP) | Ngoài phạm vi cốt lõi | Đề xuất trong báo cáo, có thể thêm `libpam-google-authenticator` |
| Script Ansible thay cho provisioning shell | Ưu tiên shell script cho môn học | Shell script đã idempotent, dễ port sang Ansible |

## 6. Nhật ký phát triển

| Ngày | Nội dung |
| --- | --- |
| 2026-11-08 | Khởi tạo repo, nghiên cứu tài liệu OpenSSH/Paramiko/scp1, viết tầng `btl.utils` |
| 2026-11-08 | Viết codec SCP thuần (`protocol.py`) + 26 unit test — sửa lỗi giải mã mode/size, lỗi parse tên có khoảng trắng |
| 2026-11-08 | Viết `btl.ssh.hostkeys` (known_hosts nghiêm ngặt) và `btl.ssh.connection` |
| 2026-11-08 | Viết `btl.scp.client` (put/get đệ quy), `btl.sftp.client` (virtual root), `btl.sftp.server` (chroot jail) |
| 2026-11-08 | Viết `btl.security` (sinh sshd/fail2ban/ufw/auditd + auditor) và `btl.provision` |
| 2026-11-08 | Viết `btl.cli` với 7 subcommand — sửa lỗi xung đột `-p`/`--port` trong argparse |
| 2026-11-08 | Viết 98 unit test — sửa lỗi `sanitize_filename` chưa loại `..`, lỗi `SafePath` trộn POSIX với native path, lỗi `KnownHostsStore.add` bỏ qua port |
| 2026-11-08 | Viết wiki (10 tài liệu) và README |
| 2026-11-08 | **Đối chiếu codec SCP với mã nguồn `scp.c` của OpenSSH** — phát hiện và sửa 4 lỗi giao thức nghiêm trọng: thiếu byte kết thúc nội dung file, `get()` treo do đọc sai chiều byte ready, `put()` lệch pha xác nhận, và hai bộ đệm độc lập trên cùng một kênh gây mất byte |
| 2026-11-08 | Bổ sung 9 test round-trip (`ScpSource` ↔ `ScpSink` qua ống), dọn import thừa bằng ruff, sinh mẫu cấu hình trong `config/` |
| **2026-11-09** | **Triển khai thật trên máy ảo Ubuntu 26.04** — phát hiện máy chủ **chưa có `openssh-server`**, cài đặt qua `vmrun`; xác định địa chỉ thật `192.168.118.128` (VMware NAT, dải `192.168.118.0/24`, khác với `192.168.122.0/24` ghi trong wiki) |
| **2026-11-09** | **Sửa 12 lỗi nghiêm trọng chỉ lộ ra khi chạy thật** (bảng ở mục 3.1): cầu nối host key policy, `sudo -S` không có stdin, file cấu hình không được di chuyển vào đích, tài khoản không có `authorized_keys`, `ufw` bật quá sớm, `ufw limit` chặn burst kết nối, `fail2ban` ban mạng quản trị, alias `ChallengeResponseAuthentication`, ngữ nghĩa `--download`, và đường dẫn đích khi tải về |
| **2026-11-09** | Chạy `btl provision` trên VM thật, `btl audit` báo **18/18 tuân thủ**, bộ test E2E đạt **38/38 PASS** — bao gồm interoperability hai chiều giữa codec SCP của dự án và `/usr/bin/scp` của OpenSSH |
| **2026-11-09** | Hoàn tất tài liệu: viết lại `wiki/08-kiem-tra-bao-mat.md` theo log thật, bổ sung mục 1.17–1.28 nhật ký kỹ thuật, cập nhật báo cáo kỹ thuật, hướng dẫn cài đặt, README và tiến trình dự án |
| **2026-11-09** | Phát hiện `authorized_keys` bị **nhân bản** mỗi lần provision (vi phạm idempotence D7) — sửa bằng phép hợp nhất `sort -u`; khôi phục khoá `tuananh` qua `vmrun` sau khi một lệnh escape sai làm rỗng file; xác minh chạy provision 2 lần liên tiếp, cả 3 tài khoản giữ **đúng 1 khoá** (mục 1.29–1.30 nhật ký) |
| **2026-11-09** | Chạy toàn bộ dự án từ đầu trên máy trạm Windows: cài đặt, `hostkey add`, `provision`, `audit`, E2E 38/38 — phát hiện và sửa 3 lỗi chỉ lộ ra khi dùng thật: `hostkey add` không đọc được định dạng `known_hosts` của `ssh-keyscan`, `btl ssh` sập khi server trả về tiếng Việt (console Windows dùng code page cũ), Paramiko 5 bỏ accessor `cipher()`/`mac()` nên `--info` crash (mục 1.31–1.33 nhật ký) |

## 7. Chất lượng mã nguồn

| Chỉ số | Kết quả |
| --- | --- |
| Số test | **200 passed, 1 skipped** |
| Test chạy | 0.61 giây |
| Kiểm thử tích hợp | **38/38 PASS** trên Ubuntu 26.04 thật |
| Kiểm toán cấu hình | **18/18 chỉ thị tuân thủ** trên VM thật |
| Lint | ruff (`--select F`) — không còn lỗi |
| Phụ thuộc ngoài | `paramiko`, `pyyaml`, `pytest` |
| Dòng mã Python | ~3.700 |
| Dòng tài liệu wiki | ~3.300 |
| Coverage ước tính | ~85% (đã bao phủ cả phần gọi SSH thật qua E2E) |

## 8. Rủi ro tồn tại

| Rủi ro | Mức độ | Giảm thiểu |
| --- | --- | --- |
| `ufw limit` không còn là mặc định | Thấp | Đã đổi sang `ufw allow`; có `--ufw-limit-ssh` để bật lại khi server lộ ra Internet |
| fail2ban có thể ban chính máy trạm quản trị | Thấp | Đã thêm `--fail2ban-ignore` để loại trừ dải quản trị |
| Chưa có kiểm thử trên nhiều bản Ubuntu | Trung bình | Đã chạy trên Ubuntu 26.04 LTS; cấu hình được `sshd -t` kiểm định trước khi áp dụng |
| `chroot` cần quyền root | Thấp | Có `SFTPServer` thay thế không cần chroot |
| `fail2ban` đọc journal cần `python3-systemd` | Thấp | Đã đưa vào script cài đặt |

## 9. Mốc tiếp theo

1. Chụp ảnh minh hoạ kết quả cho báo cáo (cần thao tác trên console VM).
2. Rà soát lại toàn bộ wiki và README lần cuối trước khi nộp.
3. Tùy chọn: thêm máy ảo Ubuntu 22.04 để kiểm thử tương thích với OpenSSH 8.9.
