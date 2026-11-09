# 09 - Tài liệu tham khảo

Danh sách các nguồn đã sử dụng trong quá trình phát triển. Truy cận ngày
**2026-11-08**.

---

## 1. Tài liệu chính thức OpenSSH

| # | Tài liệu | Liên kết | Dùng để |
| --- | --- | --- | --- |
| 1 | `sshd_config(5)` — Ubuntu manpage | https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html | Danh sách chỉ thị, giá trị hợp lệ, ngữ nghĩa `Match` |
| 2 | `sshd_config(5)` — OpenBSD | https://man.openbsd.org/sshd_config | Tham chiếu gốc |
| 3 | OpenSSH: How to Secure SSH on Ubuntu Servers | https://ubuntu.com/server/docs/how-to/security/openssh-server/ | Cơ chế drop-in `sshd_config.d` |
| 4 | Ubuntu: How to Harden Ubuntu SSH | https://ubuntu.com/blog/how-to-harden-ubuntu-ssh-cloud | Checklist hardening tổng quát |
| 5 | OpenSSH Release Notes (tất cả phiên bản) | https://www.openssh.org/releasenotes.html | Xác định chỉ thị nào tồn tại ở phiên bản nào |
| 6 | OpenSSH 9.8 release notes | https://www.openssh.org/txt/release-9.8 | `PerSourcePenalties` — chỉ có từ 9.8 |
| 7 | OpenSSH 7.5 release notes | https://www.openssh.org/txt/release-7.5 | `UsePrivilegeSeparation` bị deprecated |
| 8 | `ssh-keygen(1)`, `ssh(1)` | https://man.openbsd.org/ssh-keygen | Định dạng `known_hosts`, fingerprint |

**Điểm quan trọng rút ra từ #5–#7:** phải kiểm tra phiên bản OpenSSH trước
khi dùng một chỉ thị. Ubuntu 22.04 đi kèm OpenSSH 8.9, Ubuntu 24.04 đi kèm
OpenSSH 9.6 — cả hai đều **không** có `PerSourcePenalties`.

---

## 2. Giao thức SCP

| # | Tài liệu | Liên kết | Dùng để |
| --- | --- | --- | --- |
| 9 | Jan Pechanec — *How the SCP protocol works* | https://blogs.oracle.com/janp/entry/how_the_scp_protocol_works | Đặc tả đầy đủ: thông điệp `C`/`D`/`E`/`T`, byte xác nhận |
| 10 | Unix StackExchange — *What is the protocol for sending files over SSH?* | https://unix.stackexchange.com/questions/539423/ | Xác nhận định dạng, xử lý tên có khoảng trắng |
| 11 | `jbardin/scp.py` | https://github.com/jbardin/scp.py | Tham chiếu hiện thực bằng Python |
| 12 | AsyncSSH — mã nguồn `scp.py` | https://asyncssh.readthedocs.io/en/stable/_modules/asyncssh/scp.html | Tham chiếu hiện thực hiện đại, xử lý `T` và `-p` |
| 13 | Paramiko mailing list — *Emulating scp* | https://www.mail-archive.com/paramiko@lag.net/msg00283.html | Bài học: **phải** đọc byte xác nhận |
| 13b | **OpenSSH `scp.c` — mã nguồn tham chiếu** | https://github.com/openssh/openssh-portable/blob/master/scp.c | **Nguồn sự thật**: byte kết thúc nội dung file, thứ tự bắt tay `response()`/`atomicio()` |

> **Tài liệu quan trọng nhất cho phần SCP là `scp.c`.** Mô tả bằng lời (ví dụ
> #9) rất dễ bỏ sót chi tiết framing. Cụ thể, `scp.c` cho thấy:
>
> - Bên gửi ghi **một byte NUL sau nội dung file** để đánh dấu kết thúc dữ
>   liệu (`atomicio(vwrite, remout, "", 1)`), và bên nhận đọc byte đó rồi mới
>   xác nhận.
> - Byte "ready" luôn do **bên sink gửi**, và bên còn lại **đọc** nó.
>
> Chi tiết này đã dẫn đến ba lỗi giao thức nghiêm trọng được ghi lại ở
> mục 1.11–1.13 của `10-nhat-ky-thuat.md`.


---

## 3. SFTP

| # | Tài liệu | Liên kết | Dùng để |
| --- | --- | --- | --- |
| 14 | GolinuxCloud — *SFTP Chroot Jail* | https://www.golinuxcloud.com/sftp-chroot-restrict-user-specific-directory/ | Cấu trúc jail, yêu cầu quyền sở hữu, `Match` block |
| 15 | RFC 4253 — *SSH Transport Layer Protocol* | https://www.rfc-editor.org/rfc/rfc4253 | Định nghĩa kênh, mã hoá |
| 16 | draft-ietf-secsh-filexfer — SFTP | https://www.ietf.org/archive/id/draft-ietf-secsh-filexfer-02.txt | Định nghĩa giao thức SFTP |

---

## 4. Cấu hình SSH và chống brute force

| # | Tài liệu | Liên kết | Dùng để |
| --- | --- | --- | --- |
| 17 | tecmint — *How to Secure SSH on Ubuntu Servers with sshd_config, UFW, and Fail2Ban* | https://www.tecmint.com/ssh-hardening-tips-on-ubuntu-servers/ | Ví dụ drop-in `00-hardening.conf`, kiểm tra bằng `sshd -t` |
| 18 | HyperDC — *SSH hardening: lock down OpenSSH* | https://hyperdc.com/guides/security/ssh-hardening | Danh sách chỉ thị nên tắt |
| 19 | Vultr — *Hardening Server SSH Access* | https://docs.vultr.com/how-to-harden-server-ssh-access-using-advanced-openssh-features | `ChrootDirectory` trong `Match User` |
| 20 | jamieweb — *Restricting and Locking Down SSH Users* | https://www.jamieweb.net/blog/restricting-and-locking-down-ssh-users/ | Tùy chọn `restrict` và `command` trong `authorized_keys` |
| 21 | ssh.com — *Detailed Description of authorized_keys* | https://www.ssh.com/academy/ssh/authorized-keys-openssh | Ngữ nghĩa `command=`, `restrict` |

---

## 5. fail2ban

| # | Tài liệu | Liên kết | Dùng để |
| --- | --- | --- | --- |
| 22 | fail2ban — `jail.local` example | https://fail2ban.dev/config/jail-local/ | Cấu trúc `jail.local`, không sửa `jail.conf` |
| 23 | fail2ban — SSH guide | https://fail2ban.dev/guides/ssh/ | `mode = aggressive`, `backend = systemd` |
| 24 | fail2ban — bantime/findtime/maxretry | https://fail2ban.dev/config/bantime-findtime-maxretry/ | Ngữ nghĩa và giá trị mặc định |
| 25 | CommandInline — *Audit SSH Login Attempts with auditd and fail2ban* | https://www.commandinline.com/audit-ssh-login-attempts-linux-auditd-fail2ban/ | Định dạng `/etc/audit/rules.d/` |

---

## 6. Audit và firewall

| # | Tài liệu | Liên kết | Dùng để |
| --- | --- | --- | --- |
| 26 | Linux Box Admin — *Linux Server Hardening Checklist for 2026* | https://linuxboxadmin.com/articles/linux-server-hardening-checklist-2026 | Quy trình auditd, journald |
| 27 | Ubuntu Server — `auditd` | https://manpages.ubuntu.com/manpages/noble/man8/auditd.8.html | Cú pháp rule |

---

## 7. Thư viện Python

| # | Tài liệu | Liên kết | Dùng để |
| --- | --- | --- | --- |
| 28 | Paramiko — tài liệu chính thức | https://paramiko.readthedocs.io/ | `SSHClient`, `Transport`, `SFTPClient`, `Agent` |
| 29 | Paramiko — mã nguồn `pkey.py` | https://github.com/paramiko/paramiko/blob/master/paramiko/pkey.py | `from_type_string`, định dạng blob SSH |
| 30 | pytest — tài liệu | https://docs.pytest.org/ | Viết test |

---

## 8. Tài liệu hệ điều hành

| # | Tài liệu | Liên kết | Dùng để |
| --- | --- | --- | --- |
| 31 | Ubuntu Server — OpenSSH server | https://ubuntu.com/server/docs/how-to/security/openssh-server/ | Cấu hình chuẩn của Ubuntu |
| 32 | Ubuntu — `ufw` | https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html | Cú pháp `ufw limit` |
| 33 | VMware Workstation — tạo máy ảo | https://support.vmware.com/ | Cấu hình máy ảo |

---

## 9. Trích dẫn trực tiếp

### 9.1. Về thứ tự ưu tiên chỉ thị

> "Because OpenSSH uses the first value set for most directives, any settings
> defined in files within `sshd_config.d/` will override those in the main
> configuration file."
> — [Ubuntu Server: OpenSSH server](https://ubuntu.com/server/docs/how-to/security/openssh-server/)

### 9.2. Về `UsePrivilegeSeparation`

> "This release deprecates the sshd_config UsePrivilegeSeparation option,
> thereby making privilege separation mandatory."
> — [OpenSSH 7.5 release notes](https://www.openssh.org/txt/release-7.5)

### 9.3. Về `PerSourcePenalties`

> "OpenSSH 9.8 was released on 2024-07-01. [...] sshd(8): the server will now
> block client addresses that repeatedly fail authentication."
> — [OpenSSH 9.8 release notes](https://www.openssh.org/txt/release-9.8)

### 9.4. Về giao thức SCP

> "The scp in source mode (= data producer) always waits for a reply before
> the next protocol line is sent. After the last protocol message was sent,
> the producer sends a zero byte to notify scp in sink mode about beginning
> of the actual data transfer."
> — [Jan Pechanec, How the SCP protocol works](https://blogs.oracle.com/janp/entry/how_the_scp_protocol_works)

### 9.5. Về jail SFTP

> "The jail root must be root-owned and not group/world writable; create a
> user-owned writable subdirectory for uploads."
> — [GolinuxCloud, SFTP Chroot Jail](https://www.golinuxcloud.com/sftp-chroot-restrict-user-specific-directory/)

### 9.6. Về fail2ban

> "fail2ban bans an IP when it produces `maxretry` failures within `findtime`,
> and the ban lasts `bantime`."
> — [fail2ban: bantime, findtime, maxretry](https://fail2ban.dev/config/bantime-findtime-maxretry/)

---

## 10. Nguyên tắc trích dẫn

- Mọi khẳng định kỹ thuật về hành vi của OpenSSH đều dẫn nguồn từ tài
  liệu chính thức hoặc release notes.
- Khi không chắc chắn một chỉ thị có tồn tại ở phiên bản nào, dự án **loại
  bỏ** chỉ thị đó thay vì đoán — ưu tiên cấu hình chạy được trên mọi phiên
  bản Ubuntu mục tiêu.
- Thư viện bên thứ ba chỉ được dùng cho vận chuyển (Paramiko); phần giao
  thức được hiện thực hoá độc lập để kiểm chứng được sự hiểu biết.
