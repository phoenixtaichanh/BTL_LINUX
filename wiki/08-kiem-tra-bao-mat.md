# 08 - Kiểm tra và đối chiếu bảo mật

Tài liệu này mô tả cách kiểm chứng từng khía cạnh bảo mật của dự án, kèm
kết quả **chạy thật** trên máy ảo Ubuntu.

> **Môi trường kiểm thử**
>
> | Mục | Giá trị |
> | --- | --- |
> | Hypervisor | VMware Workstation 17 (NAT / VMnet8) |
> | Dải mạng | `192.168.118.0/24` |
> | Địa chỉ máy chủ | `192.168.118.128:22` |
> | Hệ điều hành | Ubuntu 26.04 LTS |
> | OpenSSH | 10.2 (hỗ trợ Ed25519, chacha20-poly1305) |
> | Tài khoản quản trị | `tuananh`, `btladmin` |
> | Tài khoản SFTP | `ftpsvc` (jail tại `/opt/sftp-jails/ftpsvc`) |
> | Máy trạm | Windows + Git Bash (MSYS) |

---

## 1. Kiểm tra tự động

### 1.1. Unit test

```bash
python -m pytest tests/ -v
```

Kết quả: **200 passed, 1 skipped** (test skip là test symlink trên hệ thống
không hỗ trợ).

### 1.2. Bộ test E2E

```bash
./scripts/test-e2e.sh 192.168.118.128 tuananh ~/.ssh/id_ed25519
```

Script gồm 8 nhóm kiểm tra:

| Nhóm | Nội dung | Số kiểm tra |
| --- | --- | --- |
| 1 | Kết nối và xác thực | 2 |
| 2 | Kiểm soát truy cập | 2 |
| 3 | Cấu hình hardening | 5 |
| 4 | Truyền SCP (hệ thống + codec của dự án) | 14 |
| 5 | Truyền SFTP | 4 |
| 6 | Jail SFTP | 5 |
| 7 | Phòng thủ nhiều lớp | 4 |
| 8 | Dọn dẹp | 0 |
| | **Tổng** | **38** |

Mã thoát = số kiểm tra thất bại.

Trên Windows, chạy bằng Git Bash:

```powershell
& "C:\Program Files\Git\bin\bash.exe" scripts/test-e2e.sh `
    192.168.118.128 tuananh "C:/Users/<bạn>/.ssh/id_ed25519"
```

---

## 2. Kết quả chạy thật

### 2.1. Bộ test E2E — 38/38 PASS

```
==============================================
 BTL end to end test
 target: 192.168.118.128   as: tuananh
==============================================

[1] Connectivity and authentication
  PASS  key based login works
  PASS  password authentication is refused

[2] Access control
  PASS  root login is refused
  PASS  an account outside sshusers is refused

[3] Configuration hardening
  PASS  sshd config passes validation
  PASS  password authentication is disabled in the effective config
  PASS  root login is disabled in the effective config
  PASS  TCP forwarding is disabled
  PASS  the hardening drop-in is present

[4] SCP transfers
  PASS  scp uploads a file
  PASS  the uploaded file has the right content
  PASS  scp downloads a file
  PASS  the downloaded file has the right content
  PASS  scp copies a directory recursively
  PASS  the recursive copy kept the nested file
  PASS  scp refuses a path traversal attempt
  PASS  no file escaped the intended directory
  PASS  the project SCP client uploads a file
  PASS  the file uploaded by the project SCP client is correct
  PASS  the project SCP client downloads a file
  PASS  the file downloaded by the project SCP client is correct
  PASS  the project SCP client copies a directory recursively
  PASS  the recursive copy by the project SCP client kept the nested file
  PASS  the system scp can read a file uploaded by the project client
  PASS  the file read by the system scp is correct

[5] SFTP transfers
  PASS  sftp uploads a file
  PASS  sftp downloads a file
  PASS  the SFTP download is correct
  PASS  sftp can list a directory

[6] SFTP jail (only when the account exists)
  PASS  the SFTP account cannot open a shell
  PASS  the SFTP account cannot reach /etc
  PASS  no file was written outside the jail
  PASS  the jail directory is owned by root
  PASS  the upload directory belongs to the account

[7] Defence in depth
  PASS  fail2ban is running
  PASS  the sshd jail is enabled
  PASS  the firewall is active
  PASS  auditd is running

[8] Cleanup

==============================================
 passed: 38   failed: 0
==============================================
```

Điểm đáng chú ý nhất ở nhóm 4: **codec SCP của dự án** được dùng để tải lên
rồi đọc lại bằng `/usr/bin/scp` thật của máy chủ (và ngược lại). Nếu wire
format của dự án lệch khỏi OpenSSH, các kiểm tra này sẽ đỏ — đây là bằng
chứng tương thích byte-for-byte, không phải kiểm tra "client đọc được file
của chính nó".

### 2.2. Kiểm định cấu hình — 18/18 compliant

```bash
btl audit 192.168.118.128 --user tuananh --identity ~/.ssh/id_ed25519 \
                        --sudo-password '<mật khẩu sudo>'
```

```
Checked 18 directives: 18 compliant, 0 weak, 0 missing.
```

### 2.3. Cấu hình sshd hiệu lực (`sshd -T`)

```
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
permitemptypasswords no
maxauthtries 3
maxsessions 10
logingracetime 30
x11forwarding no
allowtcpforwarding no
allowagentforwarding no
permittunnel no
gatewayports no
usedns no
allowgroups sshusers
loglevel VERBOSE
```

Đối chiếu từng chỉ thị với mục tiêu đề tài:

| Chỉ thị | Giá trị | Yêu cầu | Kết quả |
| --- | --- | --- | --- |
| `permitrootlogin` | `no` | A3 | Đạt |
| `passwordauthentication` | `no` | A2 | Đạt |
| `kbdinteractiveauthentication` | `no` | A2 | Đạt |
| `pubkeyauthentication` | `yes` | A2 | Đạt |
| `permitemptypasswords` | `no` | A2 | Đạt |
| `maxauthtries` | `3` | A5 | Đạt |
| `logingracetime` | `30` | A5 | Đạt |
| `x11forwarding` | `no` | A10 | Đạt |
| `allowtcpforwarding` | `no` | A10 | Đạt |
| `allowagentforwarding` | `no` | A10 | Đạt |
| `permittunnel` | `no` | A10 | Đạt |
| `gatewayports` | `no` | A10 | Đạt |
| `allowgroups` | `sshusers` | A4 | Đạt |

### 2.4. Drop-in cấu hình được cài đặt

```
$ ls -l /etc/ssh/sshd_config.d/
-rw-r--r-- 1 root root 2008 Nov  9 00:19 00-btl-hardening.conf
-rw-r--r-- 1 root root  381 Nov  9 00:19 10-btl-sftp.conf
```

Cấu hình hardening sinh ra (rút gọn) — xác nhận mọi nhóm yêu cầu đều có mặt:

```sshd
PermitRootLogin no
PermitEmptyPasswords no
UsePAM yes
AllowGroups sshusers

PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
PermitUserEnvironment no

MaxAuthTries 3
LoginGraceTime 30
MaxSessions 10
MaxStartups 10:30:60

X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
StreamLocalBindMask 0077

ClientAliveInterval 300
ClientAliveCountMax 2
Banner /etc/ssh/banner.txt

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,...
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,...
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,...
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,...,rsa-sha2-256
```

Khối jail SFTP:

```sshd
Match User ftpsvc
    ChrootDirectory /opt/sftp-jails/ftpsvc
    ForceCommand internal-sftp -d /upload
    AllowTcpForwarding no
    X11Forwarding no
    PermitTTY no
    GatewayPorts no

Match all
```

> `ChallengeResponseAuthentication no` vẫn được ghi vào file (đúng tên như
> `sshd_config(5)` chấp nhận), nhưng auditor phải tra tên chuẩn
> `kbdinteractiveauthentication` khi đọc output của `sshd -T` — xem mục 6.

### 2.5. Kiểm soát truy cập

| Kiểm tra | Lệnh | Kết quả |
| --- | --- | --- |
| Đăng nhập bằng key | `ssh -i key tuananh@host` | Thành công |
| Đăng nhập bằng mật khẩu | `ssh -o PubkeyAuthentication=no ...` | `Permission denied (publickey)` |
| Root | `ssh root@host` | Bị từ chối |
| User ngoài `sshusers` | `ssh outsider@host` | Bị từ chối |
| Tài khoản không tồn tại | `ssh ghost@host` | Bị từ chối |

Nhóm `sshusers` trên máy chủ:

```
$ getent group sshusers
sshusers:x:1001:tuananh,btladmin,ftpsvc
```

Cả ba tài khoản đều thuộc nhóm: tài khoản vận hành (`tuananh`, dùng để chạy
provisioning), tài khoản quản trị (`btladmin`) và tài khoản SFTP (`ftpsvc`).

### 2.5.1. Idempotence của provisioning (yêu cầu D7)

Chạy `btl provision` **hai lần liên tiếp** với cùng tham số, rồi đếm số khoá
trong `authorized_keys` của mỗi tài khoản:

```bash
btl provision --host 192.168.118.128 --user tuananh \
              --identity ~/.ssh/id_ed25519 --sudo-password '<pwd>' \
              --admin-users btladmin --sftp-users ftpsvc \
              --admin-public-key ~/.ssh/id_ed25519.pub \
              --sftp-public-key ~/.ssh/id_ed25519_sftp.pub \
              --fail2ban-ignore 192.168.118.0/24
# ... lặp lại y hệt ...

for u in tuananh btladmin ftpsvc; do
  echo "--- $u"
  sudo cat /home/$u/.ssh/authorized_keys | ssh-keygen -lf -
done
```

Kết quả thực tế:

```
--- tuananh
256 SHA256:m4kW22M0szqUaPVwwxkPtrD7SMSxKJ9xq4QomrQIulU btl-admin@BTL-workstation (ED25519)
--- btladmin
256 SHA256:m4kW22M0szqUaPVwwxkPtrD7SMSxKJ9xq4QomrQIulU btl-admin@BTL-workstation (ED25519)
--- ftpsvc
256 SHA256:3I4aWuKxcQkR+FOCZINgqTaZJGywg5+dVN/DsxjHjZY btl-sftp@BTL-workstation (ED25519)
```

Mỗi tài khoản giữ **đúng một** khoá công khai, khớp với khoá sinh ở máy
trạm:

```
$ ssh-keygen -lf ~/.ssh/id_ed25519.pub
256 SHA256:m4kW22M0szqUaPVwwxkPtrD7SMSxKJ9xq4QomrQIulU btl-admin@BTL-workstation (ED25519)
$ ssh-keygen -lf ~/.ssh/id_ed25519_sftp.pub
256 SHA256:3I4aWuKxcQkR+FOCZINgqTaZJGywg5+dVN/DsxjHjZY btl-sftp@BTL-workstation (ED25519)
```

> Trước khi sửa, `authorized_keys` dùng `printf ... >>` nên bị **nhân bản** mỗi
> lần provision (5 bản sao sau 5 lần chạy). Script provisioning nay **hợp
> nhất** khoá cũ với khoá mới bằng `sort -u`, nên kết quả quan sát được là
> không đổi. Xem mục 1.29 của nhật ký kỹ thuật.

### 2.6. Tường lửa

```
$ sudo ufw status verbose
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
```

Chỉ cổng SSH mở; mọi cổng khác bị chặn bởi chính sách `deny incoming`.

> **Vì sao là `ALLOW` chứ không phải `LIMIT`:** `ufw limit 22/tcp` từ chối
> hơn 6 kết nối mới trong 30 giây từ cùng một địa chỉ. Bộ test E2E mở hơn
> 20 phiên liên tiếp nên bị chặn giữa chừng (dấu vết kernel:
> `[UFW LIMIT BLOCK] ... SRC=192.168.118.1 DPT=22`). Chống brute force đã do
> fail2ban và `MaxAuthTries`/`MaxStartups` đảm nhiệm. Cờ `--ufw-limit-ssh`
> cho phép bật `LIMIT` khi server thật sự lộ ra Internet.

### 2.7. fail2ban

```
$ sudo fail2ban-client status sshd
Status for the jail: sshd
|- Filter
|  |- Currently failed:   0
|  |- Total failed:       0
|  `- Journal matches:    _SYSTEMD_UNIT=ssh.service + _COMM=sshd
`- Actions
   |- Currently banned:   0
   |- Total banned:       0
   `- Banned IP list:
```

Cấu hình jail (`/etc/fail2ban/jail.d/btl-sshd.local`):

```
mode     = aggressive
maxretry = 3
findtime = 10m
bantime  = 1h
ignoreip = 127.0.0.1/8 ::1 192.168.118.0/24
bantime.increment = true
bantime.factor    = 1
bantime.maxtime   = 1w
```

| Kiểm tra | Mong đợi | Thực tế |
| --- | --- | --- |
| Jail `sshd` hoạt động | Có | Đạt |
| `maxretry` | `3` | Đạt |
| `bantime` | `1h` | Đạt |
| `findtime` | `10m` | Đạt |
| `ignoreip` chứa dải quản trị | Có | Đạt (`192.168.118.0/24`) |
| `mode` | `aggressive` | Đạt |
| Tăng thời gian ban lặp lại | `bantime.increment` | Đạt |

> `ignoreip` phải chứa dải quản trị vì jail ở chế độ `aggressive` tính cả
> những lần đăng nhập thất bại **có chủ đích** mà bộ kiểm tra dùng để xác
> minh `AllowGroups`. Thiếu khai báo này thì chính máy trạm quản trị bị ban.

### 2.8. auditd

Các rule đang hoạt động:

```
$ sudo auditctl -l
-w /etc/ssh/sshd_config -p wa -k btl_sshd_config
-w /etc/sudoers -p wa -k btl_sudoers
-w /etc/sudoers.d -p wa -k btl_sudoers
-w /etc/passwd -p wa -k btl_identity
-w /etc/group -p wa -k btl_identity
-w /etc/shadow -p wa -k btl_identity
-w /opt/sftp-jails -p wa -k btl_sftp_jail
-a always,exit -F arch=b64 -S execve -F euid=0 -F key=btl_root_commands
-w /usr/sbin/sshd -p x -k btl_sshd_exec
```

| Key | Phạm vi theo dõi | Yêu cầu |
| --- | --- | --- |
| `btl_sshd_config` | Mọi thay đổi `sshd_config` | A8 |
| `btl_sudoers` | Mọi thay đổi trong `sudoers` | A8 |
| `btl_identity` | Thay đổi passwd/group/shadow | A8 |
| `btl_sftp_jail` | Thay đổi trong thư mục jail | A8 |
| `btl_root_commands` | Lệnh thực thi với euid=0 | A8 |
| `btl_sshd_exec` | Thực thi `sshd` | A8 |

Truy vấn:

```bash
sudo ausearch -k btl_sshd_config --interpret
sudo ausearch -k btl_identity --interpret
sudo ausearch -k btl_root_commands --interpret
```

### 2.9. Jail SFTP

```
$ sudo ls -ld /opt/sftp-jails/ftpsvc /opt/sftp-jails/ftpsvc/upload
drwxr-xr-x 3 root   root   4096 Nov  8 23:47 /opt/sftp-jails/ftpsvc
drwx------ 2 ftpsvc ftpsvc 4096 Nov  8 23:47 /opt/sftp-jails/ftpsvc/upload
```

| Kiểm tra | Mong đợi | Thực tế |
| --- | --- | --- |
| Thư mục jail thuộc `root` | Có | Đạt |
| Thư mục `upload` thuộc account, `700` | Có | Đạt |
| Account mở shell | Bị từ chối | Đạt (`This service allows sftp connections only.`) |
| Account nhìn thấy `/etc` | Không | Đạt |
| Ghi ra ngoài jail | Bị từ chối | Đạt |

### 2.10. Mã hoá và host key

```
$ sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
256 SHA256:8Em1Xmao521FRHSd9+gA6n8XcWkO1M8pk4JaEIh8DPw root@tuananh-VMware-Virtual-Platform (ED25519)
```

| Kiểm tra | Mong đợi | Thực tế |
| --- | --- | --- |
| Cipher | `chacha20-poly1305@openssh.com` | Đạt |
| MAC | `hmac-sha2-512-etm@openssh.com` | Đạt |
| KEX | `curve25519-sha256` | Đạt |
| Host key | `ssh-ed25519` | Đạt |
| Fingerprint khớp kho tin cậy | Có | Đạt |

### 2.11. Chống path traversal

| Kiểm tra | Kết quả |
| --- | --- |
| `scp` từ chối đường dẫn `../../etc/...` | Đạt |
| Không file nào thoát ra khỏi thư mục đích | Đạt |
| `sanitize_filename` loại bỏ `..` | Đạt (unit test) |
| `validate_relative_name` từ chối đường dẫn tương đối nguy hiểm | Đạt (unit test) |

---

## 3. Checklist đối chiếu thủ công

### 3.1. Xác thực

| # | Kiểm tra | Lệnh | Kết quả mong đợi |
| --- | --- | --- | --- |
| 1 | Đăng nhập bằng key | `ssh -i key user@host` | Thành công |
| 2 | Đăng nhập bằng mật khẩu | `ssh -o PubkeyAuthentication=no user@host` | Bị từ chối |
| 3 | Root đăng nhập | `ssh root@host` | Bị từ chối |
| 4 | User ngoài `sshusers` | `ssh outsider@host` | Bị từ chối |
| 5 | Tài khoản không tồn tại | `ssh ghost@host` | Bị từ chối |

### 3.2. Cấu hình sshd

```bash
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|maxauthtries|logingracetime|x11forwarding|allowtcpforwarding|allowagentforwarding|permittunnel|gatewayports|permitemptypasswords)'
```

Kiểm tra tự động: `sudo btl audit`

### 3.3. Chống path traversal

```bash
# Tạo file thử
echo "test" > /tmp/evil.txt

# Thử ghi ra ngoài
scp -i key /tmp/evil.txt user@host:/tmp/../../../../etc/evil.txt
# → phải thất bại
scp -i key /tmp/evil.txt user@host:/etc/evil.txt
# → phải thất bại hoặc ghi vào trong thư mục jail

# Kiểm tra không có file nào thoát ra
sudo ls -la /etc/evil.txt   # → không tồn tại
```

### 3.4. Jail SFTP

```bash
# Không mở được shell
ssh -i key_sftp ftpsvc@host
# → "This service allows sftp connections only."

# Không thấy /etc
sftp -i key_sftp ftpsvc@host
> ls /etc
# → lỗi hoặc rỗng

# Ghi được vào /upload
sftp -i key_sftp ftpsvc@host
> put /tmp/test.txt /upload/
> ls /upload
```

### 3.5. fail2ban

```bash
# Cố đăng nhập sai 4 lần từ một IP khác
for i in 1 2 3 4; do
    ssh -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 \
        -o ConnectTimeout=5 baduser@192.168.118.128 "true"
done

# Kiểm tra IP đã bị ban
sudo fail2ban-client status sshd
```

### 3.6. Tường lửa

```bash
sudo ufw status verbose

# Từ máy khác
nc -zv 192.168.118.128 80    # → bị từ chối
```

### 3.7. Quản lý khoá host

```bash
# Từ chối khoá lạ
btl ssh 192.168.118.128 --user tuananh -i ~/.ssh/id_ed25519 "true"
# → HostKeyError nếu khoá chưa được tin cậy

# Phát hiện khoá bị thay đổi
btl hostkey list
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
# → fingerprint phải khớp
```

---

## 4. Ma trận truy vết yêu cầu

| Yêu cầu đề tài | Nơi thực hiện | Cách kiểm chứng | Kết quả |
| --- | --- | --- | --- |
| A1 Drop-in sshd_config | `security/sshd_config.py` | `ls /etc/ssh/sshd_config.d/00-*` | Đạt |
| A2 Chỉ khóa công khai | `SSHDPolicy.to_config` | `sshd -T \| grep passwordauth` | Đạt |
| A3 Cấm root | `SSHDPolicy` | `sshd -T \| grep permitrootlogin` | Đạt |
| A4 Giới hạn nhóm | `AllowGroups` | `ssh outsider@host` | Đạt |
| A5 Chống brute force | `MaxAuthTries` | `sshd -T \| grep maxauthtries` | Đạt |
| A6 fail2ban | `security/defense.py` | `fail2ban-client status sshd` | Đạt |
| A7 ufw | `FirewallPolicy` | `ufw status verbose` | Đạt |
| A8 auditd | `AuditPolicy` | `auditctl -l` | Đạt |
| A9 Banner | `BANNER_TEXT` | `cat /etc/ssh/banner.txt` | Đạt |
| A10 Tắt forwarding | `SSHDPolicy` | `sshd -T \| grep allowtcpforwarding` | Đạt |
| A11 Mã hoá mạnh | `SSHDPolicy.ciphers` | `ssh -v` | Đạt |
| A12 Kiểm định | `btl audit` | `btl audit` | 18/18 |
| B2 Codec SCP | `scp/protocol.py` | `pytest tests/test_scp_protocol.py` | Đạt |
| B3/B4 Put/Get | `scp/client.py` | `scp` E2E nhóm 4 | Đạt |
| B5 Đệ quy | `ScpSink`/`ScpSource` | `scp -r` | Đạt |
| B6 Giữ quyền/thời gian | `T` message | `ls -l` sau khi truyền | Đạt |
| B7 Chống traversal | `validate_relative_name` | `pytest tests/test_paths.py` | Đạt |
| B8 Chống symlink | `SafePath.resolve` | test symlink escape | Đạt |
| C2 Ràng buộc đường dẫn | `SFTPClient(root=)` | `btl sftp --root` | Đạt |
| C4 Resume | `SFTPClient.get/put` | ngắt giữa chừng rồi `--resume` | Đạt |
| C7 Chroot jail | `sftp/server.py` | `ls -ld /opt/sftp-jails/*` | Đạt |
| C8 Cấm shell | `Match User` block | `ssh ftpsvc@host` | Đạt |
| D2 known_hosts | `ssh/hostkeys.py` | `btl hostkey list` | Đạt |
| D3 Phát hiện key đổi | `HostKeyStatus.CHANGED` | đổi key trên VM rồi thử kết nối | Đạt |
| D4 Từ chối key lạ | `auto_accept=False` | xoá khỏi kho rồi thử kết nối | Đạt |
| D6 Provision | `btl provision` | `--dry-run` rồi thực thi | Đạt |
| D7 Idempotent | `provisioner.py` | chạy 2 lần, so kết quả | Đạt — mỗi tài khoản giữ **đúng 1** khoá sau 2 lần chạy |
| E1–E3 Test | `tests/` | `pytest` | 200 pass |

---

## 5. Công cụ kiểm tra bổ sung

| Công cụ | Lệnh | Dùng để |
| --- | --- | --- |
| `ssh-audit` | `ssh-audit -p 22 192.168.118.128` | Đánh giá cấu hình SSH từ bên ngoài |
| `nmap` | `nmap -sV -p 22 192.168.118.128` | Quét cổng để xác nhận chỉ SSH mở |
| `lynis` | `sudo lynis audit system` | Đánh giá bảo mật tổng thể |
| `shellcheck` | `shellcheck scripts/*.sh` | Kiểm tra script bash |

> `ssh-audit` là công cụ đáng dùng nhất để đối chiếu độc lập với kết quả
> `btl audit`.

---

## 6. Ghi nhận phát hiện

| Ngày | Phát hiện | Mức độ | Xử lý |
| --- | --- | --- | --- |
| 2026-11-08 | `LoginFailedAttempts` không tồn tại trong OpenSSH | Cao | Gỡ khỏi baseline, thêm test chặn tái phát |
| 2026-11-08 | `UsePrivilegeSeparation` deprecated, có thể làm sshd không khởi động | Cao | Gỡ khỏi cấu hình sinh ra |
| 2026-11-08 | `PerSourcePenalties` chỉ có từ OpenSSH 9.8 | Trung bình | Không dùng; `MaxAuthTries` + fail2ban đảm nhiệm |
| 2026-11-08 | `sanitize_filename` không loại `..` | Cao | Sửa + thêm test |
| 2026-11-08 | `SafePath` trộn quy ước POSIX và native | Trung bình | Tách hàm chuyển đổi |
| 2026-11-08 | `ChallengeResponseAuthentication` là alias đã lỗi thời, OpenSSH 10.2 không in trong `sshd -T` | Trung bình | Thêm bảng `ALIASES`, auditor tra tên chuẩn |
| 2026-11-08 | `ufw limit 22/tcp` chặn loạt phiên quản trị (`[UFW LIMIT BLOCK]`) | Cao | Mặc định đổi sang `ufw allow`, thêm cờ `--ufw-limit-ssh` |
| 2026-11-08 | fail2ban chế độ `aggressive` ban IP của chính máy trạm quản trị | Cao | Thêm `--fail2ban-ignore`, khai báo `192.168.118.0/24` |
| 2026-11-08 | `AllowGroups sshusers` khoá cả tài khoản provisioning và tài khoản SFTP | Cao | Thêm tài khoản vào nhóm trước khi reload sshd |
| 2026-11-08 | Drop-in config ghi vào `/tmp` nhưng không được chuyển vào chỗ | Cao | `install -m 644 /tmp/btl_upload <đích>` |
| 2026-11-08 | `sudo -S` không nhận được mật khẩu vì stdin không được gửi | Cao | Thêm `stdin_data` cho `exec_command()` |
| 2026-11-08 | `authorized_keys` bị nhân bản mỗi lần provision (`>>` vô điều kiện) | Cao | Hợp nhất bằng `sort -u`; kiểm chứng chạy 2 lần vẫn giữ 1 khoá |
| 2026-11-08 | Lệnh `awk` escape sai làm rỗng `authorized_keys` → mất đăng nhập | Cao | Khôi phục qua `vmrun`; dùng file tạm + `mv` thay vì ghi thẳng |
| 2026-11-09 | `ssh-keyscan` dùng định dạng `known_hosts`, `hostkey add` không đọc được | Cao | `load_public_key()` nhận cả hai định dạng |
| 2026-11-09 | `btl ssh` sập khi server trả về tiếng Việt (console Windows dùng code page cũ) | Trung bình | `_write_output()` thay ký tự không mã hoá được |
| 2026-11-09 | Paramiko 5 bỏ accessor `cipher()`/`mac()`/`compression` → `--info` crash | Cao | `_negotiated_value()` hỗ trợ cả API mới và cũ |

---

## 7. Tóm tắt

| Hạng mục | Kết quả |
| --- | --- |
| Unit test | 200 passed, 1 skipped |
| E2E tích hợp | **38/38 PASS** |
| Kiểm định cấu hình | **18/18 compliant** |
| Lớp phòng thủ | 5/5 hoạt động (sshd hardening, ufw, fail2ban, auditd, chroot jail) |
| Tương thích OpenSSH | SCP và SFTP hoạt động hai chiều giữa codec của dự án và `/usr/bin/scp`, `/usr/bin/sftp` thật |
| Lỗ hổng phát hiện được | 0 trong phạm vi kiểm tra |
