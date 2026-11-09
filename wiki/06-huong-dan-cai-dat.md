# 06 - Hướng dẫn cài đặt trên VMware / Ubuntu

## 1. Yêu cầu phần cứng

| Thành phần | Tối thiểu | Khuyến nghị |
| --- | --- | --- |
| RAM cho VM | 1 GB | 2 GB |
| Ổ đĩa | 20 GB | 30 GB |
| vCPU | 1 | 2 |
| Mạng | NAT | Host-only (khuyến nghị) |

## 2. Tạo máy ảo Ubuntu

### 2.1. Tải ISO

Ubuntu Server 22.04.5 LTS:
```
https://releases.ubuntu.com/22.04/ubuntu-22.04.5-live-server-amd64.iso
```
Ubuntu Server 24.04 LTS:
```
https://releases.ubuntu.com/24.04/ubuntu-24.04.x-live-server-amd64.iso
```

### 2.2. Cấu hình VMware

| Tuỳ chọn | Khuyến nghị | Lý do |
| --- | --- | --- |
| Guest OS | Ubuntu 64-bit | |
| RAM | 2048 MB | |
| CPU | 2 vCPU | |
| Disk | 30 GB, không phân bổ ngay | Dễ clone/snapshot |
| Network | **NAT** | Dải `192.168.118.0/24` trên VMnet8 — dùng cho báo cáo này |
| Firmware | UEFI | |

> **Lưu ý về dải mạng:** VMware **không** dùng dải `192.168.122.0/24` cho
> mọi cài đặt. Dải đó chỉ là giá trị mặc định của một số bản phân phối.
> Dải thật phải được đọc từ chính máy trạm:
>
> ```powershell
> Get-NetIPAddress -AddressFamily IPv4 |
>     Where-Object { $_.InterfaceAlias -like 'VMware*' }
> ```
>
> Kết quả thực tế của máy đang dùng trong báo cáo này:
>
> | Adapter | Địa chỉ | Dải | Vai trò |
> | --- | --- | --- | --- |
> | VMware Network Adapter VMnet8 | `192.168.118.1/24` | `192.168.118.0/24` | NAT — VM dùng dải này |
> | VMware Network Adapter VMnet1 | `192.168.140.1/24` | `192.168.140.0/24` | Host-only |
>
> Máy ảo trong báo cáo dùng chế độ **NAT**, nên nó nằm trong
> `192.168.118.0/24` và được cấp địa chỉ `192.168.118.128`.

### 2.3. Cài Ubuntu

Trong trình cài đặt:

1. **Hostname:** `btl-server`
2. **Username:** `ubuntu` (tài khoản quản trị ban đầu)
3. **Authentication:** chọn "Use SSH keys" → dán public key Ed25519 đã sinh
   ở máy trạm
4. **Optional software:** chỉ chọn **OpenSSH Server**
5. **Ubuntu Pro:** bỏ qua

> **Quan trọng:** bản ISO của Ubuntu Server **không** cài `openssh-server`
> sẵn. Nếu bỏ chọn ở bước 4 thì phải cài thủ công từ console:
>
> ```bash
> sudo apt-get update
> sudo apt-get install -y openssh-server
> sudo systemctl enable --now ssh
> ```

### 2.4. Xác định địa chỉ IP

```bash
ip -4 addr show | grep inet
# hoặc
hostname -I
```

Ghi lại địa chỉ, ví dụ `192.168.122.128`.

### 2.5. Tạo snapshot

```
VM → Snapshot → Take Snapshot → "after-install"
```

Làm vậy để có thể quay lại nếu cấu hình sai.

## 3. Cài đặt máy trạm

### 3.1. Windows

```powershell
cd d:\BTL_Linux
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### 3.2. Linux / macOS

```bash
cd ~/BTL_Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Kiểm tra:
```bash
btl --version
btl --help
```

## 4. Chuẩn bị khóa

```bash
# Trên máy trạm
./scripts/generate-keys.sh

# hoặc thủ công
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/id_ed25519 -C "btl-admin"
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/id_ed25519_sftp -C "btl-sftp"
```

## 5. Tin cậy host key của máy chủ

> **Quan trọng:** Làm bước này **trước** khi hardening, và xác minh
> fingerprint qua kênh đáng tin cậy (màn hình console của VM).

### 5.1. Lấy fingerprint từ console VM

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
# 256 SHA256:XXXX... root@btl-server (ED25519)
```

### 5.2. Thêm vào kho tin cậy

Cách 1 — từ máy trạm, đọc file public key trên server:

```bash
ssh tuananh@192.168.118.128 "cat /etc/ssh/ssh_host_ed25519_key.pub" > /tmp/hostkey.pub
btl hostkey add 192.168.118.128 --key-file /tmp/hostkey.pub
```

Cách 2 — dùng `ssh-keyscan` rồi xác minh fingerprint khớp:

```bash
ssh-keyscan -t ed25519 192.168.118.128 > /tmp/hostkey.pub
ssh-keygen -lf /tmp/hostkey.pub    # so với fingerprint trên console
btl hostkey add 192.168.118.128 --key-file /tmp/hostkey.pub
```

Kiểm tra:
```bash
btl hostkey list
```

## 6. Provisioning máy chủ

### 6.1. Xem trước (không thay đổi gì)

```bash
btl provision --host 192.168.118.128 --user tuananh \
              --identity ~/.ssh/id_ed25519 \
              --admin-users btladmin \
              --sftp-users ftpsvc \
              --admin-public-key ~/.ssh/id_ed25519.pub \
              --sftp-public-key ~/.ssh/id_ed25519_sftp.pub \
              --fail2ban-ignore 192.168.118.0/24 \
              --port 22 \
              --dry-run
```

Đọc kỹ output — nó hiển thị đúng những gì sẽ được ghi.

### 6.2. Thực thi

```bash
btl provision --host 192.168.118.128 --user tuananh \
              --identity ~/.ssh/id_ed25519 \
              --sudo-password '<mật khẩu sudo>' \
              --admin-users btladmin \
              --sftp-users ftpsvc \
              --admin-public-key ~/.ssh/id_ed25519.pub \
              --sftp-public-key ~/.ssh/id_ed25519_sftp.pub \
              --fail2ban-ignore 192.168.118.0/24
```

> Ghi chú: cờ là `--sftp-users` (số nhiều).

### 6.3. Vì sao phải truyền `--admin-public-key`

Lệnh provisioning **khoá mật khẩu** của tài khoản quản trị (`passwd -l`)
và đặt `PasswordAuthentication no` trong cấu hình sshd. Nếu không cài
`authorized_keys` cho tài khoản đó thì tài khoản **không bao giờ đăng nhập
được** — bạn sẽ khoá chính mình ra khỏi máy chủ.

Vì vậy `--admin-public-key` và `--sftp-public-key` là bắt buộc trong quy
trình thật. Tài khoản dùng để chạy provisioning (`--user`) cũng được tự
động thêm vào nhóm `sshusers` và nhận cùng khoá công khai, để không bị
`AllowGroups` chặn.

### 6.4. Tuỳ chọn của lệnh provision

| Cờ | Tác dụng |
| --- | --- |
| `--dry-run` | Chỉ in ra script sẽ chạy, không thay đổi gì |
| `--admin-public-key <file>` | Khoá công khai cài cho tài khoản quản trị |
| `--sftp-public-key <file>` | Khoá công khai cài cho tài khoản SFTP |
| `--fail2ban-ignore <danh sách>` | Địa chỉ/dải IP **không bao giờ** bị fail2ban ban |
| `--ufw-limit-ssh` | Dùng `ufw limit` thay vì `ufw allow` cho cổng SSH |
| `--no-firewall` | Không cấu hình ufw (khi firewall có thể chặn bạn ra) |
| `--sudo-password <pwd>` | Mật khẩu để `sudo -S` (mặc định lấy từ `--password`) |

> **Về `--fail2ban-ignore`:** jail của fail2ban chạy ở chế độ `aggressive`,
> nên nó tính cả những lần đăng nhập thất bại có chủ đích. Bộ kiểm thử E2E
> cố tình thử `root@host` và `nobody@host` để kiểm tra `AllowGroups`, và
> không có tuỳ chọn này thì chính máy trạm quản trị sẽ bị ban IP.
>
> **Về `ufw limit`:** `ufw limit 22/tcp` từ chối hơn 6 kết nối mới trong
> 30 giây từ cùng một địa chỉ. Đây là quy tắc đúng cho server lộ ra
> Internet, nhưng nó chặn cả một loạt phiên quản trị hợp lệ, nên mặc định
> của dự án là `ufw allow`. Việc chống brute force đã do fail2ban và
> `MaxAuthTries`/`MaxStartups` của sshd đảm nhiệm.

### 6.5. Kiểm tra

```bash
ssh -i ~/.ssh/id_ed25519 btladmin@192.168.118.128 'echo OK'
btl audit 192.168.118.128 --user btladmin --identity ~/.ssh/id_ed25519
```

Kết quả `btl audit` trên máy chủ đã cấu hình:

```
Checked 18 directives: 18 compliant, 0 weak, 0 missing.
```

## 7. Cấu hình tài khoản SFTP

Tài khoản SFTP và jail của nó được tạo tự động bởi `btl provision` khi có
cờ `--sftp-users` và `--sftp-public-key`. Không cần làm thủ công.

Kiểm tra:

```bash
ssh -i ~/.ssh/id_ed25519_sftp ftpsvc@192.168.118.128
```

Phải vào được thư mục `/upload` và **không** thấy `/etc`.

## 8. Kiểm tra kết quả

### 8.1. Chạy bộ test E2E

Script phải chạy từ **thư mục gốc dự án** (để `python -m btl.cli` tìm được
mã nguồn):

```bash
./scripts/test-e2e.sh 192.168.118.128 tuananh ~/.ssh/id_ed25519
```

Bộ test gồm các nhóm kiểm tra:

| Nhóm | Nội dung |
| --- | --- |
| 1 | Kết nối bằng khóa công khai; mật khẩu bị từ chối |
| 2 | Root bị từ chối; tài khoản ngoài `sshusers` bị từ chối |
| 3 | Cấu hình hardening có hiệu lực (`sshd -T`) |
| 4 | SCP hai chiều bằng `scp` hệ thống **và** bằng codec của dự án |
| 5 | SFTP hai chiều bằng `sftp` hệ thống |
| 6 | Jail SFTP: không có shell, không thấy `/etc` |
| 7 | fail2ban, ufw, auditd đang hoạt động |

Nhóm 4 đáng chú ý nhất: nó chạy **codec SCP của dự án** đối với `/usr/bin/scp`
thật của máy chủ, ở cả hai chiều. Đây là bài kiểm tra tương thích
byte-for-byte — nếu wire format của dự án lệch khỏi OpenSSH, nhóm này sẽ đỏ.

Nếu chạy script từ máy trạm khác Ubuntu, đặt biến môi trường `KNOWN_HOSTS`
nếu file `known_hosts` không ở vị trí mặc định:

```bash
KNOWN_HOSTS=~/.ssh/known_hosts ./scripts/test-e2e.sh 192.168.118.128 tuananh
```

> **Trên Windows:** dùng Git Bash để chạy script. Script đã tự xử lý khác
> biệt đường dẫn giữa MSYS và Windows:
>
> ```powershell
> & "C:\Program Files\Git\bin\bash.exe" scripts/test-e2e.sh `
>     192.168.118.128 tuananh "C:/Users/<bạn>/.ssh/id_ed25519"
> ```
>
> Ba điều kiện trên Windows:
>
> 1. Tài khoản dùng để chạy test cần quyền `sudo` không mật khẩu, vì
>    script dùng `sudo -n`. Nếu không, hãy thêm vào server:
>    ```bash
>    echo 'tuananh ALL=(ALL:ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/90-btl
>    sudo visudo -cf /etc/sudoers.d/90-btl
>    ```
> 2. Server phải **không** dùng `ufw limit` cho cổng SSH, nếu không bộ
>    test sẽ bị firewall chặn giữa chừng.
> 3. `fail2ban` phải loại trừ dải quản trị (`--fail2ban-ignore`).

Kết quả chạy thật trên Ubuntu 26.04:

```
==============================================
 passed: 38   failed: 0
==============================================
```

### 8.2. Kiểm định cấu hình

```bash
# Chạy trên server
btl audit

# Hoặc qua SSH, từ máy trạm
btl audit 192.168.118.128 --user tuananh --identity ~/.ssh/id_ed25519 \
                        --sudo-password '<mật khẩu sudo>'
```

Kết quả mong đợi:
```
Checked 18 directives: 18 compliant, 0 weak, 0 missing.
```

### 8.3. Kiểm tra thủ công

```bash
# Cấu hình hiệu lực
sudo sshd -T | grep -E '^(passwordauthentication|permitrootlogin|allowtcpforwarding|maxauthtries)'

# fail2ban
sudo fail2ban-client status sshd

# tường lửa
sudo ufw status verbose

# audit rules
sudo ausearch -k btl_sshd_config --interpret | tail -20

# jail SFTP
ls -ld /opt/sftp-jails/ftpsvc /opt/sftp-jails/ftpsvc/upload
```

## 9. Xử lý sự cố

| Hiện tượng | Nguyên nhân | Xử lý |
| --- | --- | --- |
| `Permission denied (publickey)` | Chưa copy key cho user | `ssh-copy-id` lại |
| `Host key verification failed` | Key đổi hoặc chưa tin cậy | Xem mục 11 |
| `Too many authentication failures` | Nhiều key trong agent | `ssh -o IdentitiesOnly=yes -i <key>` |
| `channel open failed` sau khi harden | `AllowGroups` sai | Sửa qua console VM |
| `sudo: a password is required` | User chưa có quyền sudo | Thêm vào `sudo` group |
| File SFTP không ghi được | Quyền thư mục upload sai | `chown user:user` + `chmod 700` |
| `Connection timed out` giữa chừng khi chạy E2E | Server dùng `ufw limit 22/tcp` | Bỏ cờ `--ufw-limit-ssh`, hoặc `sudo ufw allow 22/tcp` |
| Tự nhiên mất kết nối ngay sau provision | Tài khoản không thuộc `sshusers` | `sudo usermod -aG sshusers <user>` rồi `sudo systemctl reload ssh` |
| `unknown host key for ...` | Chưa tin cậy host key | `btl hostkey add <host> --key-file <file>` |
| `could not connect ... timed out` ngay sau provision | Firewall chặn cổng SSH | `sudo ufw allow 22/tcp` qua console |
| Bị fail2ban ban | Bộ test thử đăng nhập sai có chủ đích | `sudo fail2ban-client set sshd unbanip <ip>` và thêm dải quản trị vào `ignoreip` |

> **Mẹo phục hồi nhanh khi bị khoá ra khỏi máy chủ:** dùng `vmrun` để thực
> thi lệnh trực tiếp trong guest, không cần SSH:
>
> ```powershell
> & "D:\VMware\VMware Workstation\vmrun.exe" -T ws `
>     -gu <user> -gp <password> runProgramInGuest `
>     "D:\Virtualmachine\Ubuntu 64-bit.vmx" /bin/bash -c "<lệnh>"
> ```

## 10. Hoàn nguyên

### Qua console VM (Luôn mở sẵn một phiên console)

```bash
sudo rm -f /etc/ssh/sshd_config.d/00-btl-hardening.conf
sudo rm -f /etc/ssh/sshd_config.d/10-btl-sftp.conf
sudo ufw allow 22/tcp
sudo systemctl restart ssh
```

### Qua SSH (nếu vẫn đăng nhập được)

```bash
ssh -i ~/.ssh/id_ed25519 btladmin@192.168.118.128 \
  'sudo rm -f /etc/ssh/sshd_config.d/00-btl-hardening.conf; sudo systemctl restart ssh'
```

### Trả về snapshot

Trong VMware: `VM → Revert to Snapshot → after-install`.

## 11. Xử lý cảnh báo host key

```bash
# Xem fingerprint đang lưu
btl hostkey list

# Xoá
btl hostkey remove 192.168.118.128

# Thêm lại sau khi xác minh
btl hostkey add 192.168.118.128 --key-file /tmp/hostkey.pub
```

Nếu host key thay đổi **không** phải do bạn chủ động đổi, hãy điều tra
trước — đó có thể là dấu hiệu tấn công MITM.
