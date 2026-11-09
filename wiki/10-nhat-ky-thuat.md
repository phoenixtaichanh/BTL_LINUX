# 10 - Nhật ký kỹ thuật

Ghi lại các phát hiện, quyết định thiết kế và lỗi trong quá trình phát
triển. Nhật ký này có giá trị về mặt học tập: nó cho thấy *tại sao* các
quyết định được đưa ra.

---

## 1. Nhật ký phát hiện lỗi

### 1.1. Decode sai thông điệp SCP — nghiêm trọng

**Hiện tượng:** Test `test_decode_file` thất bại với `C0644 299 group`.

**Nguyên nhân:** Tôi hiểu định dạng là `C <mode> <size> <name>` — tức mode
tách bằng dấu cách. Thực tế mode **dính** vào ký tự đầu: `C0644`. Kết quả
là `parts[1]` thực ra là size, và chỉ số bị lệch.

**Sửa:** Tách rõ ba trường: `parts[0][1:]` là mode (octal), `parts[1]` là
size, phần còn lại là tên.

**Bài học:** Giao thức không có tài liệu chính thức, nên phải **đọc mã
nguồn** và **viết test cho từng biến thể** trước khi tin vào trực giác.

### 1.2. Tên file có khoảng trắng

**Hiện tượng:** `C0644 10 my file name.txt` bị decode sai.

**Nguyên nhân:** Dùng `text.split(" ", 2)` rồi coi `parts[2]` là tên, nhưng
khi tách tối đa 2 lần thì `parts[2]` vẫn chứa cả size lẫn tên.

**Sửa:** Tách mode và size trước, phần còn lại sau size chính là tên.

**Bài học:** Giao thức dựa trên dòng văn bản có thể chứa khoảng trắng trong
giá trị phải được xử lý thận trọng — không được giả định trường cuối là
một token.

### 1.3. `sanitize_filename` không loại `..`

**Hiện tượng:** `sanitize_filename("../../etc/passwd")` trả về `_.._etc_passwd`
— vẫn chứa `..`.

**Nguyên nhân:** Hàm chỉ thay `/` và `\`, không xử lý `..`.

**Sửa:** Thêm vòng lặp loại bỏ chuỗi `..` cho tới khi hết.

**Bài học:** Test chỉ kiểm tra `/` bị thay mà không kiểm tra `..` — test
yếu hơn kỳ vọng. Đây là lý do cần test cho *tính chất* (không còn `..`)
chứ không chỉ *kết quả cụ thể*.

### 1.4. `SafePath` trộn quy ước POSIX và native — khó nhất

**Hiện tượng:** `SafePath.resolve("/srv/root", "/etc/passwd")` trên Windows
sinh ra `/C:\Users\...\root/etc/passwd` — một đường dẫn hỗn tạp vô nghĩa.

**Nguyên nhân:** `normalize_remote_path()` dùng `posixpath` (luôn dùng `/`)
nhưng `SafePath` lại gọi `os.path.realpath()` (dùng `\` trên Windows).

**Sửa:** Tách rõ hai miền:
- `normalize_remote_path()`, `is_within()` — thuần **POSIX**, cho đường dẫn
  từ xa.
- `SafePath`, `remote_to_native()`, `native_to_remote()` — thuần **native**,
  cho hệ thống tệp cục bộ.

**Bài học:** Dự án chạy được trên cả Windows (máy trạm) và Linux (máy
chủ), nên phải phân biệt rõ đường dẫn "trên dây" và đường dẫn "trên đĩa".
Trộn lẫn hai khái niệm này là nguồn lỗi kinh điển.

### 1.5. `KnownHostsStore.add` bỏ qua cổng

**Hiện tượng:** Thêm khóa cho cổng 2222 lại lưu hostname trần, không phải
`[host]:2222`.

**Nguyên nhân:** `add()` dùng `hostname` trực tiếp thay vì gọi
`format_known_hosts(hostname, port)`.

**Sửa:** Dùng `format_known_hosts()` trong `add()`.

### 1.6. `paramiko.DSSKey` không còn tồn tại

**Hiện tượng:** `AttributeError: module 'paramiko' has no attribute 'DSSKey'`.

**Nguyên nhân:** `DSSKey` bị xoá trong Paramiko 3.x. Máy trạm dùng
Paramiko 5.1.

**Sửa:** Bỏ khỏi danh sách key class. DSA vốn đã không còn an toàn.

### 1.7. Thiếu `import base64`

**Hiện tượng:** `NameError: name 'base64' is not defined` khi nạp public key.

**Nguyên nhân:** Dùng `base64.b64decode()` mà không import.

### 1.8. Xung đột `-p` trong argparse

**Hiện tượng:** `ArgumentError: argument -p/--preserve-times: conflicting
option string: -p`.

**Nguyên nhân:** `-p` đã dùng cho `--port`.

**Sửa:** Bỏ short flag của `--preserve-times`.

**Bài học:** Với CLI có nhiều nhóm lệnh, nên đặt hàm thêm tham số dùng
chung và kiểm tra xung đột từ đầu.

### 1.9. `UsePrivilegeSeparation` làm hỏng cấu hình — nghiêm trọng

**Hiện tượng:** Không lỗi runtime, nhưng chỉ thị này đã bị deprecated từ
OpenSSH 7.5 và có thể khiến `sshd` **không khởi động được**.

**Sửa:** Gỡ khỏi cấu hình sinh ra.

**Bài học:** Cấu hình sinh tự động có ưu thế lớn — nhưng chỉ khi nó được
kiểm định. Đây là lý do tôi viết `btl/security/validate.py`.

### 1.10. `LoginFailedAttempts` không tồn tại

**Hiện tượng:** Chỉ thị không có trong bất kỳ phiên bản OpenSSH nào.

**Sửa:** Gỡ khỏi baseline, thêm vào danh sách chỉ thị bị loại trong
validator, kèm test chặn tái phát.

### 1.11. Thiếu byte kết thúc nội dung file — nghiêm trọng, chỉ lộ ra khi test round-trip

**Hiện tượng:** Test round-trip giữa `ScpSource` và `ScpSink` thất bại với
`unknown control message type: '\x00'`. Sink đọc được một byte NUL ở cuối
luồng và cố giải mã nó như một thông điệp điều khiển.

**Nguyên nhân:** Đây là **lỗi giao thức thật**, không phải lỗi test. Khi
đọc mã nguồn `scp.c` của OpenSSH (bản portable master) thì rõ ràng:

- Phía *producer* (`scp -f`) **ghi một byte NUL ngay sau nội dung file**, để
  đánh dấu kết thúc dữ liệu (`scp.c`: `atomicio(vwrite, remout, "", 1)`).
- Phía *sink* (`scp -t`) **đọc byte NUL đó** rồi mới gửi xác nhận
  (`scp.c`: `response()` sau khi đọc đủ `size` byte).

Mã của tôi chỉ gửi byte NUL ở **cuối toàn bộ luồng**, và sink không hề
biết phải chờ byte kết thúc nội dung. Hai bên lệch pha ngay từ file đầu
tiên.

**Sửa:** Thêm hằng `EOF_MARKER = b"\x00"`:

- `ScpSource._send_file()` và `SCPClient._send_file()` ghi `EOF_MARKER` sau
  nội dung file, rồi mới chờ xác nhận.
- `ScpSink._receive_file()` đọc đúng 1 byte kết thúc trước khi gửi xác nhận.

**Bài học:** Giao thức SCP **không** có khung framing cho nội dung file — độ
dài lấy từ thông điệp `C`. Đọc mã nguồn tham chiếu là bắt buộc, vì mô tả
bằng lời trong blog dễ bỏ sót byte đánh dấu. Test round-trip (nối hai đầu
`ScpSource` ↔ `ScpSink` qua hai ống) mới là thứ phát hiện ra lỗi này; unit
test từng hàm không thể.

### 1.12. `get()` treo — đọc sai chiều byte "ready"

**Hiện tượng:** `SCPClient.get()` (tải file về) treo vô hạn.

**Nguyên nhân:** Khi ta chạy `scp -f` ở máy chủ, **máy chủ là bên producer**
và nó *chờ* ta gửi byte ready. Mã của tôi lại đi `channel.recv(1)` trước
để "đọc byte ready của máy chủ" — nhưng máy chủ không gửi byte này, nên
lệnh bị chặn vô hạn.

Đối chiếu `scp.c`: ở chế độ `-f`, `main()` gọi `(void) response();` — tức
**đọc** một byte từ peer trước khi gửi bất cứ thứ gì.

**Sửa:** Bỏ hẳn `channel.recv(1)` trong `get()`. Chính `ScpSink.receive()`
đã gửi byte ready (`write(ACK_OK)`) ngay khi bắt đầu — đúng thứ tự mà peer
đang chờ.

### 1.13. `put()` lệch pha một byte xác nhận

**Hiện tượng:** Lệnh upload bị treo hoặc báo lỗi xác nhận lạ.

**Nguyên nhân:** Khi ta chạy `scp -t` ở máy chủ, **máy chủ là bên sink**
và nó *gửi* byte ready trước. Mã của tôi không đọc byte đó, nên lệnh
`_expect_ack()` đầu tiên nuốt mất byte ready và mọi xác nhận sau đó lệch
một vị trí.

Đối chiếu `scp.c` (`toremote`): sau khi khởi chạy `scp -t` ở máy chủ,
client gọi `response()` — tức **đọc** byte ready của máy chủ.

**Sửa:** Trong `SCPClient._sink_to_peer()`, đọc riêng byte ready trước khi
gửi thông điệp đầu tiên, và kiểm tra nó phải là `ACK_OK`.

### 1.14. Hai bộ đệm độc lập trên cùng một kênh — mất byte

**Hiện tượng:** File tải về bị thiếu dữ liệu ở giữa, dung lượng không khớp.

**Nguyên nhân:** `SCPClient` có **hai** reader độc lập trên cùng một
channel SSH: `_make_line_reader()` (đọc dòng) và `_make_reader()` (đọc N
byte). Mỗi reader có buffer riêng, nên khi một thông điệp điều khiển và
phần đầu nội dung file đến cùng một gói TCP, byte nội dung rơi vào buffer
của reader nào đó và bị bỏ qua khi reader kia đọc.

**Sửa:** Gộp thành một `ChannelReader` duy nhất giữ buffer chung, cung cấp
`read_line()`, `read_exactly()` và `read_byte()` trên cùng một luồng byte.

**Bài học:** SCP là giao thức **trộn** định dạng dòng và định dạng độ dài
trên *cùng* một luồng byte. Bất kỳ reader nào giữ buffer riêng đều nguy
hiểm — phải có đúng **một** nguồn sự thật về vị trí byte.

### 1.15. Sink không dừng sau thư mục ngoài cùng

**Hiện tượng:** Sau khi nhận xong một cây thư mục, sink vẫn chờ đọc thêm.

**Nguyên nhân:** Thông điệp `E` đóng thư mục, và vòng lặp chỉ pop khỏi
ngăn xếp rồi tiếp tục chờ. Với thư mục ngoài cùng, `E` đó là **dấu kết
thúc toàn bộ luồng**.

**Sửa:** Khi ngăn xếp rỗng sau khi pop, sink gửi xác nhận rồi `break`.

**Bài học:** Với giao thức không có thông điệp kết thúc tường minh, ranh
giới "hết dữ liệu" phải suy ra từ cấu trúc thông điệu. Ở đây nó là `E`
ở cấp ngoài cùng.

### 1.16. `argparse` không chấp nhận tuỳ chọn sau tham số vị trí

**Hiện tượng:** `btl ssh 192.168.122.128 -u alice uptime` báo lỗi
`unrecognized arguments: uptime`. Mọi ví dụ trong tài liệu dùng thứ tự này
đều không chạy được.

**Nguyên nhân:** `argparse` **ngừng gán tham số vị trí** ngay khi gặp một
tuỳ chọn. Với `parse_args(['host', '-u', 'alice', 'uptime'])`, nó gán `host`
xong rồi dừng, nên `uptime` không còn chỗ nào để đặt.

Đây là hạn chế nổi tiếng của `argparse`, và nó xung đột trực tiếp với cách
viết dòng lệnh tự nhiên của một công cụ SSH.

**Sửa:** Thêm `_parse_args()` — dùng `parse_known_args()` rồi gán các giá trị
còn lại vào những tham số vị trí **còn trống**, theo đúng thứ tự khai báo.

**Bài học:** Bài học ở đây là **phải kiểm chứng lệnh trong tài liệu thực sự
chạy được**, chứ không chỉ "viết đúng cú pháp". Việc rà lại toàn bộ ví dụ
trong `wiki/07` và `README.md` bằng cách parse thật đã phát hiện ra lỗi này
— và cả một lỗi khác: ví dụ trong README dùng `--host` cho `scp`/`sftp`
trong khi hai lệnh đó nhận `host` là tham số vị trí.

Lưu ý cho người đọc: bản sửa đầu tiên của tôi gán giá trị còn lại vào **tất
cả** tham số vị trí, kể cả những cái `argparse` đã gán được — làm `host` bị
đè bằng `command`. Test phải kiểm tra **giá trị** chứ không chỉ "parse không
lỗi", mới phát hiện ra.

### 1.17. Host key bị từ chối trước khi policy của dự án kịp chạy

**Hiện tượng:** `btl ssh <host> --auto-accept-host-key` báo
`could not connect to 192.168.118.128: Server '192.168.118.128' not found in
known_hosts`, dù `btl hostkey add` cũng không giúp.

**Nguyên nhân:** Paramiko hỏi **missing-host-key policy trong lúc bắt tay**,
trước khi transport được bàn giao cho lớp trên. Tôi cài
`paramiko.RejectPolicy()` vào đúng chỗ đó, nên **mọi** host key đều bị từ
chối trước khi `HostKeyPolicy` của dự án kịp được gọi. Cờ
`--auto-accept-host-key` về mặt kỹ thuật vẫn được truyền vào, nhưng không
bao giờ có tác dụng.

**Sửa:** Thêm adapter `_StrictMissingHostKeyPolicy` cài vào Paramiko, và
adapter đó gọi đúng `HostKeyPolicy.check()` của dự án. Quyết định được đưa
ra ở **đúng một chỗ** và đúng một lần.

**Bài học:** Khi một thư viện bọc thư viện khác, phải hiểu *thời điểm* mà
thư viện trong gọi callback, không chỉ *nội dung* callback. Ở đây lỗi không
nằm ở logic kiểm tra host key — logic đó viết đúng — mà nằm ở chỗ callback
được gọi.

### 1.18. `sudo -S` không bao giờ nhận được mật khẩu

**Hiện tượng:** `btl provision` dừng ngay ở bước "Installing packages...".

**Nguyên nhân:** Script provisioning chạy `sudo -S bash -c ...`, và `-S` bảo
sudo đọc mật khẩu từ **standard input**. Nhưng `exec_command()` không gửi gì
cả vào stdin, nên sudo chờ mãi, đến khi phiên bị huỷ theo timeout.

**Sửa:** Thêm tham số `stdin_data` cho `exec_command()`, thêm trường
`sudo_password` vào `ConnectionConfig`, và truyền mật khẩu qua stdin cho mọi
lệnh `sudo -S`. Kèm `-p ''` để không lẫn prompt vào output.

**Bài học:** `-S` trong `sudo` là một lựa chọn *giao thức*, không phải một
từ khoá độc lập — nó chỉ có nghĩa nếu phía bên kia thực sự gửi mật khẩu.

### 1.19. File cấu hình được ghi vào `/tmp` rồi bị bỏ lại đó

**Hiện tượng:** `btl provision` báo thành công, `btl audit` vẫn báo 17/18
tuân thủ, và `/etc/ssh/sshd_config.d/` **rỗng**.

**Nguyên nhân:** `write_file_over_ssh()` sinh script ghi nội dung vào
`/tmp/btl_upload` bằng heredoc — và dừng đó. Docstring nói "được ghi vào vị
trí tạm trước, rồi mới chuyển vào chỗ", nhưng **không có lệnh nào chuyển
file**. Tệp nằm lại trong `/tmp` và cấu hình không bao giờ tới được sshd.

**Sửa:** `scp_upload_script(content, remote_path)` nay sinh kèm
`install -m 644 /tmp/btl_upload <đường dẫn đích>`.

**Bài học:** Docstring mô tả ý định, không phải hành vi. Khi phát hiện một
lỗi, hãy **đọc lại chính xác dòng code đó** thay vì tin vào mô tả.

### 1.20. Tài khoản quản trị bị khoá mật khẩu mà không có khoá công khai

**Hiện tượng:** Sau khi provisioning, tài khoản `btladmin` không thể đăng nhập
bằng bất kỳ cách nào.

**Nguyên nhân:** `build_admin_script()` chạy `passwd -l` cho tài khoản quản
trị, còn cấu hình sshd đặt `PasswordAuthentication no`. Nhưng script **không
cài `authorized_keys`**. Tài khoản bị khoá theo cả hai phía mà không có
lối vào nào.

**Sửa:** Thêm `--admin-public-key` và `--sftp-public-key`; provisioning cài
`authorized_keys` với quyền `600` và sở hữu đúng, **sau khi** khoá mật khẩu.

**Bài học:** "Chỉ khóa công khai" là một chính sách gồm **hai nửa**: tắt
mật khẩu *và* bảo đảm có khoá công khai. Thiếu một nửa thì tài khoản bị
khoá vĩnh viễn — đây chính là loại lỗi "cấu hình đúng nhưng không dùng
được" nguy hiểm nhất.

### 1.21. `AllowGroups` khoá cả người vận hành

**Hiện tượng:** Provisioning xong thì mất khả năng đăng nhập vào chính máy
chủ đã cấu hình.

**Nguyên nhân:** `AllowGroups sshusers` chặn mọi tài khoản không thuộc nhóm
đó. Tài khoản dùng để chạy provisioning (`tuananh`) không thuộc nhóm, và
tài khoản SFTP cũng vậy — nhóm được tạo nhưng không ai được thêm vào.

**Sửa:** (1) Thêm tài khoản provisioning vào `sshusers` và cài cho nó khoá
công khai; (2) thêm tài khoản SFTP vào `sshusers`; (3) `ProvisionPlan.validate()`
từ chối bất kỳ kế hoạch nào mà để tài khoản provisioning nằm ngoài nhóm
được phép.

**Bài học:** `AllowGroups` được đánh giá **trước** các khối `Match`, nên
tài khoản SFTP phải thuộc nhóm cho `Match User` của chúng có hiệu lực.

### 1.22. `ufw` bật trước khi có rule SSH

**Hiện tượng:** Provisioning làm mất kết nối ngay sau bước cài đặt.

**Nguyên nhân:** `build_install_script()` chạy `systemctl enable --now ufw`.
Chính sách mặc định của ufw là `deny incoming`, và rule SSH chỉ được thêm
ở bước cuối. Giữa hai bước đó, ufw đã chặn cổng 22.

**Sửa:** Bỏ `systemctl enable --now ufw` khỏi script cài đặt; firewall được
áp dụng ở bước cuối, **sau** khi sshd đã nạp cấu hình hợp lệ. Thêm cờ
`--no-firewall` cho trường hợp cần bỏ qua.

**Bài học:** Thứ tự các bước trong provisioning là một phần của *chính
sách*, không phải chi tiết cài đặt. Một tường lửa được bật sớm hơn một
quy tắc cần thiết sẽ chặn chính người quản trị.

### 1.23. `ufw limit` chặn loạt phiên quản trị

**Hiện tượng:** Bộ test E2E thất bại 19/38 kiểm tra, với lỗi
`Connection timed out` xen kẽ với các kiểm tra đã đạt.

**Nguyên nhân:** `ufw limit 22/tcp` từ chối hơn 6 kết nối mới trong 30 giây
từ cùng một địa chỉ. Bộ test mở hơn 20 phiên liên tiếp, nên bị chặn. Dấu
vết trong kernel xác nhận: `[UFW LIMIT BLOCK] ... SRC=192.168.118.1 DPT=22`.

**Sửa:** Đổi mặc định của `FirewallPolicy` sang `ufw allow`; thêm cờ
`--ufw-limit-ssh` để bật `limit` khi server thật sự lộ ra Internet. Việc
chống brute force đã do fail2ban và `MaxAuthTries`/`MaxStartups` đảm nhiệm.

**Bài học:** "harden càng nhiều càng tốt" không phải lúc nào cũng đúng. Một
biện pháp có thể gây hại cho chính người được bảo vệ, và việc phát hiện ra
điều đó **chỉ có thể xảy ra khi chạy thật**.

### 1.24. fail2ban ban cả máy trạm quản trị

**Hiện tượng:** Kết nối SSH từ máy trạm bị từ chối sau khi chạy E2E.

**Nguyên nhân:** Jail `sshd` chạy ở chế độ `aggressive`, nên nó tính cả những
lần đăng nhập thất bại **có chủ đích** mà bộ kiểm tra dùng để xác minh
`AllowGroups` (`root@host`, `nobody@host`). Sau ba lần, IP của máy trạm bị
ban. `ignoreip` mặc định chỉ chứa loopback.

**Sửa:** Thêm tuỳ chọn `--fail2ban-ignore` để khai báo dải quản trị, và
dùng nó khi provision.

**Bài học:** Chính sách chống brute force không nên trừng phạt người quản
trị hợp lệ. Trong môi trường thật, dải quản trị phải được loại trừ **tường
minh**, chứ không phải ngầm.

### 1.25. `ChallengeResponseAuthentication` là alias đã lỗi thời

**Hiện tượng:** `btl audit` báo `[MISSING] challengeresponseauthentication`,
dù cấu hình đã đặt `ChallengeResponseAuthentication no`.

**Nguyên nhân:** `sshd_config(5)` ghi rõ: *"ChallengeResponseAuthentication is
a deprecated alias for this"* — của `KbdInteractiveAuthentication`. OpenSSH
10.2 chỉ in **tên chuẩn** ra output của `sshd -T`, nên auditor tìm không
thấy tên cũ và báo động giả.

**Sửa:** Thêm bảng `ALIASES` trong `btl/security/sshd_config.py`; khi một
chỉ thị không có trong cấu hình hiệu lực, auditor thử tên chuẩn tương ứng.

**Bài học:** `sshd -T` in ra *tên đã được chuẩn hoá*, còn file cấu hình chấp
nhận *tên đã lỗi thời*. Auditor phải hiểu cả hai.

### 1.26. `btl scp --download` đảo ngược ý nghĩa hai tham số

**Hiện tượng:** `btl scp --download host <đường dẫn remote> <đường dẫn local>`
lại tải về vào `<đường dẫn remote>`.

**Nguyên nhân:** Trong nhánh `--download`, `cmd_scp` lấy `remote_path` từ
`args.local_path` và `local_path` từ `args.remote_path` — đảo ngược so với
nhánh upload. Hai tham số vị trí mang hai nghĩa khác nhau tuỳ theo chiều.

**Sửa:** Hai tham số luôn giữ **cùng một nghĩa** ở cả hai chiều:
`local_path` là đường dẫn trên máy này, `remote_path` là đường dẫn trên
máy chủ. Chỉ có hướng truyền là đổi.

**Bài học:** Khi hai tham số có nghĩa đối xứng nhau, **đừng** cho chúng đổi
nghĩa theo cờ. Người đọc phải nhớ được quy tắc, và người viết cũng dễ sai.

### 1.27. Tải về tạo ra thư mục thay vì tệp

**Hiện tượng:** `btl scp --download` báo "Downloaded 1 file(s)" nhưng tệp
không xuất hiện ở đường dẫn đã yêu cầu.

**Nguyên nhân:** `ScpSink` phân giải mọi tên nhận được **theo thư mục đích**
(`destination`), vì đó là đúng mô hình của giao thức. `SCPClient.get()`
lại truyền `local_path` (đường dẫn **tệp**) làm thư mục đích, nên tệp được
ghi vào `<local_path>/<tên phía server>` và `<local_path>` trở thành một
thư mục.

**Sửa:** Thêm `_prepare_destination()`: với tệp đơn, đích là thư mục cha và
tệp được đổi tên sau khi nhận; với thư mục (đệ quy) hoặc khi đường dẫn đích
đã là một thư mục, giữ nguyên.

**Bài học:** Mô hình của giao thức (thư mục đích) và kỳ vọng của người
dùng (đường dẫn tệp) có thể khác nhau. Lớp trên giao diện phải làm nối hai
tầng này.

### 1.28. `python3` trên Windows có thể là stub của Microsoft Store

**Hiện tượng:** Các kiểm tra "project SCP client" trong E2E thất bại, trong
khi chạy tay lại thành công.

**Nguyên nhân:** Script E2E dò interpreter bằng `command -v python3`. Trên
Windows, `python3` trỏ tới `WindowsApps/python3` — một **stub** mở Microsoft
Store thay vì chạy Python. Nên điều kiện kiểm tra interpreter tồn tại, nhưng
lệnh chạy được thì không.

**Sửa:** Dò interpreter bằng cách **thử chạy thật** (`python -c "import
btl.cli"`), không dựa vào `command -v`.

**Bài học:** Sự tồn tại của một lệnh không bảo đảm lệnh đó dùng được. Một
bài kiểm tra phải xác minh **hành vi**, không phải **sự hiện diện**.

### 1.29. `authorized_keys` bị nhân bản mỗi lần provision

**Hiện tượng:** Sau 5 lần provision, `~/.ssh/authorized_keys` của mỗi tài
khoản có **5 bản sao giống hệt** của cùng một khoá công khai.

**Nguyên nhân:** Script provisioning dùng `printf ... >> authorized_keys` —
append vô điều kiện, không kiểm tra khoá đã tồn tại. Điều này **vi phạm yêu
cầu idempotent (D7)** của đề tài: "chạy hai lần cho cùng kết quả".

Lỗi này không bị unit test bắt, vì test chỉ kiểm tra *khoá có xuất hiện
trong script*, chứ không kiểm tra *script có tạo ra kết quả trùng lặp hay
không*. Nó chỉ lộ ra khi đếm số dòng thật trên máy chủ.

**Sửa:** Thay `>>` bằng phép **hợp nhất**: ghi khoá mới vào file tạm, nối
file cũ vào, rồi `sort -u` để loại trùng.

```bash
cat > "$home_dir/.ssh/authorized_keys.new" <<'BTL_KEYS_EOF'
<khoá mới>
BTL_KEYS_EOF
touch "$home_dir/.ssh/authorized_keys"
cat "$home_dir/.ssh/authorized_keys" >> "$home_dir/.ssh/authorized_keys.new"
sort -u "$home_dir/.ssh/authorized_keys.new" > "$home_dir/.ssh/authorized_keys"
rm -f "$home_dir/.ssh/authorized_keys.new"
```

Kết quả sau khi sửa: chạy provision liên tiếp 2 lần, cả 3 tài khoản đều giữ
**đúng 1 khoá**.

**Bài học:** "Idempotent" không phải là *câu lệnh có điều kiện* — nó là *kết
quả quan sát được là không đổi*. `mkdir -p` và `usermod -aG` đều idempotent
theo nghĩa đen; `>>` thì không. Và test cho idempotence phải **chạy hai lần
rồi so sánh trạng thái**, chứ không chỉ assert nội dung script.

### 1.30. Lệnh `awk` escape sai làm mất khoá đăng nhập

**Hiện tượng:** Sau khi chạy một lệnh dọn trùng lặp thủ công qua SSH,
`tuananh` không còn đăng nhập được (`Permission denied (publickey)`), dù
`btladmin` vẫn vào được.

**Nguyên nhân:** Lệnh dọn trùng lặp dùng `awk '!seen[\$0]++'` trong điều
kiện PowerShell → SSH → bash, qua ba lớp escape. Backslash bị giữ lại và
`awk` báo `unexpected character '\'`, nên file đích bị ghi **rỗng** trước khi
lệnh lỗi.

**Sửa:** Khôi phục bằng `vmrun` (out-of-band, không cần SSH), rồi chạy lại
`btl provision` — với logic hợp nhất ở mục 1.29 — để dọn sạch trùng lặp.

**Bài học:** Đây là bài học **về thứ tự thao tác**, không chỉ về kỹ thuật:

1. Luôn **kiểm tra trạng thái trước** khi ghi đè (`wc -l` trước khi `cp`).
2. Ghi vào file tạm rồi mới `mv` sang đích, thay vì ghi thẳng.
3. Có **đường vào dự phòng** không phụ thuộc SSH (`vmrun` cho VMware) — vì
   nếu không, một lệnh sai sẽ khoá vĩnh viễn tài khoản vận hành.

Đáng chú ý: dự án đã có sẵn đường vào dự phòng này (`vmrun`), nhưng lúc
đầu tôi dùng `awk` vì "nhanh hơn". Sự nhanh đó là ảo — nó làm mất quyền truy
cập và tốn thêm nhiều phút để khôi phục.

### 1.31. `ssh-keyscan` dùng định dạng `known_hosts`, không phải định dạng khoá

**Hiện tượng:** `btl hostkey add 192.168.118.128 --key-file hostkey.pub` báo:

```
could not load private key ...: Ed25519Key: not a valid OPENSSH private key file
```

**Nguyên nhân:** `ssh-keyscan` ghi ra theo định dạng `known_hosts`, tức là
**tên host đứng trước**:

```
192.168.118.128 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

Trong khi `load_public_key()` chỉ nhận định dạng khoá thuần (`ssh-ed25519
AAAA...`). Hàm thử parse như khoá công khai, thất bại, rồi rơi xuống nhánh
"chắc là khoá riêng tư" và báo lỗi sai lệch.

**Sửa:** Nếu trường đầu tiên không phải là kiểu khoá, nhưng trường thứ hai
lại là kiểu khoá, thì bỏ qua trường đầu và parse phần còn lại.

**Bài học:** Thông điệp lỗi phải mô tả đúng **nguyên nhân**, không chỉ
"không đọc được file". Lỗi "not a valid OPENSSH private key file" khiến người
đọc nghĩ về khoá riêng tư hỏng, trong khi vấn đề thật là **định dạng của
file**. Cùng một bài học như mục 1.19: docstring và thông báo lỗi mô tả ý
định, không mô tả hành vi.

### 1.32. `btl ssh` sập khi máy chủ trả về tiếng Việt

**Hiện tượng:** `btl ssh <host> "cat file.txt"` với file chứa tiếng Việt báo:

```
UnicodeEncodeError: 'charmap' codec can't encode character '\ufeff' in position 0
```

**Nguyên nhân:** Console Windows mặc định dùng **code page cũ** (`cp1252`),
trong khi `sys.stdout.write()` mặc định encode theo code page đó. Dữ liệu
UTF-8 hợp lệ từ máy chủ không thể mã hoá.

**Sửa:** Thêm `_write_output()` trong `btl/cli.py`, thay ký tự không mã hoá
được thay vì ném lỗi, và dùng nó cho mọi nơi in dữ liệu từ máy chủ.

**Bài học:** Công cụ CLI chạy trên Windows phải coi console là một **đường
vào có giới hạn**, không phải một kênh trung thực tuyệt đối. Nội dung thay
thế vẫn cho người dùng biết "có dữ liệu ở đây", trong khi ném lỗi thì mất
toàn bộ phiên làm việc.

### 1.33. Paramiko 5 bỏ các accessor `cipher()`, `mac()`, `compression`

**Hiện tượng:** `btl ssh <host> --info` ném:

```
AttributeError: 'Transport' object has no attribute 'cipher'
```

**Nguyên nhân:** Paramiko 5.x chuyển các giá trị đã thỏa thuận sang **thuộc
tính thuần** (`remote_cipher`, `remote_mac`, `remote_compression`) và bỏ các
accessor cũ. Dự án viết theo API cũ nên không chạy được với phiên bản
Paramiko mới.

**Sửa:** Thêm `_negotiated_value()` đọc được cả hai: ưu tiên thuộc tính mới,
fallback về accessor cũ. Tương tự cho `_server_key_types()` và
`_allowed_auth_methods()`.

Hai điểm phát hiện thêm:

- `sshd -T` cần quyền root, nên lệnh dùng `sudo -n sshd -T || sshd -T`.
- `ssh -Q` **không** hỗ trợ truy vấn phương thức xác thực (chỉ có `cipher`,
  `kex`, `key`, `mac`, ...), nên phải đọc `sshd -T` thay vì đoán.

Kết quả sau khi sửa trên máy chủ thật:

```json
{
  "remote_version": "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.8",
  "local_version": "SSH-2.0-paramiko_5.1.0",
  "cipher": "aes128-ctr",
  "mac": "hmac-sha2-256",
  "compression": "none",
  "kex": null,
  "host_key_types": ["ssh-ed25519"],
  "allowed_auth_methods": ["publickey"]
}
```

`allowed_auth_methods` chỉ có `publickey` — đúng như chính sách hardening.

**Bài học:** Thư viện bên ngoài có **phiên bản**, và API có thể bị bỏ trong
một bản minor. `requirements.txt` ghi `paramiko>=3.4` — đúng nghĩa là "từ
3.4 trở lên", bao gồm cả 5.x mà dự án chưa từng kiểm thử. Cần có một bài
kiểm thử **tương thích API** cho trường hợp này, và phải chấp nhận trả
`null` khi thư viện thật sự không cung cấp giá trị — thà không có còn hơn
báo đoán.

Ngoài ra `kex` vẫn là `null`: Paramiko 5 chỉ *ghi log* thỏa thuận KEX mà
không lưu vào thuộc tính. Dự án trả `null` thay vì đoán — đây là lựa chọn
có chủ đích, và được ghi rõ trong docstring.

---

## 2. Quyết định thiết kế

### 2.1. Từ chối thay vì làm sạch đường dẫn

| Lựa chọn | Kết quả |
| --- | --- |
| **A.** Làm sạch: `../../etc/passwd` → `etc_passwd` | An toàn, nhưng **giấu** hành vi tấn công |
| **B.** Từ chối: ném `ValidationError` | An toàn, **ghi log** được ý đồ tấn công |

**Chọn B.** Trong một dự án an ninh, việc phát hiện tấn công quan trọng
không kém việc chặn nó. Bổ sung: `validate_relative_name()` dùng cho
đường dẫn từ peer, còn `sanitize_filename()` dùng cho tên do người dùng
chọn — mỗi trường hợp một hàm.

### 2.2. Kiểm định host key ở hai tầng

Paramiko có `AutoAddPolicy()` (tự động tin) và `RejectPolicy()` (từ chối
mọi thứ). Dự án dùng `RejectPolicy()` rồi kiểm tra bằng policy riêng.

**Lý do:** `RejectPolicy()` sẽ từ chối cả khóa **đã tin cậy**, nên không
dùng được. Policy riêng giải quyết đúng ba trường hợp: khớp (chấp nhận),
chưa biết (từ chối), đã đổi (lỗi chí mạng).

### 2.3. Mặc định `auto_accept=False`

Mặc định của OpenSSH (`StrictHostKeyChecking=accept-new`) chỉ cảnh báo rồi
chấp nhận khóa lạ. Dự án mặc định **từ chối**, yêu cầu thủ công.

**Đánh đổi:** người dùng phải chạy thêm một lệnh. Đây là đánh đổi có chủ
ý — đây là chốt chặn MITM quan trọng nhất.

### 2.4. Codec tách khỏi vận chuyển

`protocol.py` không import `paramiko`, không mở socket. Nó nhận callback.

**Lợi ích:** 35 test giao thức chạy trong 0.06 giây, không cần mạng; có
thể dùng lại codec cho công cụ phân tích giao thức.

### 2.5. Drop-in `00-` thay vì sửa file chính

Sửa `/etc/ssh/sshd_config` trực tiếp sẽ bị mất khi nâng cấp Ubuntu. Drop-in
`00-btl-hardening.conf` tồn tại qua các bản nâng cấp và thắng
`50-cloud-init.conf`.

### 2.6. Baseline phải khớp với chính sách sinh ra

`LoginFailedAttempts` bị loại vì không tồn tại. Baseline phải **thực sự
kiểm định được**, nếu không lệnh `audit` sẽ báo sai.

Quan trọng hơn: baseline và `SSHDPolicy` phải **khớp nhau**. `audit` so
sánh máy chủ thật với baseline, còn `provision` ghi cấu hình sinh từ policy.
Nếu một chỉ thị có trong policy nhưng vắng trong baseline thì `audit` không
bao giờ phát hiện ra nó — đúng những chỉ thị quan trọng nhất lại dễ bị bỏ sót
nhất.

Thực tế đã xảy ra: `AllowGroups` và `AllowTcpForwarding` có trong policy nhưng
thiếu trong baseline. Đã bổ sung, kèm test `TestBaselineConsistency` chạy
`to_config()` rồi đưa kết quả vào `audit_config()` và đòi kết quả phải là
"tuân thủ hoàn toàn" — để hai bên không thể trôi khỏi nhau nữa.

### 2.7. Kiểm định cấu hình tại thời điểm sinh

`validate_config()` chạy bên trong `SSHDPolicy.to_config()`, không phải ở
bước apply. Lỗi bị bắt trên máy trạm, trước khi file lên máy chủ.

### 2.8. `sudo` qua SSH không nhập mật khẩu

Các lệnh provisioning dùng `sudo -S`. Trong môi trường lab, tài khoản
provisioning đã có quyền sudo không cần mật khẩu (đã cấu hình `NOPASSWD`),
và `BatchMode` tránh treo.

**Hạn chế đã biết:** nếu `sudo` yêu cầu mật khẩu, provisioning sẽ thất
bại. Đây là điểm cần cải thiện khi triển khai thật.

---

## 3. Công cụ và quy trình

### 3.1. Quy trình làm việc

```
1. Viết tài liệu wiki trước (thiết kế trong đầu)
2. Viết code
3. Viết test cùng lúc với code
4. Chạy test, sửa đến khi xanh
5. Cập nhật wiki
```

Bước 1 đặc biệt quan trọng: nhiều lỗi được phát hiện khi viết tài liệu
trước khi viết code (ví dụ: chỉ thị `UsePrivilegeSeparation` bị loại khi
viết phần giải thích trong tài liệu, không phải khi test).

### 3.2. Công cụ đã dùng

| Công cụ | Mục đích |
| --- | --- |
| pytest | Unit test |
| argparse | CLI |
| Paramiko | Vận chuyển SSH/SFTP |
| `ssh -T`, `sshd -T` | Kiểm định cấu hình |
| Tài liệu OpenSSH chính thức | Đối chiếu hành vi |

### 3.3. Bài học về kiểm thử

| Vấn đề | Bài học |
| --- | --- |
| Test `sanitize_filename` chỉ kiểm `/` bị thay | Test **tính chất** không chỉ kết quả cụ thể |
| Test decode sai vì hiểu sai đặc tả | Mỗi biến thể thông điệp cần một test |
| Test `SafePath` dùng `endswith("/sub")` | Test phải độc lập với hệ điều hành |
| Test validator so sánh hoa thường | So sánh giá trị phải không phân biệt hoa thường |
| Unit test mỗi hàm đều xanh nhưng giao thức vẫn sai | Cần **test round-trip** nối hai đầu thật của giao thức |
| Test đọc wire format viết tay | Wire format phải đối chiếu mã nguồn `scp.c` |

### 3.4. Bài học lớn nhất: đọc mã nguồn tham chiếu

Ba lỗi giao thức nghiêm trọng (mục 1.11, 1.12, 1.13) đều **không** được phát
hiện bởi unit test, vì mỗi hàm riêng lẻ đều hợp lý theo cách tôi hiểu sai
giao thức. Chúng chỉ lộ ra khi:

1. Tôi đọc `scp.c` của OpenSSH để đối chiếu từng bước bắt tay.
2. Tôi viết test round-trip nối `ScpSource` với `ScpSink` thật.

Đối với giao thức không có đặc tả chính thức, **mã nguồn tham chiếu là
nguồn sự thật duy nhất**. Bài học này đã được đưa vào quy trình: mọi thay
đổi vào codec phải kèm đối chiếu với `scp.c` và test round-trip.


---

## 4. Đề xuất cải thiện

| # | Đề xuất | Lý do | Ưu tiên |
| --- | --- | --- | --- |
| 1 | Chạy E2E trên VM thật | Xác nhận toàn bộ giả định | Cao |
| 2 | Đối chiếu codec SCP với client OpenSSH | Xác nhận tương thích | Cao |
| 3 | Hỗ trợ `sudo` có mật khẩu trong provisioning | Dùng được thực tế hơn | Trung bình |
| 4 | Thêm MFA (TOTP) | Tăng mạnh lớp xác thực | Trung bình |
| 5 | Module Ansible thay script shell | Quản lý nhiều máy | Thấp |
| 6 | `btl audit --watch` theo dõi liên tục | Phát hiện trôi cấu hình | Thấp |

---

## 5. Ghi chú về môi trường phát triển

| Thành phần | Phiên bản |
| --- | --- |
| Máy trạm | Windows, Python 3.11.9 |
| Paramiko | 5.1.0 |
| pytest | 9.2.0 |
| Máy chủ đích | Ubuntu 22.04 / 24.04 trên VMware (đang chuẩn bị) |

> Vì không có WSL hay Linux cục bộ, toàn bộ kiểm thử tự động được viết
> theo cách **không phụ thuộc nền tảng** — đây cũng là lý do `SafePath`
> dùng `os.path` thay vì giả định đường dẫn POSIX thuần.
