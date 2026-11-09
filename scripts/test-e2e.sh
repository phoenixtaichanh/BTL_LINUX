#!/usr/bin/env bash
# ============================================================
# BTL - End to end test against a real Ubuntu server.
#
#   ./scripts/test-e2e.sh <host> <user> [identity-file]
#
# The script exercises the hardened configuration and the transfer
# clients.  It is meant to be run AFTER the server has been
# provisioned with `btl provision`.
#
# Every check prints PASS or FAIL.  The exit code is the number of
# failed checks.
# ============================================================
set -uo pipefail

HOST="${1:-}"
SSH_USER="${2:-}"
IDENTITY="${3:-$HOME/.ssh/id_ed25519}"
SFTP_USER="${SFTP_USER:-ftpsvc}"
ADMIN_USER="${ADMIN_USER:-btladmin}"
KNOWN_HOSTS="${KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"

# On Git Bash for Windows the MSYS runtime rewrites arguments that look like
# Unix paths into Windows paths.  That is exactly wrong here: the local
# scp/sftp binaries are native Windows programs and need Windows paths for
# the local files, while the remote shell is a Linux system and needs Unix
# paths for the paths inside the remote commands.
#
# The conversion is therefore switched off completely, and the local paths
# are converted to their Windows form once, with cygpath.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

#: Convert a local path to the form the native Windows tools understand.
local_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        printf '%s' "$1"
    fi
}

# The project's own client is a Python program, so it needs a path that
# Python understands.  On Windows that is the native form, not the POSIX
# form that the shell uses.
PYTHON_IDENTITY=$(local_path "$IDENTITY")
PYTHON_KNOWN_HOSTS=$(local_path "$KNOWN_HOSTS")

PASS=0
FAIL=0
RESULTS=()

if [[ -z "$HOST" || -z "$SSH_USER" ]]; then
    echo "usage: $0 <host> <ssh-user> [identity-file]" >&2
    exit 2
fi

SSH_OPTS=(
    -o StrictHostKeyChecking=yes
    -o BatchMode=yes
    -o ConnectTimeout=10
)
[[ -f "$IDENTITY" ]] && SSH_OPTS+=(-i "$IDENTITY")

# Every remote command runs through sudo.  "-n" makes sudo fail instead of
# waiting for a password, which would hang the test run, because the
# session has no terminal to type the password into.
SUDO="sudo -n"

check() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        printf '  \033[32mPASS\033[0m  %s\n' "$name"
        PASS=$((PASS + 1))
        RESULTS+=("PASS  $name")
    else
        printf '  \033[31mFAIL\033[0m  %s\n' "$name"
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL  $name")
    fi
}

check_invert() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        printf '  \033[31mFAIL\033[0m  %s\n' "$name"
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL  $name")
    else
        printf '  \033[32mPASS\033[0m  %s\n' "$name"
        PASS=$((PASS + 1))
        RESULTS+=("PASS  $name")
    fi
}

echo "=============================================="
echo " BTL end to end test"
echo " target: $HOST   as: $SSH_USER"
echo "=============================================="

echo
echo "[1] Connectivity and authentication"
check "key based login works" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" "true"

check_invert "password authentication is refused" \
    ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 -o ConnectTimeout=10 \
        "$SSH_USER@$HOST" "true"

echo
echo "[2] Access control"
check_invert "root login is refused" \
    ssh "${SSH_OPTS[@]}" "root@$HOST" "true"

check_invert "an account outside sshusers is refused" \
    ssh "${SSH_OPTS[@]}" "nobody@$HOST" "true"

echo
echo "[3] Configuration hardening"
check "sshd config passes validation" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" "$SUDO sshd -t"

check "password authentication is disabled in the effective config" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "$SUDO sshd -T | grep -qi '^passwordauthentication no$'"

check "root login is disabled in the effective config" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "$SUDO sshd -T | grep -qi '^permitrootlogin no$'"

check "TCP forwarding is disabled" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "$SUDO sshd -T | grep -qi '^allowtcpforwarding no$'"

check "the hardening drop-in is present" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "test -f /etc/ssh/sshd_config.d/00-btl-hardening.conf"

echo
echo "[4] SCP transfers"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "hello from btl" > "$TMP/sample.txt"
mkdir -p "$TMP/tree/sub"
echo "nested" > "$TMP/tree/sub/nested.txt"

# The local paths are handed to the native Windows scp/sftp binaries.
TMP_SAMPLE=$(local_path "$TMP/sample.txt")
TMP_TREE=$(local_path "$TMP/tree")
TMP_DOWNLOADED=$(local_path "$TMP/downloaded.txt")

check "scp uploads a file" \
    scp "${SSH_OPTS[@]}" "$TMP_SAMPLE" "$SSH_USER@$HOST:/tmp/btl-e2e-sample.txt"

check "the uploaded file has the right content" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "grep -q 'hello from btl' /tmp/btl-e2e-sample.txt"

check "scp downloads a file" \
    scp "${SSH_OPTS[@]}" "$SSH_USER@$HOST:/tmp/btl-e2e-sample.txt" "$TMP_DOWNLOADED"

check "the downloaded file has the right content" \
    grep -q "hello from btl" "$TMP/downloaded.txt"

check "scp copies a directory recursively" \
    scp -r "${SSH_OPTS[@]}" "$TMP_TREE" "$SSH_USER@$HOST:/tmp/btl-e2e-tree"

check "the recursive copy kept the nested file" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "grep -q nested /tmp/btl-e2e-tree/sub/nested.txt"

check_invert "scp refuses a path traversal attempt" \
    scp "${SSH_OPTS[@]}" "$TMP_SAMPLE" \
        "$SSH_USER@$HOST:/tmp/../../../../etc/btl-should-not-exist.txt"

check "no file escaped the intended directory" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "! test -e /etc/btl-should-not-exist.txt"

# The project's own SCP implementation, driven against the real
# /usr/bin/scp on the server.  This is the interoperability check that
# matters: it proves our wire format matches OpenSSH byte for byte.
#
# The interpreter is not detected with "command -v" alone.  On Windows the
# "python3" name often resolves to the Microsoft Store stub, which opens the
# Store instead of running Python, so the interpreter has to prove that it
# can actually import the package.
BTL=()
for candidate in python3 python; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c "import btl.cli" >/dev/null 2>&1; then
        BTL=("$candidate" -m btl.cli)
        break
    fi
done

if [[ ${#BTL[@]} -gt 0 ]] && ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "command -v scp" >/dev/null 2>&1; then
    TMP_OWN_DOWNLOADED=$(local_path "$TMP/own-downloaded.txt")
    TMP_OWN_READ=$(local_path "$TMP/own-read-by-system.txt")

    check "the project SCP client uploads a file" \
        "${BTL[@]}" scp --user "$SSH_USER" --identity "$PYTHON_IDENTITY" \
            --known-hosts "$PYTHON_KNOWN_HOSTS" \
            "$HOST" "$TMP_SAMPLE" "/tmp/btl-e2e-own-sample.txt"

    check "the file uploaded by the project SCP client is correct" \
        ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
            "grep -q 'hello from btl' /tmp/btl-e2e-own-sample.txt"

    check "the project SCP client downloads a file" \
        "${BTL[@]}" scp --download --user "$SSH_USER" --identity "$PYTHON_IDENTITY" \
            --known-hosts "$PYTHON_KNOWN_HOSTS" \
            "$HOST" "$TMP_OWN_DOWNLOADED" \
            "$SSH_USER@$HOST:/tmp/btl-e2e-own-sample.txt"

    check "the file downloaded by the project SCP client is correct" \
        grep -q "hello from btl" "$TMP/own-downloaded.txt"

    check "the project SCP client copies a directory recursively" \
        "${BTL[@]}" scp --recursive --user "$SSH_USER" --identity "$PYTHON_IDENTITY" \
            --known-hosts "$PYTHON_KNOWN_HOSTS" \
            "$HOST" "$TMP_TREE" "/tmp/btl-e2e-own-tree"

    check "the recursive copy by the project SCP client kept the nested file" \
        ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
            "grep -q nested /tmp/btl-e2e-own-tree/sub/nested.txt"

    # The two directions above already cover interoperability with the real
    # OpenSSH binary: "put" drives the server's "scp -t" and "get" drives the
    # server's "scp -f".  A file uploaded by the project client must also be
    # readable by the system client.
    check "the system scp can read a file uploaded by the project client" \
        scp "${SSH_OPTS[@]}" "$SSH_USER@$HOST:/tmp/btl-e2e-own-sample.txt" \
            "$TMP_OWN_READ"

    check "the file read by the system scp is correct" \
        grep -q "hello from btl" "$TMP/own-read-by-system.txt"
fi

echo
echo "[5] SFTP transfers"
# The native Windows sftp client interprets a backslash in a path as an
# escape character, so a Windows path has to be written with forward
# slashes.  A path such as "C:\Users\..." would otherwise be read as
# "C:Users...".
TMP_SFTP_DOWNLOADED=$(local_path "$TMP/sftp-downloaded.txt" | tr '\\' '/')
TMP_SAMPLE_SFTP=$(local_path "$TMP/sample.txt" | tr '\\' '/')

check "sftp uploads a file" \
    sftp -b - "${SSH_OPTS[@]}" "$SSH_USER@$HOST" <<EOF
put $TMP_SAMPLE_SFTP /tmp/btl-e2e-sftp.txt
EOF

check "sftp downloads a file" \
    sftp -b - "${SSH_OPTS[@]}" "$SSH_USER@$HOST" <<EOF
get /tmp/btl-e2e-sftp.txt $TMP_SFTP_DOWNLOADED
EOF

check "the SFTP download is correct" \
    grep -q "hello from btl" "$TMP/sftp-downloaded.txt"

check "sftp can list a directory" \
    sftp -b - "${SSH_OPTS[@]}" "$SSH_USER@$HOST" <<EOF
ls /tmp
EOF

echo
echo "[6] SFTP jail (only when the account exists)"
if ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" "id $SFTP_USER" >/dev/null 2>&1; then
    check_invert "the SFTP account cannot open a shell" \
        ssh "${SSH_OPTS[@]}" "$SFTP_USER@$HOST" "true"

    check_invert "the SFTP account cannot reach /etc" \
        sftp -b - "${SSH_OPTS[@]}" "$SFTP_USER@$HOST" <<EOF
get /etc/passwd $(local_path "$TMP/escaped.txt" | tr '\\' '/')
EOF

    check "no file was written outside the jail" \
        ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
            "! test -e /opt/sftp-jails/$SFTP_USER/etc/passwd"

    check "the jail directory is owned by root" \
        ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
            "$SUDO stat -c '%U' /opt/sftp-jails/$SFTP_USER | grep -q root"

    check "the upload directory belongs to the account" \
        ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
            "$SUDO stat -c '%U' /opt/sftp-jails/$SFTP_USER/upload | grep -q $SFTP_USER"
else
    echo "  SKIP  the SFTP account '$SFTP_USER' does not exist on the server"
fi

echo
echo "[7] Defence in depth"
check "fail2ban is running" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "$SUDO systemctl is-active --quiet fail2ban"

check "the sshd jail is enabled" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "$SUDO fail2ban-client status sshd"

check "the firewall is active" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "$SUDO ufw status | grep -qi 'Status: active'"

check "auditd is running" \
    ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
        "$SUDO systemctl is-active --quiet auditd"

echo
echo "[8] Cleanup"
ssh "${SSH_OPTS[@]}" "$SSH_USER@$HOST" \
    "rm -rf /tmp/btl-e2e-sample.txt /tmp/btl-e2e-tree /tmp/btl-e2e-sftp.txt \
             /tmp/btl-e2e-own-sample.txt /tmp/btl-e2e-own-tree" \
    >/dev/null 2>&1

echo
echo "=============================================="
printf ' passed: %d   failed: %d\n' "$PASS" "$FAIL"
echo "=============================================="

if [[ "$FAIL" -gt 0 ]]; then
    echo
    echo "Failed checks:"
    for line in "${RESULTS[@]}"; do
        [[ "$line" == FAIL* ]] && echo "  $line"
    done
fi

exit "$FAIL"
