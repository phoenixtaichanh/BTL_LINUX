"""Command line interface for the BTL toolkit.

The CLI groups the functionality into the areas of the assignment:

``ssh``
    Connect to a host, run a command, check the host key.
``scp``
    Copy files to and from a host.
``sftp``
    Browse and transfer files with a path confined SFTP client.
``hostkey``
    Manage the trusted host key store.
``audit``
    Check how well the hardened configuration is applied.
``provision``
    Configure a fresh Ubuntu host.
``gui``
    Start the graphical interface in a browser.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
from typing import List, Optional, Tuple

from . import __version__
from .security.defense import AuditPolicy, Fail2BanPolicy, FirewallPolicy, sshd_effective_config
from .security.sshd_config import SSHDPolicy, audit_config, summarize
from .ssh.connection import AuthConfig, ConnectionConfig, SSHConnection
from .ssh.hostkeys import HostKeyPolicy, KnownHostsStore
from .utils.errors import BTLException, ConfigError
from .utils.logging import get_logger, setup_logging

logger = get_logger("cli")


# ----------------------------------------------------------------------
# argument helpers
# ----------------------------------------------------------------------


def _add_connection_arguments(
    parser: argparse.ArgumentParser,
    *,
    host_as_option: bool = False,
    host_optional: bool = False,
) -> None:
    """Add the arguments that every remote command needs.

    Args:
        parser: The parser to extend.
        host_as_option: When ``True`` the host is given with ``--host``
            instead of as a positional argument.  This is used by
            ``provision``, which already has other positional looking
            options and reads more clearly with explicit flags.
        host_optional: When ``True`` the host may be omitted, which is used
            by ``audit``: without a host the local configuration is audited.
    """
    if host_as_option:
        parser.add_argument("--host", required=True, help="hostname or IP address of the server")
    elif host_optional:
        parser.add_argument("host", nargs="?", help="hostname or IP address of the server")
    else:
        parser.add_argument("host", help="hostname or IP address of the server")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port")
    parser.add_argument("-u", "--user", default="root", help="username to log in as")
    parser.add_argument(
        "-i",
        "--identity",
        help="path to a private key file (implies key authentication)",
    )
    parser.add_argument(
        "--agent",
        action="store_true",
        help="use the SSH agent for authentication (default)",
    )
    parser.add_argument(
        "--password",
        help="password to authenticate with (discouraged, use a key instead)",
    )
    parser.add_argument(
        "--passphrase",
        help="passphrase protecting the private key",
    )
    parser.add_argument(
        "--known-hosts",
        default=os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts"),
        help="path to the known hosts file",
    )
    parser.add_argument(
        "--auto-accept-host-key",
        action="store_true",
        help="accept an unknown host key without verification (dangerous)",
    )
    parser.add_argument(
        "--timeout", type=float, default=15.0, help="connection timeout in seconds"
    )
    parser.add_argument(
        "--sudo-password",
        help="password used to satisfy 'sudo -S' on the remote host "
        "(defaults to the SSH password)",
    )


def _build_connection(args: argparse.Namespace) -> ConnectionConfig:
    """Build a :class:`ConnectionConfig` from the parsed arguments."""
    if args.identity:
        method = "key"
    elif args.password:
        method = "password"
    else:
        method = "agent"

    auth = AuthConfig(
        method=method,
        key_path=args.identity,
        password=args.password,
        passphrase=args.passphrase,
    )

    policy = HostKeyPolicy(
        KnownHostsStore(args.known_hosts),
        auto_accept=args.auto_accept_host_key,
    )

    sudo_password = getattr(args, "sudo_password", None)
    if sudo_password is None:
        # The SSH password is the most likely sudo password as well.
        sudo_password = auth.password

    return ConnectionConfig(
        host=args.host,
        port=args.port,
        username=args.user,
        auth=auth,
        host_key_policy=policy,
        timeout=args.timeout,
        sudo_password=sudo_password,
    )


def _connect(args: argparse.Namespace) -> SSHConnection:
    """Open a connection using the shared arguments."""
    connection = SSHConnection(_build_connection(args))
    connection.connect()
    return connection


def _write_output(text: str, stream: "io.TextIOBase") -> None:
    """Write *text* to *stream* without failing on a narrow console.

    The Windows console still uses a legacy code page by default, so text
    that is valid UTF-8 on the remote host (for example a Vietnamese log
    message) cannot be encoded and would raise ``UnicodeEncodeError``.  The
    data is replaced instead of being lost, so the command still succeeds.
    """
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        stream.write(text)
    except UnicodeEncodeError:
        safe = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
        stream.write(safe)
    except Exception:  # noqa: BLE001 - never fail because of the console
        stream.write(text.encode("ascii", errors="replace").decode("ascii"))
    try:
        stream.flush()
    except Exception:  # noqa: BLE001 - flushing is best effort
        pass


# ----------------------------------------------------------------------
# commands
# ----------------------------------------------------------------------


def cmd_ssh(args: argparse.Namespace) -> int:
    """Run a command on the remote host."""
    with _connect(args) as connection:
        if args.info:
            info = connection.get_server_info()
            print(json.dumps(info, indent=2))
            return 0

        if not args.command:
            print("Nothing to do: give a command or use --info.", file=sys.stderr)
            return 2

        result = connection.exec_command(args.command)
        if result.stdout:
            _write_output(result.stdout, sys.stdout)
        if result.stderr:
            _write_output(result.stderr, sys.stderr)
        return result.exit_status


def _split_remote_spec(spec: str) -> "Tuple[str, Optional[str]]":
    """Split a ``[user@]host:path`` specification.

    The remote path may be given in the familiar ``user@host:/path`` form.
    Only the path is used, because the connection is already established
    with the host and the user from the shared options.

    Args:
        spec: The specification to split.

    Returns:
        A tuple of the host part (empty when there is none) and the path.
    """
    if ":" not in spec:
        return "", spec

    host_part, _, path = spec.partition(":")
    # A Windows drive letter such as "C:\path" is not a host specification.
    if len(host_part) == 1 and host_part.isalpha():
        return "", spec

    return host_part, path or "/"


def cmd_scp(args: argparse.Namespace) -> int:
    """Copy files to or from the remote host.

    The two positional arguments always keep the same meaning in both
    directions: ``local_path`` is the path on this machine and
    ``remote_path`` is the path on the server.  With ``--download`` the
    transfer simply runs the other way, so the remote path is the source
    and the local path is the destination.
    """
    from .scp.client import SCPClient

    with _connect(args) as connection:
        client = SCPClient(connection, timeout=args.timeout)
        if args.download:
            # The remote path may be written as "user@host:/path"; only the
            # path part is meaningful here, because the connection is
            # already established with the host and the user.
            _, remote_path = _split_remote_spec(args.remote_path)
            result = client.get(
                remote_path,
                args.local_path,
                recursive=args.recursive,
                preserve_times=args.preserve_times,
            )
            print(
                f"Downloaded {result.count} file(s) to {args.local_path}",
                file=sys.stderr,
            )
        else:
            result = client.put(
                args.local_path,
                args.remote_path,
                recursive=args.recursive,
                preserve_times=args.preserve_times,
            )
            print(
                f"Uploaded {result.count} file(s) to {args.remote_path}",
                file=sys.stderr,
            )
    return 0


def cmd_sftp(args: argparse.Namespace) -> int:
    """Browse or transfer files over SFTP."""
    from .sftp.client import SFTPClient

    with _connect(args) as connection:
        with connection.sftp() as raw_sftp:
            client = SFTPClient(raw_sftp, root=args.root)

            if args.download:
                size = client.get(
                    args.remote_path, args.local_path, resume=args.resume
                )
                print(f"Downloaded {size} bytes to {args.local_path}", file=sys.stderr)
            elif args.upload:
                size = client.put(
                    args.local_path, args.remote_path, resume=args.resume
                )
                print(f"Uploaded {size} bytes to {args.remote_path}", file=sys.stderr)
            else:
                for info in client.listdir(args.path or "."):
                    kind = "d" if info.is_dir else "-"
                    _write_output(
                        f"{kind} {info.permissions} {info.size_human:>10} {info.name}\n",
                        sys.stdout,
                    )
    return 0


def cmd_hostkey(args: argparse.Namespace) -> int:
    """Manage the trusted host key store."""
    store = KnownHostsStore(args.known_hosts)

    if args.action == "list":
        entries = store.load()
        if not entries:
            print("No host keys are trusted yet.")
            return 0
        for entry in entries:
            print(f"{entry.hostname} {entry.key_type} {entry.fingerprint()}")
        return 0

    if args.action == "remove":
        removed = store.remove(args.hostname)
        print(f"Removed {removed} key(s) for {args.hostname}")
        return 0

    if args.action == "add":
        if not args.key_file:
            print("A key file is required to add a host key.", file=sys.stderr)
            return 2
        try:
            from .ssh.connection import load_public_key

            key = load_public_key(args.key_file)
        except BTLException as exc:
            print(str(exc), file=sys.stderr)
            return 1
        entry = store.add(
            args.hostname, key.get_name(), key.get_base64(), port=args.port
        )
        print(f"Trusted {entry.key_type} {entry.fingerprint()} for {args.hostname}")
        return 0

    return 2


def _remote_sshd_config(args: argparse.Namespace) -> "dict[str, str]":
    """Read the effective sshd configuration from a remote host.

    ``sshd -T`` prints the configuration as sshd would interpret it, after
    every drop-in file has been merged.  It has to run on the target host.

    Args:
        args: The parsed arguments of the ``audit`` command.

    Returns:
        A mapping of directive name to effective value.

    Raises:
        BTLException: If the remote command fails or cannot be parsed.
    """
    with _connect(args) as connection:
        result = connection.exec_command(
            "sudo -S -p '' sshd -T",
            stdin_data=getattr(connection.config, "sudo_password", None) or "",
        )

    if result.exit_status != 0:
        raise BTLException(
            f"'sshd -T' failed on {args.host} with status {result.exit_status}: "
            f"{result.stderr.strip()}"
        )

    effective: "dict[str, str]" = {}
    for line in result.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            effective[parts[0].lower()] = parts[1].strip()
    return effective


def cmd_audit(args: argparse.Namespace) -> int:
    """Audit the effective sshd configuration against the baseline.

    Without a host the local configuration is audited.  With a host the
    effective configuration is read over SSH with ``sshd -T``, which is the
    only way to see the merged result of every drop-in file.
    """
    remote = getattr(args, "host", None)

    if remote:
        try:
            effective = _remote_sshd_config(args)
        except BTLException as exc:
            print(str(exc), file=sys.stderr)
            return 1
    else:
        try:
            effective = sshd_effective_config()
        except BTLException as exc:
            print(str(exc), file=sys.stderr)
            return 1

    findings = audit_config(effective)
    counts = summarize(findings)

    if args.json:
        print(json.dumps({"findings": findings, "summary": counts}, indent=2))
    else:
        for finding in findings:
            if finding["status"] == "ok":
                continue
            print(
                f"[{finding['status'].upper():>8}] {finding['directive']}: "
                f"expected {finding['expected']!r}, got {finding['actual']!r}"
            )
        print()
        print(
            f"Checked {len(findings)} directives: "
            f"{counts.get('ok', 0)} compliant, "
            f"{counts.get('weak', 0)} weak, "
            f"{counts.get('missing', 0)} missing."
        )

    return 0 if counts.get("weak", 0) == 0 and counts.get("missing", 0) == 0 else 1


def cmd_render(args: argparse.Namespace) -> int:
    """Render the configuration files without touching a server."""
    policy = SSHDPolicy(
        port=args.port,
        allowed_groups=args.groups.split(",") if args.groups else ["sshusers"],
        allowed_users=args.users.split(",") if args.users else [],
    )

    if args.what == "sshd":
        print(policy.to_config())
    elif args.what == "sshd-sftp":
        print(policy.to_sftp_match_block(args.sftp_users.split(",") if args.sftp_users else []))
    elif args.what == "fail2ban":
        print(
            Fail2BanPolicy(port=args.port).to_config()
        )
    elif args.what == "firewall":
        print(
            FirewallPolicy(ssh_port=args.port).to_script()
        )
    elif args.what == "audit":
        print(AuditPolicy().to_rules())
    return 0


def _read_public_key(path: Optional[str]) -> str:
    """Read a public key from *path*.

    Args:
        path: The path of the ``.pub`` file, or ``None``.

    Returns:
        The key as a single line, or an empty string when no path was given.

    Raises:
        ConfigError: If the file cannot be read.
    """
    if not path:
        return ""

    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except OSError as exc:
        raise ConfigError(f"could not read the public key {path}: {exc}") from exc

    raise ConfigError(f"the public key file {path} does not contain a key")


def cmd_provision(args: argparse.Namespace) -> int:
    """Configure a fresh Ubuntu host."""
    from .provision.provisioner import (
        ProvisionPlan,
        build_admin_script,
        build_apply_script,
        build_install_script,
        build_sftp_script,
        run_script,
        write_file_over_ssh,
    )

    plan = ProvisionPlan()
    plan.sshd_policy = SSHDPolicy(
        port=args.port, allowed_groups=[args.group]
    )
    plan.fail2ban_policy = Fail2BanPolicy(port=args.port)

    # The management network has to be excluded from the ban list.  The
    # end to end test deliberately probes the access control with invalid
    # accounts, and the 'aggressive' mode would otherwise ban the
    # administrator's own address.
    ignored = [ip.strip() for ip in args.fail2ban_ignore.split(",") if ip.strip()]
    if ignored:
        plan.fail2ban_policy.ignore_ip = (
            list(plan.fail2ban_policy.ignore_ip) + ignored
        )

    plan.firewall_policy = FirewallPolicy(
        ssh_port=args.port,
        rate_limit_ssh=args.ufw_limit_ssh,
    )
    plan.admin_users = [u for u in args.admin_users.split(",") if u]
    plan.sftp_users = [u for u in args.sftp_users.split(",") if u]
    # The account that drives the provisioning keeps its access, otherwise
    # the hardened AllowGroups directive would lock the operator out.
    plan.keep_access_user = args.user

    admin_public_key = _read_public_key(args.admin_public_key)
    if admin_public_key:
        for user in plan.admin_users:
            plan.admin_public_keys[user] = [admin_public_key]

    sftp_public_key = _read_public_key(args.sftp_public_key)
    if sftp_public_key:
        for user in plan.sftp_users:
            plan.sftp_public_keys[user] = [sftp_public_key]

    plan.validate()

    if args.dry_run:
        for path, content in plan.render_scripts().items():
            print(f"===== {path} =====")
            print(content)
        print("===== admin accounts =====")
        print(build_admin_script(plan))
        print("===== sftp accounts =====")
        print(build_sftp_script(plan))
        return 0

    with _connect(args) as connection:
        print("Installing packages...", file=sys.stderr)
        run_script(connection, build_install_script())

        print("Creating accounts...", file=sys.stderr)
        run_script(connection, build_admin_script(plan))
        run_script(connection, build_sftp_script(plan))

        print("Writing configuration...", file=sys.stderr)
        for path, content in plan.render_scripts().items():
            write_file_over_ssh(connection, path, content)

        print("Applying configuration...", file=sys.stderr)
        run_script(connection, build_apply_script(plan))

        # The firewall is applied last.  ufw's default incoming policy is
        # "deny", so enabling it before the SSH rule exists would lock the
        # operator out of the machine for good.
        if not args.no_firewall:
            print("Applying the firewall...", file=sys.stderr)
            run_script(connection, plan.firewall_policy.to_script())

    print("Provisioning complete. Verify with: btl audit <host>", file=sys.stderr)
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    """Start the graphical interface.

    The interface is a small web application that is served on the loopback
    address by default.  It drives exactly the same modules as the rest of
    the command line tool, so the host key policy and the path confinement
    are identical.
    """
    from .gui.server import GuiServer
    from .gui.service import Service

    service = Service(
        known_hosts=args.known_hosts,
        downloads_dir=args.downloads_dir,
    )
    server = GuiServer(host=args.host, port=args.port, service=service)

    if server.port_in_use():
        print(
            f"error: the port {args.port} on {args.host} is already in use",
            file=sys.stderr,
        )
        return 1

    print(f"The interface is available at {server.url}", file=sys.stderr)
    print("Press Ctrl+C to stop it.", file=sys.stderr)

    if args.open:
        import threading
        import webbrowser

        threading.Timer(1.0, lambda: webbrowser.open(server.url)).start()

    try:
        server.serve_forever()
    except OSError as exc:
        print(f"error: could not start the interface: {exc}", file=sys.stderr)
        return 1
    return 0


# ----------------------------------------------------------------------
# parser
# ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the top level argument parser."""
    parser = argparse.ArgumentParser(
        prog="btl",
        description="Secured Network Service Configuration with SCP, SFTP and SSH",
    )
    parser.add_argument("--version", action="version", version=f"btl {__version__}")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable debug logging",
    )
    parser.add_argument(
        "--log-file", help="also write the log to this file"
    )

    subparsers = parser.add_subparsers(dest="command_name", required=True)

    def _sub(name: str, **kwargs) -> argparse.ArgumentParser:
        """Register a sub parser and remember it for argument reassignment."""
        sub = subparsers.add_parser(name, **kwargs)
        sub.set_defaults(_subparser=sub)
        return sub

    # ssh
    ssh_parser = _sub("ssh", help="run a command over SSH")
    _add_connection_arguments(ssh_parser)
    ssh_parser.add_argument(
        "--info",
        action="store_true",
        help="print the server's SSH capabilities and exit",
    )
    ssh_parser.add_argument("command", nargs="?", help="the command to run")
    ssh_parser.set_defaults(func=cmd_ssh)

    # scp
    scp_parser = _sub("scp", help="copy files over SSH")
    _add_connection_arguments(scp_parser)
    scp_parser.add_argument(
        "-r", "--recursive", action="store_true", help="copy directories"
    )
    scp_parser.add_argument(
        "--preserve-times",
        action="store_true",
        help="preserve the modification times",
    )
    scp_parser.add_argument(
        "--download",
        action="store_true",
        help="download instead of upload; the remote path is the source "
        "and the local path is the destination",
    )
    scp_parser.add_argument("local_path", help="the local path")
    scp_parser.add_argument("remote_path", help="the remote path")
    scp_parser.set_defaults(func=cmd_scp)

    # sftp
    sftp_parser = _sub("sftp", help="transfer files over SFTP")
    _add_connection_arguments(sftp_parser)
    sftp_parser.add_argument(
        "--root", help="restrict every path to this directory on the server"
    )
    sftp_parser.add_argument(
        "--download", action="store_true", help="download a file"
    )
    sftp_parser.add_argument(
        "--upload", action="store_true", help="upload a file"
    )
    sftp_parser.add_argument(
        "--resume", action="store_true", help="resume an interrupted transfer"
    )
    sftp_parser.add_argument(
        "--path", default=".", help="the remote directory to list"
    )
    sftp_parser.add_argument("local_path", nargs="?", help="the local file")
    sftp_parser.add_argument("remote_path", nargs="?", help="the remote file")
    sftp_parser.set_defaults(func=cmd_sftp)

    # hostkey
    hostkey_parser = _sub("hostkey", help="manage the trusted host key store")
    hostkey_parser.add_argument(
        "--known-hosts",
        default=os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts"),
        help="path to the known hosts file",
    )
    hostkey_parser.add_argument("action", choices=["list", "add", "remove"])
    hostkey_parser.add_argument("hostname", nargs="?", help="the host name")
    hostkey_parser.add_argument("--port", type=int, default=22)
    hostkey_parser.add_argument("--key-file", help="the public key file to trust")
    hostkey_parser.set_defaults(func=cmd_hostkey)

    # audit
    audit_parser = _sub(
        "audit", help="audit the sshd configuration on the local host or a server"
    )
    audit_parser.add_argument(
        "--json", action="store_true", help="print the findings as JSON"
    )
    # The host is optional: without it the local configuration is audited.
    _add_connection_arguments(audit_parser, host_optional=True)
    audit_parser.set_defaults(func=cmd_audit)

    # render
    render_parser = _sub(
        "render", help="render a configuration file without touching a server"
    )
    render_parser.add_argument(
        "what",
        choices=["sshd", "sshd-sftp", "fail2ban", "firewall", "audit"],
        help="which file to render",
    )
    render_parser.add_argument("--port", type=int, default=22)
    render_parser.add_argument("--groups", help="comma separated allowed groups")
    render_parser.add_argument("--users", help="comma separated allowed users")
    render_parser.add_argument(
        "--sftp-users", help="comma separated SFTP-only accounts"
    )
    render_parser.set_defaults(func=cmd_render)

    # provision
    provision_parser = _sub("provision", help="configure a fresh Ubuntu host")
    _add_connection_arguments(provision_parser, host_as_option=True)
    provision_parser.add_argument("--group", default="sshusers")
    provision_parser.add_argument(
        "--admin-users", default="", help="comma separated administrator accounts"
    )
    provision_parser.add_argument(
        "--sftp-users", default="", help="comma separated SFTP-only accounts"
    )
    provision_parser.add_argument(
        "--admin-public-key",
        help="public key installed for the administrator accounts",
    )
    provision_parser.add_argument(
        "--sftp-public-key",
        help="public key installed for the SFTP-only accounts",
    )
    provision_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be done without changing anything",
    )
    provision_parser.add_argument(
        "--no-firewall",
        action="store_true",
        help="do not configure ufw (useful when the firewall would lock you out)",
    )
    provision_parser.add_argument(
        "--fail2ban-ignore",
        default="",
        help="comma separated addresses that fail2ban must never ban, "
        "for example the management network",
    )
    provision_parser.add_argument(
        "--ufw-limit-ssh",
        action="store_true",
        help="use 'ufw limit' for the SSH port instead of 'ufw allow'; "
        "this rejects more than six new connections per 30 seconds from one "
        "address, so it also blocks legitimate administrative bursts",
    )
    provision_parser.set_defaults(func=cmd_provision)

    # gui
    gui_parser = _sub("gui", help="start the graphical interface in the browser")
    gui_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="address to bind the interface to; use 0.0.0.0 to make it "
        "reachable from other machines (the interface can run commands "
        "and accepts credentials, so keep it on the loopback address)",
    )
    gui_parser.add_argument(
        "--port", type=int, default=8765, help="port to listen on"
    )
    gui_parser.add_argument(
        "--open", action="store_true", help="open the interface in a browser"
    )
    gui_parser.add_argument(
        "--known-hosts",
        default="",
        help="path to the trusted host key store (defaults to ~/.ssh/known_hosts)",
    )
    gui_parser.add_argument(
        "--downloads-dir",
        default="",
        help="directory that receives the files downloaded from a server",
    )
    gui_parser.set_defaults(func=cmd_gui)

    return parser


def _parse_args(parser: argparse.ArgumentParser, argv: List[str]) -> argparse.Namespace:
    """Parse the command line, allowing options after positional arguments.

    ``argparse`` stops assigning positional arguments as soon as it meets an
    option, so ``btl ssh host -u user uptime`` would leave ``uptime``
    unrecognised.  The command line of an SSH tool is naturally written that
    way, so the leftover values are collected and assigned to the trailing
    positional arguments in order.

    Args:
        parser: The parser to use.
        argv: The arguments to parse.

    Returns:
        The parsed arguments.

    Raises:
        SystemExit: If the arguments are invalid.
    """
    args, leftover = parser.parse_known_args(argv)

    if leftover:
        # The positional arguments of the sub command, in the order they
        # were declared.  Only the ones that argparse could not fill are
        # considered: the values it did assign stay untouched.
        sub = getattr(args, "_subparser", None)
        source = sub if sub is not None else parser
        positionals = [
            action
            for action in source._actions
            if not action.option_strings and action.nargs != argparse.SUPPRESS
        ]

        free = [
            action
            for action in positionals
            if getattr(args, action.dest, None) in (None, "")
        ]

        if len(leftover) > len(free):
            parser.error(f"unrecognized arguments: {' '.join(leftover)}")

        for action, value in zip(free, leftover):
            setattr(args, action.dest, value)

    return args


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for the command line interface.

    Args:
        argv: The arguments to parse.  Defaults to ``sys.argv[1:]``.

    Returns:
        The process exit code.
    """
    parser = build_parser()
    args = _parse_args(parser, list(sys.argv[1:] if argv is None else argv))

    setup_logging(
        level="DEBUG" if args.verbose else "INFO",
        log_file=args.log_file,
    )

    try:
        return args.func(args)
    except BTLException as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
