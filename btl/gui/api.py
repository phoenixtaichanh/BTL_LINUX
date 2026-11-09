"""The JSON API of the graphical interface.

Every request from the browser is a POST to ``/api/<action>`` with a JSON
body.  The response is always a JSON object with an ``ok`` key, so the
browser can show the error of a failed operation without having to parse
the HTTP status.

The handler deliberately knows nothing about the core modules: it only
translates a request into a call on the :class:`~btl.gui.service.Service`
and turns the result or the exception into a response.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, Optional

from ..utils.errors import BTLException, ConfigError
from ..utils.logging import get_logger
from .service import Service, Session

logger = get_logger("gui.api")


def _as_bool(value: Any, default: bool = False) -> bool:
    """Interpret a JSON value as a boolean."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off", ""):
        return False
    return default


def _as_int(value: Any, default: int = 0) -> int:
    """Interpret a JSON value as an integer."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    """Interpret a JSON value as a float."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_str(value: Any, default: str = "") -> str:
    """Interpret a JSON value as a string."""
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


class Api:
    """Dispatches the JSON requests of the browser to the service layer.

    Args:
        service: The application service that holds the session.
    """

    def __init__(self, service: Service) -> None:
        self.service = service

    # -- dispatch --------------------------------------------------------

    def dispatch(self, action: str, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Run the action named *action*.

        Args:
            action: The name of the action, without the ``api/`` prefix.
            payload: The decoded request body.

        Returns:
            The result of the action.

        Raises:
            ConfigError: If the action is unknown.
        """
        handler = getattr(self, f"_action_{action.replace('-', '_')}", None)
        if handler is None or not action.replace("-", "_").isidentifier():
            raise ConfigError(f"unknown action: {action!r}")
        return handler(payload)

    # -- session ---------------------------------------------------------

    def _action_state(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Return the state of the session."""
        state = self.service.session.state()
        state["defaults"] = self.service.defaults()
        return state

    def _action_connect(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Open an SSH connection."""
        settings = self._settings_from(payload)
        return self.service.session.connect(settings)

    def _action_disconnect(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Close the SSH connection."""
        return self.service.session.disconnect()

    def _settings_from(self, payload: "Dict[str, Any]") -> "Any":
        """Build the connection settings from a request body."""
        from .service import ConnectionSettings

        known_hosts = _as_str(payload.get("known_hosts")).strip()
        if not known_hosts:
            known_hosts = self.service.default_known_hosts()

        return ConnectionSettings(
            host=_as_str(payload.get("host")).strip(),
            port=_as_int(payload.get("port"), 22),
            username=_as_str(payload.get("username")).strip() or "root",
            auth_method=_as_str(payload.get("auth_method")).strip() or "key",
            key_path=_as_str(payload.get("key_path")).strip(),
            passphrase=_as_str(payload.get("passphrase")),
            password=_as_str(payload.get("password")),
            known_hosts=known_hosts,
            auto_accept_host_key=_as_bool(payload.get("auto_accept_host_key")),
            timeout=_as_float(payload.get("timeout"), 15.0),
            sudo_password=_as_str(payload.get("sudo_password")),
        )

    # -- server ----------------------------------------------------------

    def _action_server_info(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Return the SSH capabilities of the connected server."""
        return self.service.session.server_info()

    def _action_run(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Run a command on the connected server."""
        return self.service.session.run_command(_as_str(payload.get("command")))

    def _action_audit(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Audit the sshd configuration."""
        scope = _as_str(payload.get("scope")).strip() or "remote"
        return self.service.session.audit(scope)

    # -- SFTP ------------------------------------------------------------

    def _action_sftp_list(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """List a remote directory."""
        return self.service.session.sftp_list(
            _as_str(payload.get("path")).strip() or ".",
            _as_str(payload.get("root")).strip(),
        )

    def _action_sftp_read(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Read a remote text file."""
        return self.service.session.sftp_read(
            _as_str(payload.get("path")).strip(),
            _as_str(payload.get("root")).strip(),
            _as_int(payload.get("max_bytes"), 512 * 1024),
        )

    def _action_sftp_upload(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Upload a file that was chosen in the browser."""
        return self.service.session.sftp_upload(
            _as_str(payload.get("local_path")).strip(),
            _as_str(payload.get("remote_path")).strip(),
            _as_str(payload.get("root")).strip(),
            _as_bool(payload.get("resume")),
        )

    def _action_sftp_upload_inline(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Upload the bytes that the browser sent to the server."""
        import base64
        import binascii

        raw = _as_str(payload.get("content_b64"))
        if not raw:
            raise ConfigError("the request carries no file content")
        try:
            content = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ConfigError(f"the file content is not valid base64: {exc}") from exc

        return self.service.session.sftp_upload_inline(
            _as_str(payload.get("remote_path")).strip(),
            content,
            _as_str(payload.get("root")).strip(),
        )

    def _action_sftp_download(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Download a remote file to the server running the interface."""
        return self.service.session.sftp_download(
            _as_str(payload.get("remote_path")).strip(),
            _as_str(payload.get("local_path")).strip(),
            _as_str(payload.get("root")).strip(),
            _as_bool(payload.get("resume")),
        )

    # -- SCP -------------------------------------------------------------

    def _action_scp_upload(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Upload a local path over SCP."""
        return self.service.session.scp_upload(
            _as_str(payload.get("local_path")).strip(),
            _as_str(payload.get("remote_path")).strip(),
            _as_bool(payload.get("recursive")),
            _as_bool(payload.get("preserve_times")),
        )

    def _action_scp_download(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Download a remote path over SCP."""
        return self.service.session.scp_download(
            _as_str(payload.get("remote_path")).strip(),
            _as_str(payload.get("local_path")).strip(),
            _as_bool(payload.get("recursive")),
            _as_bool(payload.get("preserve_times")),
        )

    # -- host keys -------------------------------------------------------

    def _action_hostkey_list(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """List the trusted host keys."""
        known_hosts = _as_str(payload.get("known_hosts")).strip()
        return self.service.session.hostkey_list(known_hosts)

    def _action_hostkey_add(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Trust a new host key."""
        return self.service.session.hostkey_add(
            _as_str(payload.get("hostname")).strip(),
            _as_str(payload.get("key_file")).strip(),
            _as_int(payload.get("port"), 22),
            _as_str(payload.get("known_hosts")).strip(),
        )

    def _action_hostkey_remove(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Remove the trusted keys of a host."""
        return self.service.session.hostkey_remove(
            _as_str(payload.get("hostname")).strip(),
            _as_int(payload.get("port"), 22),
            _as_str(payload.get("known_hosts")).strip(),
        )

    # -- configuration ---------------------------------------------------

    def _action_render(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Render a configuration file."""
        return self.service.session.render(
            _as_str(payload.get("what")).strip(),
            _as_int(payload.get("port"), 22),
            _as_str(payload.get("groups")).strip() or "sshusers",
            _as_str(payload.get("users")).strip(),
            _as_str(payload.get("sftp_users")).strip(),
        )

    def _action_provision_preview(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Render the provisioning plan without applying it."""
        return self.service.session.provision_preview(self._provision_from(payload))

    def _action_provision_apply(self, payload: "Dict[str, Any]") -> "Dict[str, Any]":
        """Apply the provisioning plan to the connected server."""
        return self.service.session.provision_apply(self._provision_from(payload))

    def _provision_from(self, payload: "Dict[str, Any]") -> "Any":
        """Build the provisioning settings from a request body."""
        from .service import ProvisionSettings

        return ProvisionSettings(
            group=_as_str(payload.get("group")).strip() or "sshusers",
            admin_users=_as_str(payload.get("admin_users")).strip(),
            sftp_users=_as_str(payload.get("sftp_users")).strip(),
            admin_public_key=_as_str(payload.get("admin_public_key")).strip(),
            sftp_public_key=_as_str(payload.get("sftp_public_key")).strip(),
            fail2ban_ignore=_as_str(payload.get("fail2ban_ignore")).strip(),
            ufw_limit_ssh=_as_bool(payload.get("ufw_limit_ssh")),
            no_firewall=_as_bool(payload.get("no_firewall")),
        )


def error_response(exc: Exception) -> "Dict[str, Any]":
    """Build the response body for a failed operation.

    Args:
        exc: The exception that was raised.

    Returns:
        A response body with ``ok`` set to ``False``.
    """
    if isinstance(exc, BTLException):
        message = str(exc)
        kind = type(exc).__name__
    elif isinstance(exc, OSError):
        message = str(exc)
        kind = "OSError"
    else:
        message = f"{type(exc).__name__}: {exc}"
        kind = type(exc).__name__

    logger.warning("request failed: %s", message)
    return {"ok": False, "error": message, "kind": kind}


__all__ = ["Api", "error_response"]
