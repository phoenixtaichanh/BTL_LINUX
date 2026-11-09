"""Exception hierarchy for the BTL network service toolkit.

Every exception raised by this project inherits from :class:`BTLException` so
callers can catch a single base class and still discriminate on the specific
subclass when they need to.
"""

from __future__ import annotations


class BTLException(Exception):
    """Base class for every error raised by this project."""


class ConfigError(BTLException):
    """Raised when a configuration file is missing, malformed or inconsistent."""


class ValidationError(BTLException):
    """Raised when user supplied input fails validation."""


class AuthError(BTLException):
    """Raised when SSH authentication fails or credentials are rejected."""


class HostKeyError(BTLException):
    """Raised when a host key is unknown, changed or otherwise unacceptable."""


class PermissionDeniedError(BTLException):
    """Raised when the remote side refuses an operation for policy reasons.

    This is deliberately distinct from :class:`AuthError`: authentication may
    have succeeded, but a policy (chroot jail, forced command, forced SFTP)
    still blocks the requested action.
    """


class ProtocolError(BTLException):
    """Raised when a wire protocol handshake or framing is malformed."""


class SCPError(ProtocolError):
    """Raised for SCP protocol specific failures."""


class SFTPError(ProtocolError):
    """Raised for SFTP specific failures."""


__all__ = [
    "BTLException",
    "AuthError",
    "ConfigError",
    "HostKeyError",
    "PermissionDeniedError",
    "ProtocolError",
    "SCPError",
    "SFTPError",
    "ValidationError",
]
