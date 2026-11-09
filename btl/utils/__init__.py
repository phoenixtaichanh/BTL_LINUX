"""Shared utilities: logging, errors, path safety and small helpers."""

from .errors import (
    BTLException,
    AuthError,
    ConfigError,
    HostKeyError,
    PermissionDeniedError,
    ProtocolError,
    SCPError,
    SFTPError,
    ValidationError,
)
from .logging import get_logger, setup_logging
from .paths import (
    SafePath,
    is_within,
    normalize_remote_path,
    sanitize_filename,
)

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
    "get_logger",
    "setup_logging",
    "SafePath",
    "is_within",
    "normalize_remote_path",
    "sanitize_filename",
]
