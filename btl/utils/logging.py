"""Logging configuration.

The project uses a single :func:`setup_logging` entry point so that library
code never configures the root logger on import.  Libraries emit records
through :func:`get_logger`; only the CLI decides where records are rendered.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional

_CONFIGURED = False
_DEFAULT_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%dT%H:%M:%S%z"

#: Environment variable that may point at a file to receive the log output.
LOG_ENV_VAR = "BTL_LOG_FILE"

#: Environment variable holding the minimum level name, e.g. ``DEBUG``.
LOG_LEVEL_ENV_VAR = "BTL_LOG_LEVEL"


def _resolve_level(level: "int | str | None") -> int:
    """Resolve *level* (name or number) into a numeric logging level."""
    if level is None:
        level = os.environ.get(LOG_LEVEL_ENV_VAR, "INFO")
    if isinstance(level, int):
        return level
    resolved = logging.getLevelName(str(level).upper())
    if isinstance(resolved, int):
        return resolved
    raise ValueError(f"unknown log level: {level!r}")


def setup_logging(
    level: "int | str | None" = None,
    log_file: "Optional[str]" = None,
    stream: "object | None" = None,
    force: bool = False,
) -> logging.Logger:
    """Configure the ``btl`` logger hierarchy.

    Args:
        level: Minimum level to emit.  Defaults to ``$BTL_LOG_LEVEL`` then
            ``INFO``.
        log_file: Optional path to append records to.  Defaults to
            ``$BTL_LOG_FILE`` when that variable is set.
        stream: Stream for console output.  Defaults to ``sys.stderr`` so that
            command output on stdout stays machine readable.
        force: Reconfigure even if logging was already configured.

    Returns:
        The configured root logger for this project.
    """
    global _CONFIGURED

    if _CONFIGURED and not force:
        return logging.getLogger("btl")

    resolved_level = _resolve_level(level)
    resolved_file = log_file or os.environ.get(LOG_ENV_VAR)

    root = logging.getLogger("btl")
    root.setLevel(resolved_level)
    root.propagate = False

    # Reset handlers so repeated calls (e.g. in tests) do not duplicate output.
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter(fmt=_DEFAULT_FORMAT, datefmt=_DEFAULT_DATEFMT)

    console = logging.StreamHandler(stream if stream is not None else sys.stderr)
    console.setLevel(resolved_level)
    console.setFormatter(formatter)
    root.addHandler(console)

    if resolved_file:
        directory = os.path.dirname(os.path.abspath(resolved_file))
        if directory:
            os.makedirs(directory, exist_ok=True)
        file_handler = logging.FileHandler(resolved_file, encoding="utf-8")
        file_handler.setLevel(resolved_level)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    _CONFIGURED = True
    return root


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``btl`` namespace.

    Names that already start with ``btl`` are used verbatim; anything else is
    nested underneath it so that :func:`setup_logging` controls the output.
    """
    if not name or name == "btl":
        return logging.getLogger("btl")
    if name.startswith("btl."):
        return logging.getLogger(name)
    return logging.getLogger(f"btl.{name}")


__all__ = ["get_logger", "setup_logging", "LOG_ENV_VAR", "LOG_LEVEL_ENV_VAR"]
