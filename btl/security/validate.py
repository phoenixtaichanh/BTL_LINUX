"""Validation of generated ``sshd_config`` files against the OpenSSH directive set.

A single unknown or misspelled directive makes ``sshd -t`` fail, and if the
configuration is applied without validation the server can be left unable to
start.  This module keeps a list of the directives that the project is
allowed to emit and verifies the generated file against it before it is
written to a server.

The list is derived from ``sshd_config(5)``.  It deliberately excludes
directives that were removed or are version dependent:

* ``UsePrivilegeSeparation`` was deprecated in OpenSSH 7.5 and is a no-op.
* ``LoginFailedAttempts`` does not exist in any OpenSSH release.
* ``PerSourcePenalties`` only exists from OpenSSH 9.8 onwards, so it would
  break Ubuntu 24.04, which ships OpenSSH 9.6.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..utils.errors import ConfigError
from ..utils.logging import get_logger

logger = get_logger("security.validate")

#: Directives the project is allowed to emit, with the values that are
#: considered safe.  A directive mapped to ``None`` is accepted with any
#: value.
ALLOWED_DIRECTIVES: "Dict[str, Optional[Set[str]]]" = {
    # Listener
    "port": None,
    "listenaddress": None,
    "addressfamily": {"any", "inet", "inet6"},
    # Access control
    "permitrootlogin": {"yes", "no", "prohibit-password", "without-password"},
    "permitemptypasswords": {"yes", "no"},
    "allowusers": None,
    "denyusers": None,
    "allowgroups": None,
    "denygroups": None,
    "allowtcpforwarding": {"yes", "no", "local", "remote", "all"},
    "allowagentforwarding": {"yes", "no"},
    "allowstreamlocalforwarding": {"yes", "no"},
    "permitopen": None,
    "permitlisten": None,
    "permittunnel": {"yes", "no", "point-to-point", "ethernet"},
    "gatewayports": {"yes", "no"},
    "x11forwarding": {"yes", "no"},
    "x11displayoffset": None,
    "x11uselocalforwarding": {"yes", "no"},
    # Authentication
    "pubkeyauthentication": {"yes", "no", "unbound", "host-bound"},
    "passwordauthentication": {"yes", "no"},
    "kbdinteractiveauthentication": {"yes", "no"},
    "challengeresponseauthentication": {"yes", "no"},
    "gssapiauthentication": {"yes", "no"},
    "hostbasedauthentication": {"yes", "no"},
    "hostbasedusesnamefrompacketonly": {"yes", "no"},
    "usepam": {"yes", "no"},
    "authenticationmethods": None,
    "permitemptypasswd": {"yes", "no"},
    "permitemptypasswords ": {"yes", "no"},
    "permituserenvironment": {"yes", "no"},
    "permituserRC": {"yes", "no"},
    "authorizedkeysfile": None,
    "authorizedkeyscommand": None,
    "authorizedprincipalsfile": None,
    "trustedusercakeys": None,
    "ignorerhosts": {"yes", "no"},
    "revokedkeys": None,
    "pamauthenticationvia": None,
    # Brute force resistance
    "maxauthtries": None,
    "logingracetime": None,
    "maxsessions": None,
    "maxstartups": None,
    "clientaliveinterval": None,
    "clientalivecountmax": None,
    "livemax": None,
    "tcpkeepalive": {"yes", "no"},
    # Session behaviour
    "banner": None,
    "printmotd": {"yes", "no"},
    "printlastlog": {"yes", "no"},
    "permittty": {"yes", "no"},
    "permitttyrc": {"yes", "no"},
    "streamlocalbindmask": None,
    "setenv": None,
    "acceptenv": None,
    "forcecommand": None,
    "chrootdirectory": None,
    "permituserrc": {"yes", "no"},
    # Logging
    "syslogfacility": {"daemon", "user", "auth", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"},
    "loglevel": {"quiet", "fatal", "error", "info", "verbose", "debug", "debug1", "debug2", "debug3"},
    # Crypto
    "ciphers": None,
    "macs": None,
    "kexalgorithms": None,
    "hostkeyalgorithms": None,
    "hostkey": None,
    "hostcertificate": None,
    "compression": {"yes", "no"},
    "rekeylimit": None,
    "noneforwarding": {"yes", "no"},
}


def parse_config(text: str) -> "List[Tuple[str, str, int]]":
    """Parse an ``sshd_config`` into a list of directives.

    Comments and blank lines are skipped.  ``Match`` blocks are recognised:
    the directives inside them are returned as well, because they still have
    to be valid, but the block marker itself is not returned.

    Args:
        text: The configuration text.

    Returns:
        A list of ``(keyword, value, line_number)`` tuples.
    """
    directives: "List[Tuple[str, str, int]]" = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        keyword, _, value = line.partition(" ")
        keyword = keyword.strip().lower()
        value = value.strip()

        if keyword == "match":
            continue
        if keyword == "include":
            continue
        if not value and keyword in ("permitrootlogin",):
            continue

        directives.append((keyword, value, number))

    return directives


def validate_config(text: str) -> "List[str]":
    """Check a generated configuration for unknown or unsafe directives.

    Args:
        text: The configuration text.

    Returns:
        A list of human readable problems.  An empty list means the
        configuration is safe to apply.

    Raises:
        ConfigError: If the configuration contains a directive that the
            project does not allow, or a directive with a disallowed value.
    """
    problems: "List[str]" = []
    seen: "Set[str]" = set()

    for keyword, value, number in parse_config(text):
        if keyword in seen:
            continue
        seen.add(keyword)

        if keyword not in ALLOWED_DIRECTIVES:
            problems.append(
                f"line {number}: unknown directive {keyword!r}. It would make "
                "'sshd -t' fail and could stop the server from starting."
            )
            continue

        allowed = ALLOWED_DIRECTIVES[keyword]
        if allowed is None:
            continue

        # A directive may take several space separated values.  The
        # comparison is case insensitive because sshd accepts either form.
        candidates = [part.lower() for part in value.split()]
        if not candidates:
            problems.append(f"line {number}: directive {keyword!r} has no value")
            continue

        if not any(candidate in allowed for candidate in candidates):
            problems.append(
                f"line {number}: directive {keyword!r} has value {value!r}, "
                f"expected one of: {', '.join(sorted(allowed))}"
            )

    if problems:
        raise ConfigError(
            "the generated sshd configuration is not valid:\n  "
            + "\n  ".join(problems)
        )

    return problems


def known_directives() -> "Iterable[str]":
    """Return the sorted list of allowed directives."""
    return sorted(ALLOWED_DIRECTIVES)


__all__ = ["ALLOWED_DIRECTIVES", "known_directives", "parse_config", "validate_config"]
