"""BTL - Secured Network Service Configuration with SCP, SFTP and SSH.

This package provides:

* :mod:`btl.ssh` - hardened SSH transport with strict host key verification.
* :mod:`btl.scp` - a from scratch implementation of the SCP protocol.
* :mod:`btl.sftp` - an SFTP client with a virtual root and a confined server.
* :mod:`btl.security` - the server hardening configuration and its audit.
* :mod:`btl.provision` - idempotent provisioning for the target Ubuntu host.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
