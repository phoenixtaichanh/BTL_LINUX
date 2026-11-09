"""The graphical interface of the BTL toolkit.

The interface is a small web application that is served by
:mod:`btl.gui.server`.  It is written with plain HTML, CSS and JavaScript
so that it runs on any machine that can run the core project, without a
build step and without a JavaScript tool chain.

The modules are:

``service``
    The application logic, shared with the command line tool.
``api``
    The JSON request dispatcher.
``server``
    The HTTP server.
"""

from __future__ import annotations

from .server import GuiServer, make_handler
from .service import ConnectionSettings, ProvisionSettings, Service, Session

__all__ = [
    "ConnectionSettings",
    "GuiServer",
    "ProvisionSettings",
    "Service",
    "Session",
    "make_handler",
]
