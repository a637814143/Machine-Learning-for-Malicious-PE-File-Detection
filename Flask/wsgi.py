"""WSGI entry point for production servers (uWSGI, Gunicorn, etc.)."""
from __future__ import annotations

from . import create_app

# WSGI servers such as uWSGI and Gunicorn look for a module-level object named
# ``application`` by default. Importing via ``create_app`` ensures all factory
# configuration (templates, static assets, proxy fixes, etc.) remains centralised
# in ``Flask.__init__``.
application = create_app()

__all__ = ["application"]
