"""Flask service exposing the malicious PE detection logic used by the GUI."""
from __future__ import annotations

from flask import Flask

from .routes import register_routes


def create_app() -> Flask:
    """Application factory used by the CLI or a WSGI server.

    The factory keeps the Flask setup in one place and makes it easy to
    integrate the service with deployment tooling.
    """

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/static",
    )
    register_routes(app)
    return app


__all__ = ["create_app"]
