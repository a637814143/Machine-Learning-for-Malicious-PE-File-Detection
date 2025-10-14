"""Flask service exposing the malicious PE detection logic used by the GUI."""
from __future__ import annotations

import os

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

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

    try:
        proxy_hops = int(os.getenv("PE_SENTINEL_TRUSTED_PROXY_HOPS", "1"))
    except ValueError:
        proxy_hops = 1

    if proxy_hops > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=proxy_hops,
            x_proto=proxy_hops,
            x_host=proxy_hops,
            x_port=proxy_hops,
            x_prefix=proxy_hops,
        )

    app.config.setdefault("PREFERRED_URL_SCHEME", "https")
    register_routes(app)
    return app


__all__ = ["create_app"]
