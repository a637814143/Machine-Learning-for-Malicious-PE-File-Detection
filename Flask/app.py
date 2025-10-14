"""WSGI entry point for running the Flask service locally."""
from __future__ import annotations

from . import create_app

app = create_app()


if __name__ == "__main__":  # pragma: no cover - manual execution helper
    app.run(host="0.0.0.0", port=8000, debug=False)
