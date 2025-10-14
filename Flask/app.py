"""WSGI entry point and CLI helper for running the Flask service locally."""
from __future__ import annotations

import argparse
from typing import Sequence

from . import create_app

app = create_app()


def main(argv: Sequence[str] | None = None) -> None:
    """Simple command line interface for launching the web service."""

    parser = argparse.ArgumentParser(
        description=(
            "Run the Machine Learning PE detector as an HTTP service. "
            "The service mirrors the GUI's prediction pipeline so that "
            "remote users can upload files or reference a path available on the server."
        )
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0).")
    parser.add_argument("--port", type=int, default=8000, help="TCP port to listen on (default: 8000).")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable Flask debug mode (useful for development, disable in production).",
    )

    args = parser.parse_args(argv)

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":  # pragma: no cover - manual execution helper
    main()
