"""Production-style API process entry point."""

from __future__ import annotations

import argparse
import logging
import os
from collections.abc import Sequence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="graphsentinel-api")
    parser.add_argument("--host", default=os.getenv("GRAPHSENTINEL_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("GRAPHSENTINEL_PORT", "8000")))
    parser.add_argument("--workers", type=int, default=int(os.getenv("GRAPHSENTINEL_WORKERS", "1")))
    parser.add_argument("--log-level", default=os.getenv("GRAPHSENTINEL_LOG_LEVEL", "info"))
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 1 <= args.port <= 65_535:
        raise SystemExit("port must be in [1, 65535]")
    if args.workers <= 0:
        raise SystemExit("workers must be positive")
    # The application is imported inside Uvicorn worker processes; publish the effective value
    # so readiness and the security-posture endpoint report the actual topology.
    os.environ["GRAPHSENTINEL_WORKERS"] = str(args.workers)
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    import uvicorn

    uvicorn.run(
        "graphsentinel.api.main:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        log_level=args.log_level,
        proxy_headers=True,
    )
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
