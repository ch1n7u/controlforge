"""Entry point for the CONTROLFORGE worker process.

Runs until it is asked to stop. The loop is intentionally dull: take one run if
there is one, reap expired leases on a timer, sleep briefly when there is
nothing to do. All of the interesting behaviour lives in
``app.runner.worker``; this file only decides how the process starts and how it
stops.

Stopping is cooperative. A SIGTERM sets a flag rather than raising, so an
in-flight run is allowed to finish - killing a tool mid-scan leaves the target
in an unknown state and the run's evidence half-written. systemd's
``TimeoutStopSec`` is the hard stop behind that.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time

from app.config import get_settings
from app.runner.worker import Worker

logger = logging.getLogger("controlforge.worker")


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stdout,
    )


def main() -> int:
    _configure_logging(os.environ.get("CONTROLFORGE_LOG_LEVEL", "INFO"))
    settings = get_settings()
    stop = threading.Event()

    def request_stop(signum: int, _frame: object) -> None:
        logger.info("received signal %s; finishing the current run and stopping", signum)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    worker = Worker(settings=settings)
    logger.info(
        "worker %s starting: poll %ss, lease %ss, %s run(s) at a time",
        worker.worker_id,
        settings.worker_poll_seconds,
        settings.lease_seconds,
        settings.max_concurrent_runs,
    )

    worker.reap()
    last_reap = time.monotonic()

    while not stop.is_set():
        try:
            worked = worker.run_once()
        except Exception:
            logger.exception("the worker loop hit an unexpected error; continuing")
            worked = False

        if time.monotonic() - last_reap >= settings.reaper_interval_seconds:
            worker.reap()
            last_reap = time.monotonic()

        if not worked:
            stop.wait(settings.worker_poll_seconds)

    logger.info("worker %s stopped", worker.worker_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
