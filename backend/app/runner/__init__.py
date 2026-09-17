"""The runner, minus the parts that need a database.

This package executes things: it runs a command under a timeout (``exec``), and
later it will claim runs from the queue and drive engines. It is kept importable
without side effects so unit tests can exercise the process handling directly.
"""

from app.runner.exec import CommandResult, run_command

__all__ = ["CommandResult", "run_command"]
