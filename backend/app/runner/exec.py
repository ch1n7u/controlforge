"""Running an external tool under a wall clock, a byte cap and a kill switch.

Every property here exists because a security tool left unsupervised is a
problem in its own right:

* the child is started in its own session, so a timeout can take down the whole
  process group - nmap and nuclei both spawn children, and killing only the
  parent leaves those running against a target after the run is "over";
* output is read incrementally and capped, because ``subprocess.run(capture_
  output=True)`` buffers without limit and a runaway tool (or a target that
  streams an endless response) would fill the disk;
* the environment is rebuilt rather than inherited, so the worker's secrets do
  not end up inside a tool that might print its own environment into evidence;
* there is no shell anywhere. Callers pass an argv list.
"""

from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CANCEL_POLL_SECONDS = 1.0
TERMINATE_GRACE_SECONDS = 5.0

# Deliberately minimal. No VALTROS_* variables, no SSH agent, no proxy
# settings that could redirect traffic outside the authorized scope.
BASE_ENV: dict[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
    "HOME": "/nonexistent",
}


@dataclass
class CommandResult:
    """What came back. ``stdout``/``stderr`` are already decoded lossily."""

    argv: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    cancelled: bool = False
    truncated: bool = False
    stdout_bytes: int = 0
    stderr_bytes: int = 0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.cancelled

    def failure_reason(self) -> str:
        if self.cancelled:
            return "cancelled by an operator"
        if self.timed_out:
            return f"timed out after {round(self.duration_ms / 1000)}s"
        if self.exit_code is None:
            return "did not report an exit status"
        if self.exit_code != 0:
            tail = " ".join(self.stderr.split())[-400:]
            return f"exited {self.exit_code}" + (f": {tail}" if tail else "")
        return ""


@dataclass
class _Sink:
    """A capped buffer that keeps draining after it is full.

    Draining matters even when the data is discarded: a tool that keeps writing
    to a pipe nobody reads blocks forever, so the timeout would never fire.
    """

    limit: int
    chunks: list[bytes] = field(default_factory=list)
    total: int = 0
    truncated: bool = False

    def feed(self, data: bytes) -> None:
        self.total += len(data)
        remaining = self.limit - sum(len(chunk) for chunk in self.chunks)
        if remaining <= 0:
            self.truncated = True
            return
        if len(data) > remaining:
            self.chunks.append(data[:remaining])
            self.truncated = True
        else:
            self.chunks.append(data)

    def text(self) -> str:
        return b"".join(self.chunks).decode("utf-8", errors="replace")


def _kill_group(process: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(os.getpgid(process.pid), sig)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except ProcessLookupError:
            pass


def run_command(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
    should_cancel: Callable[[], bool] | None = None,
    cancel_poll_seconds: float = DEFAULT_CANCEL_POLL_SECONDS,
    cwd: str | Path | None = None,
    env_extra: Mapping[str, str] | None = None,
    on_output: Callable[[str, str], None] | None = None,
) -> CommandResult:
    """Run ``argv`` to completion, or stop it.

    Cancellation is polled rather than pushed: the caller supplies a cheap
    ``should_cancel`` that reads a flag, so this module stays free of any
    database or HTTP dependency and can be unit-tested on its own.

    ``on_output`` receives each chunk as ``(stream, text)`` on the reading
    thread, for a caller that wants to show progress while the tool runs. It is
    called *before* the caps are applied, so a live view can be more complete
    than what is retained; a caller writing it anywhere persistent has to do
    its own bounding. Raising from it would abandon the child mid-run, so it is
    the caller's job to be careful here.
    """
    if not argv:
        raise ValueError("argv must not be empty")
    if isinstance(argv, str):  # a shell string is always a bug
        raise TypeError("argv must be a list of arguments, not a string")

    argv = [str(part) for part in argv]
    env = dict(BASE_ENV)
    if env_extra:
        env.update(env_extra)

    started = time.monotonic()

    try:
        process = subprocess.Popen(  # noqa: S603 - argv list, never a shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            cwd=str(cwd) if cwd else None,
            env=env,
            close_fds=True,
        )
    except FileNotFoundError as exc:
        return CommandResult(
            argv=argv,
            exit_code=None,
            stdout="",
            stderr=f"{argv[0]} is not installed",
            duration_ms=0,
        )
    except PermissionError as exc:
        return CommandResult(
            argv=argv,
            exit_code=None,
            stdout="",
            stderr=f"{argv[0]} is not executable: {exc}",
            duration_ms=0,
        )

    out = _Sink(limit=max_output_bytes)
    err = _Sink(limit=max_output_bytes // 4)
    selector = selectors.DefaultSelector()
    for stream, sink in ((process.stdout, out), (process.stderr, err)):
        if stream is not None:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, sink)

    deadline = started + timeout_seconds
    last_cancel_check = started
    timed_out = cancelled = False

    def stop(signum: int) -> None:
        _kill_group(process, signum)

    try:
        while True:
            for key, _ in selector.select(timeout=0.25):
                try:
                    data = key.fileobj.read(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    data = None
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if on_output is not None:
                    name = "stdout" if key.data is out else "stderr"
                    on_output(name, data.decode("utf-8", errors="replace"))
                key.data.feed(data)

            if process.poll() is not None and not selector.get_map():
                break

            now = time.monotonic()
            if now >= deadline:
                timed_out = True
                break
            if should_cancel is not None and now - last_cancel_check >= cancel_poll_seconds:
                last_cancel_check = now
                if should_cancel():
                    cancelled = True
                    break

        if timed_out or cancelled:
            stop(signal.SIGTERM)
            try:
                process.wait(timeout=TERMINATE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                # SIGKILL the whole group: a tool that ignored SIGTERM might be
                # mid-write, and the run is over either way.
                stop(signal.SIGKILL)
                try:
                    process.wait(timeout=TERMINATE_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    pass

        # Final drain, so output written between the last poll and exit is kept.
        for stream, sink, name in ((process.stdout, out, "stdout"), (process.stderr, err, "stderr")):
            if stream is None:
                continue
            try:
                remainder = stream.read()
            except (OSError, ValueError):
                remainder = None
            if remainder:
                if on_output is not None:
                    on_output(name, remainder.decode("utf-8", errors="replace"))
                sink.feed(remainder)
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    duration_ms = int((time.monotonic() - started) * 1000)
    exit_code = process.returncode

    return CommandResult(
        argv=argv,
        exit_code=exit_code,
        stdout=out.text(),
        stderr=err.text(),
        duration_ms=duration_ms,
        timed_out=timed_out,
        cancelled=cancelled,
        truncated=out.truncated or err.truncated,
        stdout_bytes=out.total,
        stderr_bytes=err.total,
    )


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_VERSION = re.compile(r"\d+\.\d+")


def tool_version(argv: Sequence[str], *, timeout_seconds: int = 15) -> str | None:
    """The line on which a tool names its own version, or None.

    A probe is best-effort by design: a tool that is missing, slow or silent
    leaves the version unrecorded, and the artifact the run captured remains the
    record of what was actually executed. Tools print their version in a banner,
    a log line or on stderr depending on the tool, so this looks for the first
    line carrying a version number rather than assuming a shape.
    """
    result = run_command(argv, timeout_seconds=timeout_seconds, max_output_bytes=64 * 1024)
    if result.exit_code != 0:
        return None
    for raw in (result.stdout + "\n" + result.stderr).splitlines():
        line = _ANSI.sub("", raw).strip()
        if line and _VERSION.search(line):
            return line[:200]
    return None
