"""The command executor.

These are mostly about the ways a security tool misbehaves: it hangs, it writes
without bound, it spawns children that outlive it, or it tries to read the
worker's environment.
"""

from __future__ import annotations

import os
import signal
import sys
import time

import pytest

from app.runner.exec import run_command, tool_version


def test_a_successful_command_captures_output():
    result = run_command(
        [sys.executable, "-c", "print('hello')"],
        timeout_seconds=10,
        max_output_bytes=1024,
    )
    assert result.ok
    assert result.stdout.strip() == "hello"
    assert result.exit_code == 0
    assert result.duration_ms >= 0


def test_a_nonzero_exit_reports_the_stderr_tail():
    result = run_command(
        [sys.executable, "-c", "import sys; print('boom', file=sys.stderr); sys.exit(3)"],
        timeout_seconds=10,
        max_output_bytes=1024,
    )
    assert not result.ok
    assert result.exit_code == 3
    assert "boom" in result.stderr
    assert "exited 3" in result.failure_reason()
    assert "boom" in result.failure_reason()


def test_a_missing_binary_is_reported_not_raised():
    result = run_command(
        ["definitely-not-a-real-binary-xyz"], timeout_seconds=5, max_output_bytes=1024
    )
    assert not result.ok
    assert result.exit_code is None
    assert "is not installed" in result.stderr


def test_a_shell_string_is_rejected():
    """A string argv would be interpreted by a shell; there must be no such path."""
    with pytest.raises(TypeError):
        run_command("echo hello", timeout_seconds=5, max_output_bytes=1024)
    with pytest.raises(ValueError):
        run_command([], timeout_seconds=5, max_output_bytes=1024)


def test_a_hanging_command_is_killed_at_the_timeout():
    started = time.monotonic()
    result = run_command(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        timeout_seconds=1,
        max_output_bytes=1024,
    )
    elapsed = time.monotonic() - started
    assert result.timed_out
    assert not result.ok
    assert elapsed < 15, f"timeout took {elapsed:.1f}s"
    assert "timed out" in result.failure_reason()


def test_the_timeout_kills_grandchildren_too(tmp_path):
    """nmap and nuclei spawn helpers. Killing only the parent would leave those
    running against the target after the run is over."""
    pid_file = tmp_path / "child.pid"
    script = (
        "import subprocess, sys, time, pathlib\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))\n"
        "time.sleep(120)\n"
    )
    result = run_command(
        [sys.executable, "-c", script], timeout_seconds=2, max_output_bytes=1024
    )
    assert result.timed_out

    child_pid = int(pid_file.read_text())
    # give the signal a moment to be reaped
    for _ in range(50):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    os.kill(child_pid, signal.SIGKILL)
    pytest.fail(f"grandchild {child_pid} survived the process-group kill")


def test_a_cancel_callback_stops_the_command():
    calls = {"n": 0}

    def should_cancel() -> bool:
        calls["n"] += 1
        return True

    result = run_command(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        timeout_seconds=60,
        max_output_bytes=1024,
        should_cancel=should_cancel,
        cancel_poll_seconds=0.1,
    )
    assert result.cancelled
    assert calls["n"] >= 1
    assert "cancelled" in result.failure_reason()


def test_output_is_capped_and_the_process_still_finishes():
    """A full pipe that nobody drains would block the tool forever."""
    result = run_command(
        [
            sys.executable,
            "-c",
            "import sys\n"
            "for _ in range(2000):\n"
            "    sys.stdout.write('x' * 1000)\n",
        ],
        timeout_seconds=30,
        max_output_bytes=4096,
    )
    assert result.ok, result.failure_reason()
    assert result.truncated
    assert result.stdout_bytes > 4096
    assert len(result.stdout) <= 4096


def test_the_worker_environment_is_not_inherited(monkeypatch):
    """Tools must not be able to read the worker's secrets from their env."""
    monkeypatch.setenv("CONTROLFORGE_SECRET_KEY", "super-secret-value")
    monkeypatch.setenv("CONTROLFORGE_DB_URL", "postgresql://user:pw@host/db")

    result = run_command(
        [sys.executable, "-c", "import os; print(sorted(os.environ))"],
        timeout_seconds=10,
        max_output_bytes=8192,
    )
    assert result.ok
    assert "CONTROLFORGE_SECRET_KEY" not in result.stdout
    assert "CONTROLFORGE_DB_URL" not in result.stdout
    # and the values themselves never appear
    assert "super-secret-value" not in result.stdout


def test_extra_env_is_passed_explicitly():
    result = run_command(
        [sys.executable, "-c", "import os; print(os.environ.get('CF_ALLOWED', 'missing'))"],
        timeout_seconds=10,
        max_output_bytes=1024,
        env_extra={"CF_ALLOWED": "yes"},
    )
    assert result.stdout.strip() == "yes"


def test_tool_version_reads_the_line_that_names_a_version():
    result = tool_version(
        [sys.executable, "-c", "print('tool 1.2.3 (build 7)')"],
    )
    assert result == "tool 1.2.3 (build 7)"


def test_tool_version_strips_ansi_and_reads_stderr():
    """Tools colour their banners, and nuclei logs its version to stderr."""
    result = tool_version(
        [
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('\\x1b[34m[INF]\\x1b[0m Engine Version: v9.9.9\\n')",
        ],
    )
    assert result == "[INF] Engine Version: v9.9.9"


def test_tool_version_is_none_for_a_missing_tool():
    assert tool_version(["definitely-not-installed-here", "--version"]) is None


def test_tool_version_is_none_when_the_probe_fails():
    assert tool_version([sys.executable, "-c", "raise SystemExit(3)"]) is None
