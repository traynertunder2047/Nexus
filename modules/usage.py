from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional

# Name under which the shell announces itself to subprocesses.
ENV_VAR = "NEXUS_PROG"

_REPL_COMMAND: ContextVar[Optional[str]] = ContextVar("nexus_repl_command", default=None)


@contextmanager
def repl_command(name: str) -> Iterator[None]:
    """Announce `name` as the REPL command for the enclosed dispatch."""
    token = _REPL_COMMAND.set(name)
    try:
        yield
    finally:
        _REPL_COMMAND.reset(token)


def prog_name(module_path: str) -> str:
    """Program name to advertise: REPL command if active, else python -m <path>."""
    return _REPL_COMMAND.get() or os.environ.get(ENV_VAR) or f"python -m {module_path}"


def usage_line(module_path: str, args: str = "") -> str:
    """`Usage: <prog> [args]`, REPL-aware (see prog_name)."""
    tail = args.strip()
    return f"Usage: {prog_name(module_path)} {tail}".rstrip()
