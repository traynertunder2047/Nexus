from __future__ import annotations

import importlib, os, shlex, subprocess, sys

from typing import Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich.text import Text

from modules.usage import ENV_VAR, repl_command

# ---------------------------------------------------------------------------
# Command registry
# ---------------------------------------------------------------------------
# In-process commands: name -> (module_path, usage_tail, description).
# Insertion order = display order (identity first, then network).
IN_PROCESS_COMMANDS = {
    # --- identity -----------------------------------------------------------
    "breach-check":      ("modules.identity.breach_checker", "<email>", "XposedOrNot breach lookup"),
    "analytics":         ("modules.identity.breach_analytics", "<email>", "XposedOrNot breach analytics"),
    "email-lookup":      ("modules.identity.email_lookup", "<email>", "EmailRep reputation"),
    "password-check":    ("modules.identity.password_checker", "<password>", "XposedOrNot anon password check"),
    "password-strength": ("modules.identity.strong_password", "<password>", "Local strength scorer"),
    "assess":            ("modules.identity.password_assessor", "[password]", "Strength + breach fusion (masked prompt if omitted)"),
    "phone-validate":    ("modules.identity.phone_validator", "<phone>", "Phone validation + metadata"),
    "phone-breach":      ("modules.identity.phone_breach_check", "<phone>", "Leak-Lookup phone breach check"),
    "social":            ("modules.identity.social_linker", "<username>", "Cross-platform username probe"),
    # --- network ------------------------------------------------------------
    "whois":             ("modules.network.whois_lookup", "<domain>", "WHOIS record lookup"),
    "dns":               ("modules.network.dns_enumerator", "<domain>", "DNS records + subdomain enumeration"),
    "ports":             ("modules.network.port_scanner", "<host>", "TCP port scanner"),
    "geo":               ("modules.network.geolocator", "<ip>", "IP geolocation"),
}

# Metadata modes: name -> (argv after sys.executable, usage_tail, description).
# These run in a subprocess so their heavy imports never touch the shell.
SUBPROCESS_COMMANDS = {
    "atlas":        (["-m", "modules.metadata.atlas"], "<free text | image>", "Text place search (Mode 1)"),
    "doppelganger": (["-m", "modules.metadata.doppelganger"], "<image_path>", "Face search (Mode 2)"),
    "locus":        (["-m", "modules.metadata.locus"], "<image_path>", "Photo geolocation (Mode 3)"),
}

# ---------------------------------------------------------------------------
# Help rows (Command, Usage, Flags, Description)
# ---------------------------------------------------------------------------
# Single source of truth for both the printed help table and the anti-drift
# test in tests/test_repl.py: every flag advertised here must be accepted by
# the module's own --help, and every flag a module's --help documents must be
# advertised here (compat-only aliases may be listed in
# tests/test_repl.py::UNDOCUMENTED_FLAGS with a rationale).
HELP_METADATA_ROWS = [
    ("atlas", '"<free text>"', "--full", "Text place search (Mode 1)"),
    ("locus", "<image_path>", "", "Photo geolocation (Mode 3)"),
    ("doppelganger", "<image_path> [handles...]", "", "Face search (Mode 2)"),
]
HELP_IDENTITY_ROWS = [
    ("breach-check", "<email>", "--json --timeout SEC", "XposedOrNot breach lookup"),
    ("analytics", "<email>", "--json --timeout SEC", "XposedOrNot breach analytics"),
    ("email-lookup", "<email>", "--json --timeout SEC", "EmailRep reputation"),
    ("password-check", "<password>", "--json --timeout SEC", "XposedOrNot anon password check"),
    ("password-strength", "[password]", "--json", "Local strength scorer"),
    ("assess", "[password]", "--json --timeout SEC --skip-breach", "Strength + breach fusion (masked prompt if omitted)"),
    ("phone-validate", "<phone>", "--json --region CC --live --no-live --timeout SEC", "Phone validation + metadata"),
    ("phone-breach", "<phone>", "--json --region CC --timeout SEC", "Leak-Lookup phone breach check"),
    ("social", "<username>", "--json --platforms LIST --proxy URL --no-cache --timeout SEC", "Cross-platform username probe"),
]
HELP_NETWORK_ROWS = [
    ("whois", "<domain> [...]", "--json --multi [--workers N]", "WHOIS record lookup (--multi races domains, fastest answer first)"),
    ("dns", "<domain>", "--json --wordlist FILE --full --bruteforce --permutations --axfr --takeover --no-passive --timeout SEC --workers N --max-queries N", "DNS records + subdomain enumeration (--full enables active stages)"),
    ("ports", "<target>", "--json --xml FILE --ports SPEC --preset NAME --max-ports N --yes-full-sweep --max-hosts N --protocol P --udp-ports SPEC --timeout SEC --workers N --rate N --min-rate N --jitter F --shuffle --retries N --no-probe --no-tls --quick-tls --skip-hostdown --os --seed N --help", "TCP/UDP port scanner (version probes, OS fingerprint, nmap XML)"),
    ("geo", "<ip>", "--json --timeout SEC", "IP geolocation"),
]

# Friendly aliases -> canonical command names.
# Accepted when typed (old habits, saved notes) but never suggested: both
# autocomplete and the help screen mirror the documented commands only.
_ALIASES = {
    # identity parity with the orchestrator's own aliases
    "breach": "breach-check",
    "breach_checker": "breach-check",
    "breach-checker": "breach-check",
    "breach-analytics": "analytics",
    "breach_analytics": "analytics",
    "email_lookup": "email-lookup",
    "password_assessor": "assess",
    "assess-password": "assess",
    "strong_password": "password-strength",
    "strong-password": "password-strength",
    "phone_validator": "phone-validate",
    "phone_breach": "phone-breach",
    "phone_breach_check": "phone-breach",
    "social_linker": "social",
    # network module file names and natural variants
    "whois-lookup": "whois",
    "whois_lookup": "whois",
    "dns-enum": "dns",
    "dns_enumerator": "dns",
    "port-scan": "ports",
    "port_scanner": "ports",
    "geolocator": "geo",
    "geolocate": "geo",
    "ip": "geo",
}

BUILTINS = ("help", "clear", "exit", "quit")


def _clear_screen() -> bool:
    """Erase the screen by writing VT sequences straight to stdout.

    Measured on Windows 11 + VS Code (ConPTY + xterm.js):
      * raw "\\x1b[2J\\x1b[3J\\x1b[H" written to sys.stdout -> clears the screen
      * cls (console buffer APIs)                            -> clears the screen
      * prompt_toolkit's Windows10_Output.erase_screen()     -> does NOT clear
    The escape sequences are fine here; it is prompt_toolkit's hybrid
    Win32/VT flush that loses them, so we write them ourselves. The same
    bytes are the native mechanism on Linux/macOS.

    "\\x1b[2J" erases the viewport, "\\x1b[3J" the saved lines above it (so the
    history leaves the terminal's scrollback too), "\\x1b[H" homes the cursor.
    Homing matters: when a prompt finishes prompt_toolkit resets its renderer,
    and the next prompt asserts `_cursor_pos.y == 0`, so a clear must leave
    the cursor on row 0 -- which is exactly what this does.

    Returns False when stdout is not a terminal (pipes, redirects, tests) so
    the caller can fall back to rich.
    """
    try:
        if not sys.stdout.isatty():
            return False
        sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
        sys.stdout.flush()
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Prompt — "Nexus" in the same green as the help-table command names
# ---------------------------------------------------------------------------

PROMPT_LABEL = "Nexus"
PROMPT_SUFFIX = "> "
# Bold green, i.e. rich's "bold green" used for the commands in the help tables.
PROMPT_GREEN = "\x1b[1;32m"
ANSI_RESET = "\x1b[0m"


def _styled_prompt():
    """prompt_toolkit prompt object: 'Nexus' in the help-table command green."""
    from prompt_toolkit.formatted_text import HTML

    return HTML(f"<b><ansigreen>{PROMPT_LABEL}</ansigreen></b>{PROMPT_SUFFIX}")


def _plain_prompt() -> str:
    """input() fallback prompt; colored only on a real terminal."""
    try:
        if sys.stdout.isatty():
            return f"{PROMPT_GREEN}{PROMPT_LABEL}{ANSI_RESET}{PROMPT_SUFFIX}"
    except Exception:
        pass
    return f"{PROMPT_LABEL}{PROMPT_SUFFIX}"


HISTORY_FILE = ".nexus_history"


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable without a terminal)
# ---------------------------------------------------------------------------

def parse_line(line: str) -> Tuple[str, list]:
    """Split a command line into (name, argv) with quote support.

    Returns ("", []) for empty/whitespace input.
    Raises ValueError on unbalanced quotes.
    """
    try:
        parts = shlex.split(line)
    except ValueError as exc:
        raise ValueError(f"Could not parse command line: {exc}") from exc
    if not parts:
        return "", []
    return parts[0], parts[1:]


def resolve(name: str) -> Tuple[str, object]:
    """Resolve a command name to (kind, target).

    kind: "in_process" (target = module path)
          "subprocess" (target = argv list after sys.executable)
          "builtin"    (target = name)
          "unknown"    (target = None)
    """
    name = (name or "").strip().lower()
    name = _ALIASES.get(name, name)
    if name in BUILTINS:
        return "builtin", name
    if name in IN_PROCESS_COMMANDS:
        return "in_process", IN_PROCESS_COMMANDS[name][0]
    if name in SUBPROCESS_COMMANDS:
        return "subprocess", SUBPROCESS_COMMANDS[name][0]
    return "unknown", None


def command_for_module(module_path: str) -> str:
    """Canonical REPL command that runs `module_path` (fallback: the path).

    Used to announce the REPL name to the module, so its usage line reports
    `Usage: ports <host>` and never the python -m path.
    """
    for name, (path, _usage_tail, _desc) in IN_PROCESS_COMMANDS.items():
        if path == module_path:
            return name
    for name, (argv, _usage_tail, _desc) in SUBPROCESS_COMMANDS.items():
        if argv[-1] == module_path:
            return name
    return module_path


def command_names() -> list:
    """Command names offered by autocomplete: exactly the help-table rows.

    Aliases (see _ALIASES) and module file names are still accepted when
    typed -- resolve() maps them -- but they are deliberately NOT suggested:
    the completion list mirrors the help tables, so a user only ever sees
    documented commands, never a file name or a variant of one.
    """
    rows = HELP_METADATA_ROWS + HELP_IDENTITY_ROWS + HELP_NETWORK_ROWS
    return sorted({row[0] for row in rows} | set(BUILTINS))


# ---------------------------------------------------------------------------
# The shell
# ---------------------------------------------------------------------------

class NexusShell:
    """Interactive shell. `dispatch()` is headless-safe; the prompt loop
    (prompt_toolkit session, history) is created lazily in run_interactive().
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self._session = None  # lazy: prompt_toolkit PromptSession

    # -- public API ---------------------------------------------------------

    def run_interactive(self) -> int:
        """REPL loop. Returns the final exit code."""
        from prompt_toolkit import PromptSession
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        from prompt_toolkit.completion import WordCompleter
        from prompt_toolkit.history import FileHistory

        completer = WordCompleter(command_names(), ignore_case=True, sentence=True)
        try:
            self._session = PromptSession(
                history=FileHistory(HISTORY_FILE),
                auto_suggest=AutoSuggestFromHistory(),
                completer=completer,
            )
        except Exception:
            self._session = None  # degraded mode: plain input()

        self._print_banner()
        while True:
            try:
                line = self._read_line()
            except KeyboardInterrupt:
                continue  # Ctrl+C on an empty prompt: just re-prompt
            except EOFError:
                self.console.print("\n[dim]Bye.[/dim]")
                return 0
            if not line.strip():
                continue
            try:
                self.execute(line)
            except EOFError:  # exit/quit builtin
                self.console.print("[dim]Bye.[/dim]")
                return 0
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Cancelled.[/yellow]")

    def run_one_shot(self, argv: list) -> int:
        """`Nexus <cmd> [args]` — run one command, return its exit code."""
        if not argv:
            self.print_help()
            return 0
        if argv[0] in ("-h", "--help", "help") and len(argv) == 1:
            self.print_help()
            return 0
        try:
            return self.dispatch(argv[0], argv[1:])
        except EOFError:  # `Nexus exit` in one-shot mode
            return 0
        except KeyboardInterrupt:
            return 130

    def execute(self, line: str) -> int:
        """Parse + run one raw command line; returns an exit code.

        Errors are contained: a failing command never raises out of here
        (except EOFError for exit/quit, which run_interactive translates
        into a clean shutdown).
        """
        try:
            name, argv = parse_line(line)
        except ValueError as exc:
            self.console.print(f"[red]Error:[/red] {exc}")
            return 2
        if not name:
            return 0
        return self.dispatch(name, argv)

    # -- dispatch -------------------------------------------------------------

    def dispatch(self, name: str, argv: Optional[list] = None) -> int:
        """Run one resolved command. May raise EOFError (exit) / KeyboardInterrupt."""
        argv = list(argv or [])

        # Shell passthrough: !dir, !git status, ...
        if name.startswith("!"):
            return self._run_shell_passthrough((name[1:] + " " + " ".join(argv)).strip())

        kind, target = resolve(name)
        if kind == "unknown":
            self.console.print(
                f"[red]Unknown command:[/red] {name}  [dim](try 'help')[/dim]")
            return 2
        if kind == "builtin":
            return self._run_builtin(target, argv)
        if kind == "in_process":
            return self._run_in_process(target, argv, command_for_module(target))
        return self._run_subprocess(target, argv, command_for_module(target[-1]))

    def _run_in_process(self, module_path: str, argv: list,
                        command: str = "") -> int:
        try:
            mod = importlib.import_module(module_path)
        except Exception as exc:
            self.console.print(f"[red]Failed to import {module_path}:[/red] {exc}")
            return 1
        try:
            # Announce the REPL command so a misuse reports
            # "Usage: <command> ..." instead of the python -m path
            # (see modules/usage.py).
            with repl_command(command or module_path):
                return mod.main(argv) or 0
        except SystemExit as exc:  # argparse-style main() may sys.exit
            return int(exc.code) if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Cancelled.[/yellow]")
            return 130
        except Exception as exc:
            self.console.print(f"[red]Command failed:[/red] {exc}")
            return 1

    def _run_subprocess(self, module_argv: list, argv: list,
                        command: str = "") -> int:
        cmd = [sys.executable, *module_argv, *argv]
        # Metadata modes run out of process, so the REPL name travels in the
        # environment (modules/usage.py reads NEXUS_PROG).
        env = {**os.environ, ENV_VAR: command or module_argv[-1]}
        try:
            proc = subprocess.run(cmd, env=env)
            return proc.returncode
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Cancelled.[/yellow]")
            return 130
        except Exception as exc:
            self.console.print(f"[red]Command failed to start:[/red] {exc}")
            return 1

    def _run_shell_passthrough(self, shell_cmd: str) -> int:
        if not shell_cmd:
            self.console.print("[dim]Usage: !<shell command>  (e.g. !dir)[/dim]")
            return 2
        try:
            proc = subprocess.run(shell_cmd, shell=True)
            return proc.returncode
        except KeyboardInterrupt:
            return 130

    # -- builtins ------------------------------------------------------------

    def _run_builtin(self, name: str, argv: list) -> int:
        if name in ("exit", "quit"):
            raise EOFError
        if name == "clear":
            # Write the escape sequences ourselves: prompt_toolkit's hybrid
            # Windows10_Output flush drops them. On a real terminal the
            # banner is then reprinted, so a cleared screen still says what
            # this shell is; rich is the fallback when stdout is not a
            # terminal (one-shot CLI, piped stdin, tests).
            if _clear_screen():
                self._print_banner()
            else:
                self.console.clear()
            return 0
        if name == "help":
            if argv:
                return self._help_command(argv[0])
            self.print_help()
            return 0
        return 0

    def _help_command(self, name: str) -> int:
        """help <cmd> — for module commands, delegate to the module's --help."""
        canon = _ALIASES.get(name.strip().lower(), name.strip().lower())
        if canon in IN_PROCESS_COMMANDS or canon in SUBPROCESS_COMMANDS:
            return self.dispatch(canon, ["--help"])
        if canon in BUILTINS:
            self.console.print(f"[bold]{canon}[/bold] — builtin (no arguments)")
            return 0
        self.console.print(f"[red]Unknown command:[/red] {name}")
        return 2

    # -- output --------------------------------------------------------------

    def _print_banner(self) -> None:
        n_cmds = len(IN_PROCESS_COMMANDS) + len(SUBPROCESS_COMMANDS)
        self.console.print(self._banner_art())
        self.console.print(
            f"[dim]OSINT toolchain shell | {n_cmds} commands | "
            "type [bold]help[/bold] for the list, [bold]exit[/bold] to quit | "
            "Tab completes[/dim]"
        )
        self.console.print()

    # ANSI-Shadow FIGlet-style glyphs for the banner — the same hardcoded
    # raw-string approach as Phantom's build_banner(): solid block letters
    # (█ ╗ ║ ╔ etc.) that read as filled chunky squares in any terminal,
    # no font engine required. Six rows, all 43 chars wide.
    _BANNER_LETTERS = (
        "███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗",
        "████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝",
        "██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗",
        "██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║",
        "██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║",
        "╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝",
    )

    @staticmethod
    def _console_width() -> int:
        """Live console width (0 when unavailable)."""
        try:
            from rich import get_console

            return get_console().width or 80
        except Exception:
            return 80

    @classmethod
    def _banner_art(cls, dx: int = 2, dy: int = 1, layers: int = 2):
        """NEXUS in ANSI-Shadow block glyphs with green offset ghosts.

        Same approach as Phantom's build_banner(): a hardcoded raw string
        of Unicode block/box-drawing glyphs in the FIGlet "ANSI Shadow"
        style — no font engine, deterministic width, reads as solid
        chunky letters in any terminal rich can drive (this is the style
        of the C2.CORE reference screenshot). On top of Phantom's plain
        string, each row also gets `layers` green offset copies of the
        glyph matrix stepping down-right by (dx, dy): the nearest ghost
        is the brightest green, further ones fade, and ghosts only show
        where the letter is empty — a drop shadow behind the word.

        Falls back to plain bold-white text when the output stream
        cannot encode Unicode block glyphs (e.g. piped cp1252) or the
        console is too narrow.
        """
        import sys as _sys

        from rich.text import Text

        enc = str(getattr(_sys.stdout, "encoding", "") or "utf-8")
        try:
            "█╗".encode(enc)
        except (UnicodeEncodeError, LookupError):
            return Text("NEXUS", style="bold white")  # legacy codepage

        letters = cls._BANNER_LETTERS
        width = max(len(line) for line in letters)
        total = width + layers * dx
        if total > (cls._console_width() or 80):
            return Text("NEXUS", style="bold white")  # too narrow

        shadow_styles = {1: "bright_green", 2: "green", 3: "darkgreen"}
        out = Text()
        for i, line in enumerate(letters):
            padded = line.ljust(width)
            run, run_style = "", None
            for c in range(total):
                ch = padded[c] if c < len(padded) else " "
                if ch != " ":
                    style = "bold white"
                else:
                    style, ch = None, " "
                    # Ghost layers: nearest first, from the row k*dy above
                    # and k*dx columns left (painted where letter is empty)
                    for k in range(1, layers + 1):
                        src_i = i - k * dy
                        if src_i < 0:
                            continue
                        src = letters[src_i]
                        sc = src[c - k * dx] if 0 <= c - k * dx < len(src) else " "
                        if sc != " ":
                            style, ch = shadow_styles.get(k, "green"), sc
                            break
                if style != run_style:
                    if run:
                        out.append(run, style=run_style)
                    run, run_style = ch, style
                else:
                    run += ch
            if run:
                out.append(run, style=run_style)
            if i < len(letters) - 1:
                out.append("\n")
        return out

    def print_help(self) -> None:
        """Help as one left-aligned table per module family.

        Unified color scheme: bold white table titles, grey35 borders,
        bold green command names - one accent echoing the banner.
        Tables are left-aligned in the terminal.
        """

        # Rows live at module level (HELP_*_ROWS) so the printed table and
        # the anti-drift test share one source of truth.
        identity_rows = HELP_IDENTITY_ROWS
        network_rows = HELP_NETWORK_ROWS
        metadata_rows = HELP_METADATA_ROWS

        # One accent + neutrals: quiet grey frame, white titles (hierarchy
        # via weight, not hue), green commands echoing the banner ghosts.
        BORDER_COLOR = "grey35"
        COMMAND_COLOR = "green"
        TITLE_COLOR = "bold white"

        def family_table(title: str, rows, cmd_style: str | None = None):
            table = Table(
                title=f"[{TITLE_COLOR}]{title}[/]",
                border_style=BORDER_COLOR,
                show_lines=False,
                # Every table spans the full terminal width with identical
                # column proportions, so all boxes align edge-to-edge.
                expand=True,
            )
            table.add_column("Command", style=cmd_style or f"bold {COMMAND_COLOR}", no_wrap=True, ratio=1, width=19)
            table.add_column("Usage", no_wrap=True, ratio=1, width=27)
            table.add_column("Flags", style="dim", overflow="fold", ratio=2, width=20)
            table.add_column("Description", overflow="fold", ratio=2, width=18)
            for name, usage, flags, desc in rows:
                table.add_row(name, usage, flags or "-", desc)
            return table

        self.console.print()
        self.console.print(family_table("METADATA - Atlas / Locus / Doppelganger", metadata_rows))
        self.console.print()
        self.console.print(family_table("IDENTITY - Email / Password / Phone / Social", identity_rows))
        self.console.print()
        self.console.print(family_table("NETWORK - Domain / IP Recon", network_rows))
        self.console.print()
        self.console.print(
            Text(
                "* metadata modes run in an isolated subprocess.\n"
                "Builtins: help [cmd] · clear · exit · !<shell command>   "
                "Tab completes the commands above.",
                style="dim",
            )
        )
        self.console.print()

    # -- input ---------------------------------------------------------------

    def _read_line(self) -> str:
        if self._session is not None:
            try:
                return self._session.prompt(_styled_prompt())
            except (OSError, ValueError):
                # Non-interactive stdin (pipe/redirect): fall back to input().
                self._session = None
        return input(_plain_prompt())
