import contextlib
import importlib
import io
import re
import subprocess
import sys
import types
from types import SimpleNamespace

import pytest
from unittest import mock

import repl as r
from repl import NexusShell, command_names, parse_line, resolve


@pytest.fixture()
def shell():
    buf = io.StringIO()
    sh = NexusShell(console=__import__("rich").console.Console(file=buf, width=200))
    sh.buffer = buf
    return sh


def out(shell) -> str:
    return shell.buffer.getvalue()


# ---------------------------------------------------------------------------
# parse_line
# ---------------------------------------------------------------------------

def test_parse_line_simple():
    assert parse_line("whois example.com") == ("whois", ["example.com"])


def test_parse_line_quotes():
    assert parse_line('breach-check "a b@c.com" --json') == (
        "breach-check", ["a b@c.com", "--json"])


def test_parse_line_empty():
    assert parse_line("") == ("", [])
    assert parse_line("   ") == ("", [])


def test_parse_line_unbalanced_quotes_raise():
    with pytest.raises(ValueError):
        parse_line('social "unclosed')


# ---------------------------------------------------------------------------
# resolve
# ---------------------------------------------------------------------------

def test_resolve_identity_in_process():
    kind, target = resolve("breach-check")
    assert kind == "in_process"
    assert target == "modules.identity.breach_checker"


def test_resolve_network_in_process():
    kind, target = resolve("whois")
    assert kind == "in_process"
    assert target == "modules.network.whois_lookup"


def test_resolve_metadata_subprocess():
    kind, target = resolve("atlas")
    assert kind == "subprocess"
    assert target == ["-m", "modules.metadata.atlas"]


def test_resolve_builtin_and_alias_and_unknown():
    assert resolve("help")[0] == "builtin"
    assert resolve("breach") == ("in_process", "modules.identity.breach_checker")
    assert resolve("ip") == ("in_process", "modules.network.geolocator")
    assert resolve("GEO")[0] == "in_process"  # case-insensitive
    assert resolve("nope")[0] == "unknown"


# ---------------------------------------------------------------------------
# command_names (autocomplete source)
# ---------------------------------------------------------------------------
# Suggestions must mirror the help tables exactly: no module file names, no
# alias variants. Aliases stay typable (resolve() maps them) but never appear
# in the completion list.

HELP_TABLE_ROWS = r.HELP_METADATA_ROWS + r.HELP_IDENTITY_ROWS + r.HELP_NETWORK_ROWS
DOCUMENTED_COMMANDS = {name for name, _usage, _flags, _desc in HELP_TABLE_ROWS}


def test_command_names_is_exactly_the_help_table_plus_builtins():
    assert set(command_names()) == DOCUMENTED_COMMANDS | set(r.BUILTINS)
    assert command_names() == sorted(command_names())


def test_command_names_suggests_no_file_names_or_variants():
    """The variants the help tables dropped must not come back as suggestions."""
    variants = {
        # module file names
        "breach_checker", "breach_analytics", "email_lookup",
        "password_checker", "strong_password", "password_assessor",
        "phone_validator", "phone_breach_check", "social_linker",
        "whois_lookup", "dns_enumerator", "port_scanner", "geolocator",
        # hyphen / short variants of documented commands
        "breach", "breach-checker", "breach-analytics", "strong-password",
        "assess-password", "whois-lookup", "dns-enum", "port-scan",
        "phone_breach", "geolocate", "ip",
    }
    suggested = variants & set(command_names())
    assert suggested == set(), f"variants offered as suggestions: {sorted(suggested)}"


def test_help_rows_and_registry_agree():
    """Every documented command resolves, and nothing hides from the table."""
    for name in sorted(DOCUMENTED_COMMANDS):
        assert resolve(name)[0] != "unknown", f"help row '{name}' does not resolve"
    registry = set(r.IN_PROCESS_COMMANDS) | set(r.SUBPROCESS_COMMANDS)
    assert registry == DOCUMENTED_COMMANDS, (
        f"only in registry: {sorted(registry - DOCUMENTED_COMMANDS)}; "
        f"only in help table: {sorted(DOCUMENTED_COMMANDS - registry)}")


def test_typed_aliases_still_resolve_even_if_not_suggested():
    """Dropping a name from the suggestions must not break typing it."""
    assert resolve("ip") == ("in_process", "modules.network.geolocator")
    assert resolve("port_scanner") == ("in_process", "modules.network.port_scanner")
    assert resolve("password_assessor") == ("in_process", "modules.identity.password_assessor")


def test_help_screen_advertises_no_aliases(shell):
    """The help footer points at the table instead of listing alias variants."""
    shell.dispatch("help")
    assert "Aliases:" not in out(shell)
    assert "Tab completes the commands above" in out(shell)


# ---------------------------------------------------------------------------
# dispatch — builtins and errors
# ---------------------------------------------------------------------------

def test_dispatch_unknown_command(shell):
    rc = shell.dispatch("definitely-not-a-command")
    assert rc == 2
    assert "Unknown command" in out(shell)


def test_dispatch_exit_raises_eof(shell):
    with pytest.raises(EOFError):
        shell.dispatch("exit")
    with pytest.raises(EOFError):
        shell.dispatch("quit")


def test_dispatch_clear(shell):
    assert shell.dispatch("clear") == 0


def test_clear_falls_back_to_ansi_when_not_a_console():
    """Non-terminal stdout -> rich's ANSI clear runs.

    Uses its own force_terminal console: rich only emits control codes
    when it believes it is writing to a terminal (the shared `shell`
    fixture's plain StringIO console would make clear() a no-op).
    """
    buf = io.StringIO()
    console = __import__("rich").console.Console(
        file=buf, width=200, force_terminal=True)
    sh = NexusShell(console=console)
    with mock.patch.object(r, "_clear_screen", return_value=False):
        sh.dispatch("clear")
    assert "OSINT toolchain shell" not in buf.getvalue()  # rich path: no banner
    assert "[2J" in buf.getvalue()


def test_clear_screen_writes_vt_sequences(monkeypatch):
    """clear writes 2J/3J/H to stdout and reports success."""
    fake = mock.MagicMock()
    fake.isatty.return_value = True
    monkeypatch.setattr(r, "sys", SimpleNamespace(stdout=fake))
    assert r._clear_screen() is True
    fake.write.assert_called_once_with("\x1b[2J\x1b[3J\x1b[H")
    fake.flush.assert_called_once_with()


def test_clear_screen_returns_false_when_not_a_terminal(monkeypatch):
    """Piped/redirected stdout -> False, so rich takes over."""
    fake = mock.MagicMock()
    fake.isatty.return_value = False
    monkeypatch.setattr(r, "sys", SimpleNamespace(stdout=fake))
    assert r._clear_screen() is False
    fake.write.assert_not_called()


def test_clear_screen_degrades_when_stdout_raises(monkeypatch):
    """A broken stdout must not take down the shell."""
    fake = mock.MagicMock()
    fake.isatty.return_value = True
    fake.write.side_effect = OSError("console gone")
    monkeypatch.setattr(r, "sys", SimpleNamespace(stdout=fake))
    assert r._clear_screen() is False


def test_clear_reprints_banner_on_a_terminal(shell):
    """After a real erase the banner comes back, so the screen is not blank."""
    with mock.patch.object(r, "_clear_screen", return_value=True):
        assert shell.dispatch("clear") == 0
    text = out(shell)
    assert "OSINT toolchain shell" in text
    assert "exit" in text  # the tagline, not just the art


def test_dispatch_clear_prefers_vt_over_rich():
    """rich's ANSI clear is not used when the VT erase went out."""
    buf = io.StringIO()
    console = __import__("rich").console.Console(
        file=buf, width=200, force_terminal=True)
    sh = NexusShell(console=console)
    with mock.patch.object(r, "_clear_screen", return_value=True):
        assert sh.dispatch("clear") == 0
    assert "\x1b[2J" not in buf.getvalue()


def test_dispatch_help_table(shell):
    assert shell.dispatch("help") == 0
    text = out(shell)
    for cmd in ("breach-check", "whois", "atlas", "locus"):
        assert cmd in text


def test_dispatch_help_lists_whois_multi_flags(shell):
    """The whois row advertises the domain race and its worker cap."""
    assert shell.dispatch("help") == 0
    text = out(shell)
    assert "--multi" in text and "--workers" in text


def test_dispatch_help_lists_dns_scope_flags(shell):
    """The dns row advertises the active-stage opt-in flags and --full."""
    assert shell.dispatch("help") == 0
    text = out(shell)
    for flag in ("--full", "--bruteforce", "--permutations", "--axfr",
                 "--takeover"):
        assert flag in text


def test_dispatch_help_specific_delegates_to_module(shell, monkeypatch):
    captured = {}

    def fake_import(path):
        captured["path"] = path
        m = types.ModuleType(path)
        m.main = lambda argv: captured.update(argv=argv) or 0
        return m

    monkeypatch.setattr(r, "importlib", SimpleNamespace(import_module=fake_import))
    rc = shell.dispatch("help", ["breach-check"])
    assert rc == 0
    assert captured["path"] == "modules.identity.breach_checker"
    assert captured["argv"] == ["--help"]


def test_shell_passthrough(shell):
    assert shell.dispatch("!echo", ["hello"]) == 0
    assert shell.dispatch("!") == 2  # no command given


def test_empty_line_is_noop(shell):
    assert shell.execute("   ") == 0


# ---------------------------------------------------------------------------
# dispatch — in-process modules
# ---------------------------------------------------------------------------

def test_in_process_delegates_argv_and_returncode(shell, monkeypatch):
    captured = {}

    def fake_import(path):
        m = types.ModuleType(path)
        m.main = lambda argv: captured.update(path=path, argv=argv) or 7
        return m

    monkeypatch.setattr(r, "importlib", SimpleNamespace(import_module=fake_import))
    rc = shell.execute('breach-check "victim@example.com" --json')
    assert rc == 7
    assert captured["path"] == "modules.identity.breach_checker"
    assert captured["argv"] == ["victim@example.com", "--json"]


def test_in_process_none_return_is_zero(shell, monkeypatch):
    def fake_import(path):
        m = types.ModuleType(path)
        m.main = lambda argv: None
        return m

    monkeypatch.setattr(r, "importlib", SimpleNamespace(import_module=fake_import))
    assert shell.dispatch("whois", ["x.com"]) == 0


def test_in_process_systemexit_code_preserved(shell, monkeypatch):
    def fake_import(path):
        m = types.ModuleType(path)
        m.main = lambda argv: (_ for _ in ()).throw(SystemExit(3))
        return m

    monkeypatch.setattr(r, "importlib", SimpleNamespace(import_module=fake_import))
    assert shell.dispatch("whois", ["x.com"]) == 3


def test_in_process_systemexit_none_is_zero(shell, monkeypatch):
    def fake_import(path):
        m = types.ModuleType(path)
        m.main = lambda argv: (_ for _ in ()).throw(SystemExit())
        return m

    monkeypatch.setattr(r, "importlib", SimpleNamespace(import_module=fake_import))
    assert shell.dispatch("whois", ["x.com"]) == 0


def test_in_process_crash_is_contained(shell, monkeypatch):
    def fake_import(path):
        m = types.ModuleType(path)
        m.main = lambda argv: (_ for _ in ()).throw(RuntimeError("boom"))
        return m

    monkeypatch.setattr(r, "importlib", SimpleNamespace(import_module=fake_import))
    rc = shell.dispatch("whois", ["x.com"])
    assert rc == 1
    assert "boom" in out(shell)


def test_import_failure_is_contained(shell, monkeypatch):
    def fake_import(path):
        raise ImportError("no such module")

    monkeypatch.setattr(r, "importlib", SimpleNamespace(import_module=fake_import))
    rc = shell.dispatch("whois", ["x.com"])
    assert rc == 1
    assert "Failed to import" in out(shell)


# ---------------------------------------------------------------------------
# dispatch — subprocess modes
# ---------------------------------------------------------------------------

def test_subprocess_command_composition(shell, monkeypatch):
    captured = {}

    class P:
        returncode = 0

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return P()

    monkeypatch.setattr(r.subprocess, "run", fake_run)
    rc = shell.execute("locus photo.jpg --json")
    assert rc == 0
    assert captured["cmd"] == [sys.executable, "-m", "modules.metadata.locus",
                               "photo.jpg", "--json"]


def test_subprocess_returncode_passthrough(shell, monkeypatch):
    class P:
        returncode = 5

    monkeypatch.setattr(r.subprocess, "run", lambda cmd, **kw: P())
    assert shell.dispatch("atlas", ["rome"]) == 5


# ---------------------------------------------------------------------------
# one-shot mode
# ---------------------------------------------------------------------------

def test_one_shot_help(shell):
    assert shell.run_one_shot(["--help"]) == 0
    assert "breach-check" in out(shell)


def test_one_shot_unknown(shell):
    assert shell.run_one_shot(["nope"]) == 2


def test_one_shot_exit_is_clean(shell):
    assert shell.run_one_shot(["exit"]) == 0


def test_one_shot_empty_prints_help(shell):
    assert shell.run_one_shot([]) == 0
    assert "whois" in out(shell)


# ---------------------------------------------------------------------------
# Anti-drift: the help table vs the modules' real CLI contracts
# ---------------------------------------------------------------------------
# The REPL help advertises per-command flags. Every advertised flag must be
# accepted by the module it names, and every flag a module documents must be
# advertised back -- otherwise the table drifts away from the code silently.

# Flags a module accepts but the help row deliberately does not advertise:
# compatibility aliases for command lines written before the scope model.
UNDOCUMENTED_FLAGS = {
    "dns": {"--no-bruteforce", "--no-permutations", "--no-axfr",
            "--no-takeover"},
}

FLAG_RE = re.compile(r"--[a-z][a-z0-9-]*")


def _row_flags(flags: str) -> set:
    return set(FLAG_RE.findall(flags))


def _module_help(path: str) -> str:
    """Call <module>.main(["--help"]) in-process and capture its output."""
    mod = importlib.import_module(path)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            mod.main(["--help"])
        except SystemExit:
            pass
    return buf.getvalue()


def _in_process_help_rows():
    return r.HELP_IDENTITY_ROWS + r.HELP_NETWORK_ROWS


def test_help_rows_advertise_real_module_flags():
    """REPL -> module: every advertised flag exists in the module's --help."""
    for name, _usage, flags, _desc in _in_process_help_rows():
        text = _module_help(resolve(name)[1])
        for flag in sorted(_row_flags(flags)):
            assert flag in text, (
                f"help row for '{name}' advertises {flag}, "
                f"but its --help never mentions it")


def test_module_help_flags_are_advertised_in_help_rows():
    """module -> REPL: every documented flag is advertised (aliases aside)."""
    for name, _usage, flags, _desc in _in_process_help_rows():
        text = _module_help(resolve(name)[1])
        advertised = _row_flags(flags) | UNDOCUMENTED_FLAGS.get(name, set())
        missing = sorted(set(FLAG_RE.findall(text)) - advertised)
        assert not missing, (
            f"'{name}' documents {missing} in --help but the REPL row omits "
            f"them (add them to HELP_*_ROWS)")


def test_undocumented_flag_aliases_still_exist():
    """The alias allowlist cannot outlive the flags it excuses."""
    for name, aliases in UNDOCUMENTED_FLAGS.items():
        text = _module_help(resolve(name)[1])
        for flag in sorted(aliases):
            assert flag in text, f"'{name}' no longer accepts {flag}"


def test_atlas_help_row_matches_its_usage_line():
    """atlas has no --help (text is positional): its usage line is the contract."""
    atlas_flags = None
    for name, _usage, flags, _desc in r.HELP_METADATA_ROWS:
        if name == "atlas":
            atlas_flags = _row_flags(flags)
    assert atlas_flags is not None, "atlas row disappeared from the table"

    proc = subprocess.run(
        [sys.executable, "-m", "modules.metadata.atlas", "--full"],
        capture_output=True, text=True, timeout=120)
    text = proc.stdout + proc.stderr
    assert "Usage:" in text  # --full is stripped, then the usage is printed
    documented = set(FLAG_RE.findall(text))
    assert documented <= atlas_flags, (
        f"atlas CLI documents {sorted(documented)} but the help row "
        f"advertises {sorted(atlas_flags)}")
    assert "--full" in documented


# ---------------------------------------------------------------------------
# Usage lines speak the REPL language — never "python -m modules..."
# ---------------------------------------------------------------------------
# The shell announces the command name to the module (in-process through
# modules/usage.repl_command, in a subprocess through NEXUS_PROG), so a
# misuse inside the shell advertises the command the user can retype.

IN_PROCESS_NAMES = sorted(r.IN_PROCESS_COMMANDS)


def test_misuse_reports_the_repl_command(shell, capsys):
    """A rejected invocation must show "Usage: <command> ..."."""
    for name in IN_PROCESS_NAMES:
        shell.dispatch(name, ["--definitely-not-a-flag"])
        text = capsys.readouterr()
        combined = text.out + text.err
        assert f"Usage: {name}" in combined, f"{name}: no REPL usage line"
        assert "python -m" not in combined, f"{name}: leaked the python -m path"


def test_help_reports_the_repl_command(shell, capsys):
    """`help <cmd>` prints the module help with the REPL usage line."""
    for name in IN_PROCESS_NAMES:
        shell.dispatch("help", [name])
        text = capsys.readouterr()
        combined = text.out + text.err
        assert f"Usage: {name}" in combined, f"{name}: help shows no REPL usage"
        assert "python -m" not in combined, f"{name}: help leaked python -m"


def test_alias_misuse_names_the_canonical_command(shell, capsys):
    """Typing an old alias still reports the documented command."""
    shell.execute("port_scanner --definitely-not-a-flag")
    text = capsys.readouterr()
    combined = text.out + text.err
    assert "Usage: ports" in combined
    assert "python -m" not in combined


def test_subprocess_modes_announce_the_repl_command(shell, monkeypatch):
    """Metadata modes learn the REPL name through the environment."""
    captured = {}

    class P:
        returncode = 0

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env") or {}
        return P()

    monkeypatch.setattr(r.subprocess, "run", fake_run)
    assert shell.dispatch("atlas", ["rome"]) == 0
    assert captured["env"][r.ENV_VAR] == "atlas"
    assert captured["cmd"] == [sys.executable, "-m", "modules.metadata.atlas", "rome"]


def test_whois_no_args_and_multi_guard_speak_repl(shell, capsys):
    """The two output-only branches of whois (no-args, multi guard)."""
    for args in ([], ["a.com", "b.com"]):
        shell.dispatch("whois", args)
        text = capsys.readouterr()
        combined = text.out + text.err
        assert "Usage: whois" in combined, f"args={args}: no REPL usage line"
        assert "python -m" not in combined, f"args={args}: leaked python -m"


def test_module_run_directly_keeps_the_python_m_form(capsys):
    """Outside the shell the python -m path is the real command."""
    mod = importlib.import_module("modules.network.port_scanner")
    mod.main(["--definitely-not-a-flag"])
    text = capsys.readouterr()
    assert "python -m modules.network.port_scanner" in text.out + text.err


# ---------------------------------------------------------------------------
# Prompt color
# ---------------------------------------------------------------------------

def test_prompt_greens_nexus_on_a_terminal(monkeypatch):
    fake = SimpleNamespace(isatty=lambda: True)
    monkeypatch.setattr(r, "sys", SimpleNamespace(stdout=fake))
    assert r._plain_prompt() == "\x1b[1;32mNexus\x1b[0m> "


def test_prompt_is_plain_off_a_terminal(monkeypatch):
    fake = SimpleNamespace(isatty=lambda: False)
    monkeypatch.setattr(r, "sys", SimpleNamespace(stdout=fake))
    assert r._plain_prompt() == "Nexus> "


def test_styled_prompt_marks_only_nexus_green():
    from prompt_toolkit.formatted_text import to_formatted_text
    from prompt_toolkit.formatted_text.utils import to_plain_text

    prompt = r._styled_prompt()
    assert to_plain_text(prompt) == "Nexus> "
    styled = list(to_formatted_text(prompt))
    label = [item for item in styled if item[1] == "Nexus"]
    assert label and "ansigreen" in label[0][0]
    assert "ansigreen" not in [item[0] for item in styled if item[1] == "> "][0]
