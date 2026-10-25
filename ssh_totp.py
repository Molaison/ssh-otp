#!/usr/bin/env python3
"""Shared core for the SSH-over-OTP setup.

Responsibilities:
  * Parse ~/.ssh/config (case-sensitive Host aliases, glob patterns, and the
    ``# totp_secret:`` / ``# totp_prompt:`` metadata comments).
  * Resolve which TOTP secret answers a given target -- directly, or by
    following a native ``ProxyJump`` (or the legacy debug_proxy ProxyCommand)
    to the OTP gateway that actually issues the challenge.
  * Discover the *right* real ssh binary (on Windows: a git/msys build that
    supports connection multiplexing; never this wrapper; only System32 ssh as
    a last resort, since it cannot multiplex).
  * Inject ControlMaster/ControlPath/ControlPersist so one auth serves many
    connections, and run the real ssh with SSH_ASKPASS wired to the TOTP
    generator.

Used by: the ``sshotp`` wrapper (and the ``bin/ssh`` shim), ``otpctl``, and the
regression tests. Public surface kept stable: ``resolve_totp_for_args``,
``normalize_totp_args`` and ``main``.
"""
import fnmatch
import hashlib
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
MUX_DIR = os.path.expanduser("~/.ssh/cm")
# ControlPath handed to ssh. %C is a fixed-length hash -> always a valid
# filename (incl. Windows) and OpenSSH expands the leading ~ itself.
CONTROL_PATH = "~/.ssh/cm/%C"
CONTROL_PERSIST = "8h"
DEFAULT_SOCKS = "127.0.0.1:7070"
DEFAULT_JUMP_ALIAS = "x"
SOCKS_CLIENT_DRAIN_GRACE_SECONDS = 2.0
SOCKS_CONNECT_TIMEOUT_SECONDS = 0.5
SOCKS_START_READY_TIMEOUT_SECONDS = 15.0
SOCKS_START_LOCK_TIMEOUT_SECONDS = 120.0
SOCKS_START_STALE_LOCK_SECONDS = 180.0
SOCKS_START_POLL_SECONDS = 0.2

OPTIONS_WITH_VALUE = {
    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L",
    "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
}
# Options we force on for OTP targets so the keyboard-interactive challenge is
# actually offered and answered by SSH_ASKPASS (any caller-supplied copies are
# stripped first by normalize_totp_args).
TOTP_FORCED_OPTIONS = {
    "batchmode": "no",
    "kbdinteractiveauthentication": "yes",
    "numberofpasswordprompts": "3",
}


def _is_windows() -> bool:
    return os.name == "nt"


# --------------------------------------------------------------------------- #
# ssh argv parsing
# --------------------------------------------------------------------------- #
def _target_from_ssh_args(args: List[str]) -> Optional[str]:
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--":
            continue
        if arg in OPTIONS_WITH_VALUE:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def _args_through_target(args: List[str]) -> List[str]:
    """Return SSH args through the target, dropping the remote command."""
    result: List[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            result.append(arg)
            skip_next = False
            continue
        if arg == "--":
            result.append(arg)
            continue
        if arg in OPTIONS_WITH_VALUE:
            result.append(arg)
            skip_next = True
            continue
        if arg.startswith("-"):
            result.append(arg)
            continue
        result.append(arg)
        return result
    return result


def _host_part(target: str) -> str:
    return target.rsplit("@", 1)[-1]


def _hop_host(hop: str) -> str:
    """Extract the bare host from a ProxyJump hop like ``user@host:port``."""
    host = _host_part(hop.strip())
    if host.count(":") == 1 and not host.startswith("["):
        host = host.rsplit(":", 1)[0]
    return host


def _gateway_from_tokens(tokens: List[str]) -> Optional[str]:
    """Explicit gateway alias carried by a ProxyCommand (``--gateway ALIAS``)."""
    for index, token in enumerate(tokens):
        if token in {"--gateway", "-g"} and index + 1 < len(tokens):
            return tokens[index + 1]
        if token.startswith("--gateway="):
            return token.split("=", 1)[1]
    return None


def _program_name(command: str) -> str:
    return re.split(r"[\\/]", command.strip("\"'"))[-1].lower()


def ssh_config_path(configured: Optional[str] = None) -> str:
    """Path of the ssh config this wrapper parses (``SSH_TOTP_CONFIG`` wins)."""
    if configured:
        return configured
    override = os.environ.get("SSH_TOTP_CONFIG", "").strip()
    return override or os.path.expanduser("~/.ssh/config")


def _config_gateway_alias(config_file: str) -> Optional[str]:
    """Gateway alias recorded in the ssh config itself.

    ``configure`` writes ``# totp_gateway:``; hand-written configs fall back to
    the first host marked ``# totp_master: yes``.
    """
    blocks, _metadata = _read_config(config_file)
    for _aliases, _options, metadata in blocks:
        gateway = metadata.get("totp_gateway", "").strip()
        if gateway:
            return gateway
    for aliases, _options, metadata in blocks:
        if metadata.get("totp_master", "").strip().lower() in {"1", "true", "yes", "on"}:
            if aliases:
                return aliases[0]
    return None


def default_jump_alias(config_file: Optional[str] = None) -> str:
    """Resolve the gateway alias instead of assuming it is ``x``.

    ``SSH_TOTP_JUMP_ALIAS`` wins, then what the ssh config records, and only
    then the historical default. Any config produced by ``configure`` (with any
    ``--jump-alias``) therefore drives automatic startup without extra env.
    """
    override = os.environ.get("SSH_TOTP_JUMP_ALIAS", "").strip()
    if override:
        return override
    return _config_gateway_alias(ssh_config_path(config_file)) or DEFAULT_JUMP_ALIAS


def _ssh_option_key(option: str) -> str:
    return re.split(r"[=\s]+", option.strip(), maxsplit=1)[0].lower()


def normalize_totp_args(args: List[str]) -> List[str]:
    normalized: List[str] = []
    index = 0

    while index < len(args):
        arg = args[index]

        if arg == "-o":
            if index + 1 >= len(args):
                normalized.append(arg)
                index += 1
                continue
            option = args[index + 1]
            if _ssh_option_key(option) not in TOTP_FORCED_OPTIONS:
                normalized.extend([arg, option])
            index += 2
            continue

        if arg.startswith("-o") and len(arg) > 2:
            option = arg[2:].lstrip()
            if _ssh_option_key(option) not in TOTP_FORCED_OPTIONS:
                normalized.append(arg)
            index += 1
            continue

        if arg in OPTIONS_WITH_VALUE:
            normalized.append(arg)
            if index + 1 < len(args):
                normalized.append(args[index + 1])
            index += 2
            continue

        if arg.startswith("-"):
            normalized.append(arg)
            index += 1
            continue

        forced_args: List[str] = []
        for key, value in TOTP_FORCED_OPTIONS.items():
            forced_args.extend(["-o", f"{key}={value}"])
        return [*normalized, *forced_args, *args[index:]]

    forced_args = []
    for key, value in TOTP_FORCED_OPTIONS.items():
        forced_args.extend(["-o", f"{key}={value}"])
    return [*normalized, *forced_args]


# --------------------------------------------------------------------------- #
# config parsing
# --------------------------------------------------------------------------- #
def _read_config(config_path: str) -> Tuple[List[Tuple[List[str], Dict[str, str], Dict[str, str]]], Dict[str, Dict[str, str]]]:
    blocks: List[Tuple[List[str], Dict[str, str], Dict[str, str]]] = []
    metadata_by_alias: Dict[str, Dict[str, str]] = {}
    current_aliases: List[str] = []
    current_options: Dict[str, str] = {}
    current_metadata: Dict[str, str] = {}
    pending_metadata: Dict[str, str] = {}

    def flush() -> None:
        nonlocal current_aliases, current_options, current_metadata
        if current_aliases:
            blocks.append((current_aliases, current_options, current_metadata))
            for alias in current_aliases:
                if current_metadata:
                    metadata_by_alias[alias] = dict(current_metadata)
        current_aliases = []
        current_options = {}
        current_metadata = {}

    if not os.path.exists(config_path):
        return blocks, metadata_by_alias

    with open(config_path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            stripped = raw_line.strip()
            lower = stripped.lower()
            if stripped.startswith("#"):
                meta = re.match(
                    r"#\s*(totp_secret|totp_prompt|totp_master|totp_gateway)\s*:\s*(.*)$",
                    stripped,
                    re.IGNORECASE,
                )
                if meta:
                    pending_metadata[meta.group(1).lower()] = meta.group(2).strip()
                continue
            if not stripped:
                continue
            if lower.startswith("host "):
                flush()
                current_aliases = stripped[5:].split()
                current_metadata = dict(pending_metadata)
                pending_metadata = {}
                continue
            if lower.startswith("match "):
                # We do not evaluate Match blocks; end the current Host scope.
                flush()
                pending_metadata = {}
                continue
            if not current_aliases:
                pending_metadata = {}
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2:
                current_options.setdefault(parts[0].lower(), parts[1])
            pending_metadata = {}
    flush()
    return blocks, metadata_by_alias


def _alias_matches(alias: str, patterns: List[str]) -> bool:
    """OpenSSH Host matching: case-sensitive glob, ``!`` negation wins."""
    positive = False
    for pattern in patterns:
        negative = pattern.startswith("!")
        raw = pattern[1:] if negative else pattern
        if fnmatch.fnmatchcase(alias, raw):
            if negative:
                return False
            positive = True
    return positive


def _load_ssh_config(alias: str, config_path: str) -> Dict[str, str]:
    """Merge every block whose pattern matches ``alias`` (first value wins)."""
    blocks, _ = _read_config(config_path)
    merged: Dict[str, str] = {}
    for aliases, options, _metadata in blocks:
        if _alias_matches(alias, aliases):
            for key, value in options.items():
                merged.setdefault(key, value)
    return merged


def _find_alias_for_host(config_path: str, host: str) -> Optional[str]:
    blocks, _ = _read_config(config_path)
    for aliases, options, _metadata in blocks:
        hostname = options.get("hostname", "")
        for alias in aliases:
            if alias == host or hostname == host:
                return alias
    return None


def _metadata_totp(config_path: str, alias: str) -> Optional[dict]:
    _blocks, metadata_by_alias = _read_config(config_path)
    metadata = metadata_by_alias.get(alias, {})
    secret = metadata.get("totp_secret", "")
    if not secret:
        return None
    return {
        "alias": alias,
        "secret": secret,
        "prompt": metadata.get("totp_prompt", ""),
        "master": metadata.get("totp_master", "").lower() in {"1", "true", "yes", "on"},
        "via_proxy": False,
    }


def _proxy_targets(config_path: str, alias: str) -> List[str]:
    """Jump hosts for ``alias`` -- native ProxyJump first, then ProxyCommand."""
    config = _load_ssh_config(alias, config_path)
    targets: List[str] = []

    proxy_jump = config.get("proxyjump", "")
    if proxy_jump and proxy_jump.strip().lower() != "none":
        for hop in proxy_jump.split(","):
            host = _hop_host(hop)
            if host:
                targets.append(host)

    proxy_command = config.get("proxycommand", "")
    if proxy_command:
        try:
            tokens = shlex.split(proxy_command)
        except ValueError:
            tokens = proxy_command.split()
        if tokens and tokens[0] == "exec":
            tokens = tokens[1:]
        if tokens:
            proxy_program = _program_name(tokens[0])
            if proxy_program in {"ssh", "ssh.exe"}:
                target = _target_from_ssh_args(tokens[1:])
                if target:
                    targets.append(_host_part(target))
            elif proxy_program in {"debug_proxy.cmd", "debug_proxy.sh", "debug_proxy_win.py"}:
                targets.append(_gateway_from_tokens(tokens) or default_jump_alias(config_path))
            elif proxy_program in {"sshotp", "sshotp.cmd", "ssh_totp.py"} and "--socks" in tokens:
                targets.append(_gateway_from_tokens(tokens) or default_jump_alias(config_path))
            elif len(tokens) > 1 and _program_name(tokens[1]) == "ssh_totp.py" and "--socks" in tokens:
                targets.append(_gateway_from_tokens(tokens) or default_jump_alias(config_path))
            else:
                targets.extend(
                    _host_part(m) for m in re.findall(r"[\w.-]+@([A-Za-z0-9_.-]+)", proxy_command)
                )

    return targets


def resolve_totp_for_args(args: List[str], config_path: Optional[str] = None) -> Optional[dict]:
    """Return the TOTP metadata that answers the target in ``args`` (or None)."""
    if config_path is None:
        config_path = ssh_config_path()
    target = _target_from_ssh_args(args)
    if not target:
        return None

    direct_host = _host_part(target)
    direct_alias = _find_alias_for_host(config_path, direct_host) or direct_host
    direct_totp = _metadata_totp(config_path, direct_alias)
    if direct_totp:
        return direct_totp

    for proxy_host in _proxy_targets(config_path, direct_alias):
        proxy_alias = _find_alias_for_host(config_path, proxy_host) or proxy_host
        proxy_totp = _metadata_totp(config_path, proxy_alias)
        if proxy_totp:
            proxy_totp["via_proxy"] = True
            return proxy_totp
    return None


# --------------------------------------------------------------------------- #
# real ssh discovery (must support ControlMaster; never self; System32 last)
# --------------------------------------------------------------------------- #
def _under_dir(path: str, directory: str) -> bool:
    try:
        path = os.path.normcase(os.path.realpath(path))
        directory = os.path.normcase(os.path.realpath(directory))
    except Exception:
        return False
    return path == directory or path.startswith(directory + os.sep)


def _is_system32_ssh(path: str) -> bool:
    p = os.path.normcase(os.path.realpath(path))
    return "system32" in p and "openssh" in p


def _which_all(name: str) -> List[str]:
    found: List[str] = []
    exts = [".exe", ".EXE", ""] if _is_windows() else [""]
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        for ext in exts:
            candidate = os.path.join(directory, name + ext)
            if os.path.isfile(candidate) and candidate not in found:
                found.append(candidate)
    return found


def _real_ssh_executable() -> str:
    """Locate the ssh binary to run.

    Preference order matters: on Windows the git/msys ssh supports connection
    multiplexing (ControlMaster) while System32 OpenSSH does not, so System32 is
    only used as a last resort. Set SSH_TOTP_REAL_SSH to override entirely.
    """
    configured = os.environ.get("SSH_TOTP_REAL_SSH", "")
    if configured and os.path.isfile(configured):
        return configured

    script_dir = os.path.realpath(SCRIPT_DIR)
    self_paths = {os.path.realpath(p) for p in ([__file__] + (sys.argv[:1] if sys.argv else [])) if p}

    def usable(path: str, allow_system32: bool = True) -> bool:
        if not path or not os.path.isfile(path):
            return False
        rp = os.path.realpath(path)
        if rp in self_paths:
            return False
        if _under_dir(rp, script_dir):  # our own bin/ssh shims live here
            return False
        if _is_windows() and not allow_system32 and _is_system32_ssh(rp):
            return False
        if not _is_windows() and not os.access(rp, os.X_OK):
            return False
        return True

    candidates: List[str] = []
    if _is_windows():
        candidates += [
            r"D:\Git\usr\bin\ssh.exe",
            os.path.expanduser(r"~\scoop\apps\git\current\usr\bin\ssh.exe"),
            r"C:\Program Files\Git\usr\bin\ssh.exe",
        ]
        candidates += _which_all("ssh")
    else:
        if sys.platform == "darwin":
            candidates += ["/opt/homebrew/bin/ssh", "/usr/local/bin/ssh"]
        prefix = os.environ.get("PREFIX", "")  # Termux
        if prefix:
            candidates.append(os.path.join(prefix, "bin", "ssh"))
        candidates += ["/usr/bin/ssh", "/bin/ssh", "/data/data/com.termux/files/usr/bin/ssh"]
        candidates += _which_all("ssh")

    # First pass: multiplex-capable ssh (excludes System32 on Windows).
    for candidate in candidates:
        if usable(candidate, allow_system32=False):
            return candidate
    # Last resort: anything usable (e.g. System32 ssh -- no multiplexing).
    for candidate in candidates:
        if usable(candidate, allow_system32=True):
            return candidate

    raise FileNotFoundError("ssh executable not found")


def _plain_ssh_executable() -> str:
    """Locate the plain OpenSSH client for transparent config-driven targets."""
    configured = os.environ.get("SSH_TOTP_PLAIN_SSH", "")
    if configured and os.path.isfile(configured):
        return configured
    if _is_windows():
        system32 = r"C:\Windows\System32\OpenSSH\ssh.exe"
        if os.path.isfile(system32):
            return system32
    return _real_ssh_executable()


# --------------------------------------------------------------------------- #
# multiplexing + environment
# --------------------------------------------------------------------------- #
def _has_o_option(argv: List[str], name: str) -> bool:
    name_l = name.lower()
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "-o" and i + 1 < len(argv):
            if argv[i + 1].split("=", 1)[0].strip().lower() == name_l:
                return True
            i += 2
            continue
        if arg.startswith("-o") and len(arg) > 2:
            if arg[2:].split("=", 1)[0].strip().lower() == name_l:
                return True
        i += 1
    return False


def multiplex_args(argv: List[str]) -> List[str]:
    """ControlMaster options to add, skipping any the caller already set."""
    extra: List[str] = []
    has_master = _has_o_option(argv, "controlmaster") or "-M" in argv
    has_path = _has_o_option(argv, "controlpath") or "-S" in argv
    has_persist = _has_o_option(argv, "controlpersist")
    if not has_path:
        try:
            os.makedirs(MUX_DIR, exist_ok=True)
        except Exception:
            pass
        # Absolute path (forward slashes) so the dir we just created always
        # matches the socket path ssh uses, regardless of how it expands ~.
        extra += ["-o", "ControlPath=" + os.path.join(MUX_DIR, "%C").replace("\\", "/")]
    if not has_master:
        extra += ["-o", "ControlMaster=auto"]
    if not has_persist:
        extra += ["-o", "ControlPersist=" + CONTROL_PERSIST]
    return extra


def _has_short_flag(argv: List[str], flag: str) -> bool:
    """Return whether SSH argv contains a flag like -N, including -MNf."""
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            return False
        if arg == "-o":
            i += 2
            continue
        if arg in OPTIONS_WITH_VALUE:
            i += 2
            continue
        if arg.startswith("-o") or arg.startswith("--"):
            i += 1
            continue
        if arg.startswith("-"):
            if flag in arg[1:]:
                return True
            i += 1
            continue
        return False
    return False


def _has_dynamic_forward(argv: List[str]) -> bool:
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            return False
        if arg == "-D" or arg.startswith("-D"):
            return True
        if arg == "-o":
            i += 2
            continue
        if arg in OPTIONS_WITH_VALUE:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return False
    return False


def socks_master_args(argv: List[str]) -> List[str]:
    """Open the gateway SOCKS listener for master sessions such as ssh -MNf X."""
    if not _has_short_flag(argv, "N"):
        return []
    extra: List[str] = []
    if not _has_dynamic_forward(argv):
        extra += ["-D", os.environ.get("SSH_OTP_SOCKS", DEFAULT_SOCKS)]
    if not _has_o_option(argv, "exitonforwardfailure"):
        # Without this, ssh backgrounds successfully after a bind failure and
        # leaves an unusable orphan master behind. The caller then sees exit 0
        # even though no SOCKS listener exists.
        extra += ["-o", "ExitOnForwardFailure=yes"]
    return extra


def _uses_master_control(argv: List[str]) -> bool:
    return _has_short_flag(argv, "N") or "-O" in argv


def _expanded_controlpath(real_ssh: str, argv: List[str], mux: List[str]) -> Optional[str]:
    base = _args_through_target(argv)
    if not _target_from_ssh_args(base):
        return None
    try:
        result = subprocess.run(
            [real_ssh, "-G", *mux, *base],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key.lower() == "controlpath":
            return value.strip()
    return None


def _prune_stale_control_socket(real_ssh: str, argv: List[str], mux: List[str]) -> None:
    if "-O" in argv:
        return
    controlpath = _expanded_controlpath(real_ssh, argv, mux)
    if not controlpath or not os.path.exists(controlpath):
        return
    base = _args_through_target(argv)
    check = subprocess.run(
        [real_ssh, *mux, "-O", "check", *base],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check.returncode != 0:
        os.unlink(controlpath)


def _askpass_program() -> str:
    name = "totp_askpass.cmd" if _is_windows() else "totp_askpass.py"
    return os.path.join(SCRIPT_DIR, name)


def _explicit_config_args() -> List[str]:
    """``-F`` pin so ssh reads the same config this wrapper parsed.

    Only applied when ``SSH_TOTP_CONFIG`` is set, so the default path keeps
    ssh's own resolution (and hand-written configs stay untouched).
    """
    override = os.environ.get("SSH_TOTP_CONFIG", "").strip()
    if override and os.path.isfile(override):
        return ["-F", override]
    return []


def _env_with_totp(totp: Optional[dict], real_ssh: str) -> dict:
    env = os.environ.copy()
    env["SSH_TOTP_REAL_SSH"] = real_ssh
    if not totp:
        for key in ("SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "SSH_TOTP_SECRET", "SSH_TOTP_PROMPT_PATTERN"):
            env.pop(key, None)
        return env
    env["SSH_ASKPASS"] = _askpass_program()
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["SSH_TOTP_SECRET"] = totp["secret"]
    if totp.get("prompt"):
        env["SSH_TOTP_PROMPT_PATTERN"] = totp["prompt"]
    env.setdefault("DISPLAY", ":0")
    return env


def run_wrapper(argv: List[str], stdio: Optional[tuple] = None) -> int:
    """The sshotp behaviour: resolve OTP, add multiplexing, exec real ssh.

    Every OTP target is multiplexed, not just ``-N`` masters: one authenticated
    connection then serves shells, scp, git and IDE probes for ControlPersist,
    instead of each one burning a fresh single-use code. ``stdio`` overrides the
    inherited descriptors (used by background masters that must not hold the
    caller's pipes open).
    """
    totp = resolve_totp_for_args(argv)
    real_ssh = _real_ssh_executable()
    pin = _explicit_config_args()
    if totp:
        if totp.get("via_proxy"):
            cmd = [_plain_ssh_executable(), *pin, *argv]
            env = _env_with_totp(None, real_ssh)
        else:
            final = [*pin, *normalize_totp_args(argv)]
            mux = multiplex_args(final)
            if totp.get("master") and _uses_master_control(final):
                _prune_stale_control_socket(real_ssh, final, mux)
                cmd = [real_ssh, *mux, *socks_master_args(final), *final]
            else:
                cmd = [real_ssh, *mux, *final]
            env = _env_with_totp(totp, real_ssh)
    else:
        cmd = [_plain_ssh_executable(), *pin, *argv]
        env = _env_with_totp(None, real_ssh)
    if stdio is None:
        return subprocess.call(cmd, env=env)
    return subprocess.call(cmd, env=env, stdin=stdio[0], stdout=stdio[1], stderr=stdio[2])


def _run_detached(argv: List[str]) -> int:
    """Start a background gateway master without inheriting our stdio.

    ``ssh -f`` leaves the forked master holding the inherited stderr, so any
    caller that reads a pipe (``otp-up x | cat``, script subprocess.PIPE, IDE
    log capture) would wait for EOF forever after the output was produced.
    """
    stderr_target = subprocess.DEVNULL
    log_handle = None
    log_path = os.environ.get("SSH_TOTP_SOCKS_LOG", "")
    if log_path:
        try:
            log_handle = open(log_path, "a", encoding="utf-8")
            stderr_target = log_handle
        except OSError:
            log_handle = None
    try:
        return run_wrapper(
            argv, stdio=(subprocess.DEVNULL, subprocess.DEVNULL, stderr_target)
        )
    finally:
        if log_handle is not None:
            log_handle.close()


def _socks_address(socks: str) -> Tuple[str, int]:
    host, separator, port = socks.rpartition(":")
    if not separator or not port:
        raise ValueError(f"invalid SSH_OTP_SOCKS address: {socks!r}")
    return host or "127.0.0.1", int(port)


def _connect_socks(socks: str, timeout: float = SOCKS_CONNECT_TIMEOUT_SECONDS):
    connection = socket.create_connection(_socks_address(socks), timeout=timeout)
    # create_connection leaves the timeout on the returned socket. That is
    # useful for the readiness probe but fatal for the long-lived ProxyCommand
    # relay: a quiet 0.5 s interval would otherwise tear down a healthy SSH
    # session. Restore normal blocking mode before handing the socket over.
    settimeout = getattr(connection, "settimeout", None)
    if settimeout:
        settimeout(None)
    return connection


def _socks_start_lock_path(socks: str) -> str:
    state_dir = os.environ.get("SSH_TOTP_STATE_DIR", "")
    if not state_dir:
        state_dir = os.path.join(tempfile.gettempdir(), "codex-ssh-totp")
    os.makedirs(state_dir, exist_ok=True)
    key = hashlib.sha256(socks.encode("utf-8")).hexdigest()[:16]
    return os.path.join(state_dir, f"socks-start-{key}.lock")


def _process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if _is_windows():
        import ctypes

        process_query_limited_information = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(
            process_query_limited_information, False, pid
        )
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _socks_start_lock_is_stale(lock_path: str) -> bool:
    try:
        stat = os.stat(lock_path)
        with open(lock_path, "r", encoding="ascii") as handle:
            owner = handle.read().strip()
    except FileNotFoundError:
        return False
    except (OSError, UnicodeError):
        return time.time() - stat.st_mtime > SOCKS_START_STALE_LOCK_SECONDS
    try:
        pid = int(owner.split(":", 1)[0])
    except (TypeError, ValueError):
        return time.time() - stat.st_mtime > SOCKS_START_STALE_LOCK_SECONDS
    return (
        not _process_is_alive(pid)
        or time.time() - stat.st_mtime > SOCKS_START_STALE_LOCK_SECONDS
    )


def _acquire_socks_start_lock(socks: str) -> Tuple[int, str, str]:
    lock_path = _socks_start_lock_path(socks)
    deadline = time.monotonic() + SOCKS_START_LOCK_TIMEOUT_SECONDS
    token = f"{os.getpid()}:{time.time_ns()}"
    while True:
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(lock_fd, token.encode("ascii"))
            os.fsync(lock_fd)
            return lock_fd, lock_path, token
        except FileExistsError:
            if _socks_start_lock_is_stale(lock_path):
                try:
                    os.unlink(lock_path)
                except FileNotFoundError:
                    pass
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting to start gateway SOCKS {socks}")
            time.sleep(SOCKS_START_POLL_SECONDS)


def _release_socks_start_lock(lock_fd: int, lock_path: str, token: str) -> None:
    os.close(lock_fd)
    try:
        with open(lock_path, "r", encoding="ascii") as handle:
            current = handle.read().strip()
        if current == token:
            os.unlink(lock_path)
    except FileNotFoundError:
        pass


def _socks_auto_start_enabled() -> bool:
    value = os.environ.get("SSH_TOTP_AUTO_START", "1").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _gateway_master_state(jump_alias: str) -> int:
    """Return 0 when a multiplexing master for the gateway is already running."""
    return run_wrapper(["-O", "check", jump_alias], stdio=(subprocess.DEVNULL,) * 3)


def cmd_up(jump_alias: Optional[str] = None) -> int:
    """Expose the gateway SOCKS listener, reusing an existing master if any."""
    socks = os.environ.get("SSH_OTP_SOCKS", DEFAULT_SOCKS)
    try:
        _ensure_socks_connection(socks, jump_alias)
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        print(f"otp: cannot prepare gateway SOCKS {socks} ({exc})", file=sys.stderr)
        return 1
    return 0


def _gateway_control(alias: str, action: str) -> int:
    totp = resolve_totp_for_args([alias])
    if not totp:
        print(f"otp: {alias} has no TOTP metadata", file=sys.stderr)
        return 1
    if totp.get("via_proxy"):
        print(f"otp: {alias} is reached through gateway {totp['alias']}", file=sys.stderr)
        return 1
    return run_wrapper(["-O", action, alias])


def cmd_status(jump_alias: Optional[str] = None) -> int:
    return _gateway_control(jump_alias or default_jump_alias(), "check")


def cmd_down(jump_alias: Optional[str] = None) -> int:
    return _gateway_control(jump_alias or default_jump_alias(), "exit")


def _ensure_socks_connection(socks: str, jump_alias: Optional[str] = None):
    """Return a live SOCKS socket, starting the OTP gateway master if needed."""
    try:
        return _connect_socks(socks)
    except OSError as initial_error:
        if not _socks_auto_start_enabled():
            raise RuntimeError(
                f"gateway SOCKS {socks} is unavailable and SSH_TOTP_AUTO_START is disabled"
            ) from initial_error

    lock_fd, lock_path, token = _acquire_socks_start_lock(socks)
    try:
        try:
            return _connect_socks(socks)
        except OSError:
            pass

        config_file = ssh_config_path()
        jump_alias = jump_alias or default_jump_alias(config_file)
        config_args: List[str] = []
        if _gateway_master_state(jump_alias) == 0:
            # A master already serves this gateway: attach the SOCKS listener to
            # it instead of authenticating a second time (masters allow adding
            # forwards later, and the forward lives as long as the master).
            result = run_wrapper(
                ["-O", "forward", "-D", socks, jump_alias],
                stdio=(subprocess.DEVNULL,) * 3,
            )
        else:
            start_argv = ["-MNf", "-D", socks, *config_args, jump_alias]
            result = _run_detached(start_argv)
        if result != 0:
            raise RuntimeError(
                f"automatic gateway start failed for {jump_alias} with exit code {result}"
            )

        deadline = time.monotonic() + SOCKS_START_READY_TIMEOUT_SECONDS
        last_error = None
        while True:
            try:
                return _connect_socks(socks)
            except OSError as exc:
                last_error = exc
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"gateway {jump_alias} started but SOCKS {socks} did not become ready: {last_error}"
                ) from last_error
            time.sleep(SOCKS_START_POLL_SECONDS)
    finally:
        _release_socks_start_lock(lock_fd, lock_path, token)


def _log_socks_relay(message: str) -> None:
    log_path = os.environ.get("SSH_TOTP_SOCKS_LOG", "")
    if not log_path:
        return
    try:
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} pid={os.getpid()} {message}\n")
    except OSError:
        pass


def _socks_relay(host: str, port: str) -> int:
    """ProxyCommand: relay stdio to host:port through the gateway SOCKS proxy.

    The gateway master (auto-started on demand, or opened by ``otp-up x``)
    exposes a SOCKS5 port via ``-D``.
    Jump hosts tunnel through it -- this avoids ssh's ``-W`` stdio-forward, which
    the Windows git/msys ssh master cannot service (``mux_client_request_stdio_fwd:
    read from master failed``). Works uniformly on every platform.
    """
    import struct
    import threading

    socks = os.environ.get("SSH_OTP_SOCKS", DEFAULT_SOCKS)
    try:
        sock = _ensure_socks_connection(socks)
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        sys.stderr.write(
            f"sshotp --socks: cannot prepare gateway SOCKS {socks} ({exc}). "
            f"Manual fallback: 'otp-up {default_jump_alias()}'.\n"
        )
        return 1
    _log_socks_relay(f"connected socks={socks} target={host}:{port}")

    hb = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode()
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        sys.stderr.write("sshotp --socks: SOCKS5 auth negotiation failed\n")
        return 1
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", int(port)))
    rep = sock.recv(4)
    if len(rep) < 4 or rep[1] != 0x00:
        code = rep[1] if len(rep) > 1 else -1
        sys.stderr.write(f"sshotp --socks: SOCKS connect to {host}:{port} failed (code {code})\n")
        return 1
    atyp = rep[3]
    if atyp == 0x01:
        sock.recv(4 + 2)
    elif atyp == 0x03:
        sock.recv(sock.recv(1)[0] + 2)
    elif atyp == 0x04:
        sock.recv(16 + 2)
    _log_socks_relay("handshake-complete")

    in_fd = sys.stdin.fileno()
    out_fd = sys.stdout.fileno()

    def close_stdout_pipe() -> None:
        try:
            os.close(out_fd)
        except OSError:
            return
        sys.stdout = None
        _log_socks_relay("stdout-closed")

    def pump_stdin() -> None:
        try:
            while True:
                data = os.read(in_fd, 65536)
                if not data:
                    _log_socks_relay("stdin-eof")
                    break
                _log_socks_relay(f"stdin-read bytes={len(data)}")
                sock.sendall(data)
        except OSError as exc:
            _log_socks_relay(f"stdin-error error={exc!r}")
        finally:
            try:
                sock.shutdown(socket.SHUT_WR)
                _log_socks_relay("socket-shutdown-write")
            except OSError as exc:
                _log_socks_relay(f"socket-shutdown-write-error error={exc!r}")

    stdin_thread = threading.Thread(target=pump_stdin, daemon=True)
    stdin_thread.start()
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                _log_socks_relay("socket-eof")
                break
            written = os.write(out_fd, data)
            _log_socks_relay(f"socket-read bytes={len(data)} stdout-write={written}")
    except OSError as exc:
        _log_socks_relay(f"socket-or-stdout-error error={exc!r}")
    finally:
        close_stdout_pipe()
        stdin_thread.join(SOCKS_CLIENT_DRAIN_GRACE_SECONDS)
        _log_socks_relay(f"stdin-thread-alive={stdin_thread.is_alive()}")
        try:
            sock.close()
            _log_socks_relay("socket-closed")
        except OSError as exc:
            _log_socks_relay(f"socket-close-error error={exc!r}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "--resolve-totp":
        totp = resolve_totp_for_args(argv[1:])
        if not totp:
            print("none")
            return 1
        print(totp["alias"])
        return 0
    if argv and argv[0] == "--real-ssh":
        print(_real_ssh_executable())
        return 0
    if argv and argv[0] == "--default-jump":
        print(default_jump_alias(argv[1] if len(argv) > 1 else None))
        return 0
    if argv and argv[0] in {"--up", "--status", "--down"}:
        alias = argv[1] if len(argv) > 1 else None
        if argv[0] == "--up":
            return cmd_up(alias)
        if argv[0] == "--status":
            return cmd_status(alias)
        return cmd_down(alias)
    if argv and argv[0] in {"--socks", "--gateway"}:
        gateway = _gateway_from_tokens(argv)
        if gateway:
            os.environ["SSH_TOTP_JUMP_ALIAS"] = gateway
        if "--socks" not in argv:
            print("usage: ssh_totp.py --gateway ALIAS --socks <host> <port>", file=sys.stderr)
            return 2
        index = argv.index("--socks")
        if len(argv) < index + 3:
            print("usage: ssh_totp.py --socks <host> <port>", file=sys.stderr)
            return 2
        return _socks_relay(argv[index + 1], argv[index + 2])
    return run_wrapper(argv)


if __name__ == "__main__":
    raise SystemExit(main())
