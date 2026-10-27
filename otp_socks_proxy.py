#!/usr/bin/env python3
"""ProxyCommand shim backed by an isolated SSH SOCKS master.

Usage:
    otp_socks_proxy.py <host> <port>
    otp_socks_proxy.py --status
    otp_socks_proxy.py --down

The wrapper reads a complete public-main core from SSH_OTP_RUNTIME_DIR. It never
changes the core's ControlPath globals or enters managed-route mode.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Optional, Sequence, Tuple


DEFAULT_REAL_SSH = Path.home() / "scoop" / "apps" / "git" / "current" / "usr" / "bin" / "ssh.exe"
DEFAULT_SOCKS = "127.0.0.1:7090"
CONTROL_PATH = "~/.ssh/cm/app-codex-f102-%C"
DEFAULT_GATEWAY_ALIAS = "X"
DEFAULT_START_TIMEOUT_SECONDS = 40.0
STATUS_TIMEOUT_SECONDS = 10.0


class ProxyError(Exception):
    pass


def _env_path(name: str, required: bool = False) -> Optional[Path]:
    value = os.environ.get(name, "").strip()
    if not value:
        if required:
            raise ProxyError(f"{name} is required")
        return None
    return Path(os.path.expandvars(os.path.expanduser(value))).resolve()


def _load_core(runtime_dir: Path) -> ModuleType:
    core_path = runtime_dir / "ssh_totp.py"
    askpass = runtime_dir / "totp_askpass.cmd"
    if not core_path.is_file():
        raise ProxyError(f"ssh_totp.py not found in runtime directory: {runtime_dir}")
    if not askpass.is_file():
        raise ProxyError(f"totp_askpass.cmd not found in runtime directory: {runtime_dir}")
    spec = importlib.util.spec_from_file_location("_otp_socks_proxy_core", str(core_path))
    if spec is None or spec.loader is None:
        raise ProxyError(f"cannot load ssh_totp.py: {core_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validate_core_api(core: ModuleType) -> None:
    """Require only the public-main helpers used in this process."""
    required = (
        "main",
        "_connect_socks",
        "_acquire_socks_start_lock",
        "_release_socks_start_lock",
    )
    missing = [name for name in required if not callable(getattr(core, name, None))]
    if missing:
        raise ProxyError("runtime core is missing API: " + ", ".join(missing))


def _profile_dir() -> Path:
    configured = os.environ.get("SSH_OTP_PROFILE_DIR", "").strip()
    if configured:
        path = Path(configured).expanduser()
    else:
        script_dir = Path(__file__).resolve().parent
        if (script_dir / "master_state.json").is_file():
            path = script_dir
        elif (script_dir.parent / "master_state.json").is_file():
            path = script_dir.parent
        else:
            path = script_dir
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()


def _real_ssh() -> Path:
    configured = os.environ.get("SSH_OTP_PROXY_REAL_SSH", "").strip()
    path = Path(configured).expanduser() if configured else DEFAULT_REAL_SSH
    if not path.is_file():
        raise ProxyError(f"Git/MSYS ssh executable not found: {path}")
    return path.resolve()


def _load_master_state(profile_dir: Path) -> dict:
    state_path = profile_dir / "master_state.json"
    if not state_path.exists():
        return {}
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProxyError(f"cannot read master state: {state_path}") from exc
    if not isinstance(state, dict):
        raise ProxyError(f"invalid master state object: {state_path}")
    return state


def _same_socks(left: str, right: str) -> bool:
    lh, _ls, lp = left.rpartition(":")
    rh, _rs, rp = right.rpartition(":")
    return lh in {"127.0.0.1", "localhost"} and rh in {"127.0.0.1", "localhost"} and lp == rp


def _socks_address(profile_dir: Path) -> str:
    state_value = str(_load_master_state(profile_dir).get("socks", "")).strip()
    configured = os.environ.get("SSH_OTP_SOCKS", "").strip()
    if configured and state_value and not _same_socks(configured, state_value):
        raise ProxyError(
            "SSH_OTP_SOCKS does not match the existing master_state.json port"
        )
    value = configured or state_value or DEFAULT_SOCKS
    host, separator, port_text = value.rpartition(":")
    if not separator or not port_text.isdigit():
        raise ProxyError(f"invalid SSH_OTP_SOCKS value: {value!r}")
    port = int(port_text)
    if host not in {"127.0.0.1", "localhost"} or not 1 <= port <= 65535:
        raise ProxyError("SSH_OTP_SOCKS must be an independent loopback address")
    return f"127.0.0.1:{port}"


def _control_path(profile_dir: Path) -> str:
    state_value = str(_load_master_state(profile_dir).get("control_path", "")).strip()
    value = state_value or CONTROL_PATH
    normalized = Path(value).expanduser().as_posix()
    if os.name == "nt" and not Path(normalized).is_absolute():
        raise ProxyError(f"ControlPath must expand to an absolute Windows path: {value}")
    return normalized


def _gateway_alias(profile_dir: Path) -> str:
    state_value = str(
        _load_master_state(profile_dir).get("gateway_alias", "")
    ).strip()
    alias = state_value or DEFAULT_GATEWAY_ALIAS
    if not alias or any(char.isspace() for char in alias):
        raise ProxyError("master_state.gateway_alias is invalid")
    return alias


def _configure_environment(
    runtime_dir: Path,
    profile_dir: Path,
    real_ssh: Path,
    socks: str,
    gateway_alias: str,
) -> None:
    os.environ["SSH_TOTP_JUMP_ALIAS"] = gateway_alias
    os.environ["SSH_TOTP_MANAGED_ROUTE"] = "0"
    os.environ["SSH_TOTP_REAL_SSH"] = str(real_ssh)
    os.environ["SSH_OTP_SOCKS"] = socks
    os.environ["SSH_TOTP_ASKPASS_LOG"] = str(profile_dir / "askpass-socks.log")
    os.environ["SSH_TOTP_AUTO_START"] = "0"
    os.environ["SSH_TOTP_PYTHON"] = sys.executable
    os.environ["SSH_TOTP_STATE_DIR"] = str(profile_dir / "state")
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ.pop("SSH_TOTP_CONFIG", None)
    os.environ["SSH_TOTP_WRAPPER_DIR"] = str(runtime_dir)


def _control_args(control_path: str) -> list:
    return ["-o", f"ControlPath={control_path}"]


def _run_core_cli(
    runtime_dir: Path,
    profile_dir: Path,
    args: Sequence[str],
    log_name: str,
    timeout: float,
) -> int:
    """Run the public core as a child so all of its ssh checks inherit DEVNULL."""
    core_path = runtime_dir / "ssh_totp.py"
    if not core_path.is_file():
        raise ProxyError(f"ssh_totp.py not found in runtime directory: {runtime_dir}")
    log_path = profile_dir / log_name
    command = [sys.executable, str(core_path), *args]
    try:
        with open(log_path, "a", encoding="utf-8") as log_handle:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=log_handle,
                env=os.environ.copy(),
                timeout=timeout,
                check=False,
            )
    except subprocess.TimeoutExpired as exc:
        raise ProxyError(
            f"isolated master operation timed out after {timeout:g}s; see {log_name}"
        ) from exc
    return result.returncode


def _master_check(
    runtime_dir: Path,
    profile_dir: Path,
    control_path: str,
    gateway_alias: str,
) -> int:
    return _run_core_cli(
        runtime_dir,
        profile_dir,
        [*_control_args(control_path), "-O", "check", gateway_alias],
        "master-check.stderr.log",
        STATUS_TIMEOUT_SECONDS,
    )


def _master_down(
    runtime_dir: Path,
    profile_dir: Path,
    control_path: str,
    gateway_alias: str,
) -> int:
    return _run_core_cli(
        runtime_dir,
        profile_dir,
        [*_control_args(control_path), "-O", "exit", gateway_alias],
        "master-down.stderr.log",
        STATUS_TIMEOUT_SECONDS,
    )


def _port_is_open(socks: str) -> bool:
    host, _separator, port_text = socks.rpartition(":")
    try:
        connection = socket.create_connection((host, int(port_text)), timeout=0.5)
    except OSError:
        return False
    connection.close()
    return True


def _expanded_git_control_path(
    real_ssh: Path, control_path: str, gateway_alias: str
) -> str:
    try:
        result = subprocess.run(
            [
                str(real_ssh),
                "-G",
                "-o",
                f"ControlPath={control_path}",
                gateway_alias,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=STATUS_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProxyError("ssh -G timed out while validating the stale ControlPath") from exc
    if result.returncode != 0:
        raise ProxyError(
            f"ssh -G failed while validating the stale ControlPath: exit {result.returncode}"
        )
    paths = []
    for line in result.stdout.splitlines():
        key, separator, value = line.partition(" ")
        if separator and key.lower() == "controlpath":
            paths.append(value.strip())
    if len(paths) != 1 or not paths[0]:
        raise ProxyError("ssh -G did not return exactly one expanded ControlPath")
    return paths[0]


def _remove_own_stale_control_socket(
    profile_dir: Path, control_path: str, gateway_alias: str
) -> None:
    state_value = str(_load_master_state(profile_dir).get("control_path", "")).strip()
    state_control_path = Path(state_value or CONTROL_PATH).expanduser().as_posix()
    if control_path != state_control_path:
        raise ProxyError("refusing stale cleanup for a ControlPath not recorded by this profile")

    expected_parent = Path(control_path).parent
    template_name = Path(control_path).name
    if template_name.count("%C") != 1 or not template_name.endswith("%C"):
        raise ProxyError("stale cleanup requires a ControlPath ending in exactly one %C")
    prefix = template_name[:-2]
    if not prefix or "%" in prefix:
        raise ProxyError("stale cleanup requires a fixed ControlPath prefix and only %C")

    real_ssh_text = os.environ.get("SSH_TOTP_REAL_SSH", "").strip()
    if not real_ssh_text:
        raise ProxyError("SSH_TOTP_REAL_SSH is required for stale ControlPath validation")
    real_ssh = Path(real_ssh_text)
    if not real_ssh.is_file():
        raise ProxyError(f"Git/MSYS ssh executable not found: {real_ssh}")

    expanded_text = _expanded_git_control_path(real_ssh, control_path, gateway_alias)
    expanded = Path(expanded_text)
    if expanded.parent != expected_parent:
        raise ProxyError(
            f"expanded ControlPath parent does not match the profile ControlPath: {expanded_text}"
        )
    if re.fullmatch(re.escape(prefix) + r"[0-9a-fA-F]{40}", expanded.name) is None:
        raise ProxyError(
            f"expanded ControlPath name does not match this tool: {expanded_text}"
        )
    if expanded.exists():
        try:
            expanded.unlink()
        except OSError as exc:
            raise ProxyError(f"cannot remove confirmed stale ControlPath: {expanded}") from exc


def _probe_core_socks(core: ModuleType, socks: str) -> bool:
    try:
        connection = core._connect_socks(socks)
    except OSError:
        return False
    connection.close()
    return True


def _start_timeout() -> float:
    configured = os.environ.get("SSH_OTP_START_TIMEOUT_SECONDS", "").strip()
    if configured:
        try:
            value = float(configured)
        except ValueError as exc:
            raise ProxyError("SSH_OTP_START_TIMEOUT_SECONDS must be numeric") from exc
        if not 1.0 <= value <= 120.0:
            raise ProxyError("SSH_OTP_START_TIMEOUT_SECONDS must be between 1 and 120")
        return value
    return DEFAULT_START_TIMEOUT_SECONDS


def _start_master(
    runtime_dir: Path,
    profile_dir: Path,
    socks: str,
    control_path: str,
    gateway_alias: str,
    timeout: float,
) -> None:
    argv = [
        *_control_args(control_path),
        "-o", "ControlPersist=8h",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ConnectTimeout=8",
        "-o", "ConnectionAttempts=1",
        "-MNf",
        "-D", socks,
        gateway_alias,
    ]
    result = _run_core_cli(
        runtime_dir,
        profile_dir,
        argv,
        "socks-master.stderr.log",
        timeout,
    )
    if result != 0:
        raise ProxyError(
            f"isolated SOCKS master failed with exit {result}; "
            "see socks-master.stderr.log"
        )


def _wait_ready(core: ModuleType, socks: str) -> None:
    deadline = time.monotonic() + _start_timeout()
    poll_seconds = float(getattr(core, "SOCKS_START_POLL_SECONDS", 0.2))
    while True:
        if _probe_core_socks(core, socks):
            return
        if time.monotonic() >= deadline:
            raise ProxyError(
                f"isolated SOCKS master did not become ready at {socks} before timeout"
            )
        time.sleep(poll_seconds)


def _ensure_master(
    core: ModuleType,
    profile_dir: Path,
    runtime_dir: Path,
    socks: str,
    control_path: str,
    gateway_alias: str,
) -> None:
    lock_path = None
    lock_fd = None
    token = None
    try:
        lock_fd, lock_path, token = core._acquire_socks_start_lock(socks)
        if _master_check(runtime_dir, profile_dir, control_path, gateway_alias) == 0:
            if not _probe_core_socks(core, socks):
                raise ProxyError(
                    "isolated master exists but its SOCKS listener is unavailable"
                )
            return
        if _port_is_open(socks):
            raise ProxyError(
                f"SOCKS port {socks} is already in use without the isolated master"
            )
        _remove_own_stale_control_socket(profile_dir, control_path, gateway_alias)
        _start_master(
            runtime_dir,
            profile_dir,
            socks,
            control_path,
            gateway_alias,
            _start_timeout(),
        )
        _wait_ready(core, socks)
    finally:
        if lock_fd is not None and lock_path is not None and token is not None:
            core._release_socks_start_lock(lock_fd, lock_path, token)


def _prepare() -> Tuple[ModuleType, Path, Path, str, str, str]:
    profile_dir = _profile_dir()
    runtime_dir = _env_path("SSH_OTP_RUNTIME_DIR", required=False)
    if runtime_dir is None:
        runtime_dir = profile_dir / "runtime"
    real_ssh = _real_ssh()
    socks = _socks_address(profile_dir)
    control_path = _control_path(profile_dir)
    gateway_alias = _gateway_alias(profile_dir)
    _configure_environment(
        runtime_dir,
        profile_dir,
        real_ssh,
        socks,
        gateway_alias,
    )
    core = _load_core(runtime_dir)
    _validate_core_api(core)
    control_dir = Path.home() / ".ssh" / "cm"
    control_dir.mkdir(parents=True, exist_ok=True)
    return core, profile_dir, runtime_dir, socks, control_path, gateway_alias


def _relay(core: ModuleType, gateway_alias: str, host: str, port: str) -> int:
    return core.main(["--gateway", gateway_alias, "--socks", host, port])


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        core, profile_dir, runtime_dir, socks, control_path, gateway_alias = _prepare()
        if args == ["--status"]:
            running = (
                _master_check(
                    runtime_dir,
                    profile_dir,
                    control_path,
                    gateway_alias,
                )
                == 0
            )
            print(f"master={'running' if running else 'not-running'}")
            return 0 if running else 1
        if args == ["--down"]:
            result = _master_down(
                runtime_dir,
                profile_dir,
                control_path,
                gateway_alias,
            )
            if result != 0:
                raise ProxyError(f"isolated master down failed with exit {result}")
            return 0
        if len(args) != 2:
            raise ProxyError("usage: otp_socks_proxy.py <host> <port> | --status | --down")
        host, port = args
        _ensure_master(
            core,
            profile_dir,
            runtime_dir,
            socks,
            control_path,
            gateway_alias,
        )
        return _relay(core, gateway_alias, host, port)
    except (ProxyError, OSError, ValueError, TimeoutError) as exc:
        print(f"otp_socks_proxy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
