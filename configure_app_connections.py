#!/usr/bin/env python3
"""Install an isolated Codex/ChatGPT App SSH alias for an OTP jump host.

The command is dry-run by default. It only reads SSH config; --apply creates an
isolated profile and prepends one Include line to the selected SSH config.

Current Gamma target: codex-totp-f102 -> target alias ``debug`` (f102.hn.org),
with the OTP challenge explicitly routed through gateway alias ``X``.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


SYSTEM32_SSH = r"C:\Windows\System32\OpenSSH\ssh.exe"
SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
WINDOWS_TIMEOUT_SECONDS = 20
ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
MANIFEST_NAME = "manifest.json"
PROXY_NAME = "proxy.cmd"
SSH_CONFIG_NAME = "app_ssh_config"
ASKPASS_LOG_NAME = "askpass.log"
ASKPASS_SOCKS_LOG_NAME = "askpass-socks.log"
MASTER_STATE_NAME = "master_state.json"
DEFAULT_REAL_GIT_SSH = "~/scoop/apps/git/current/usr/bin/ssh.exe"
BUNDLE_PATHS = (
    "runtime/ssh_totp.py",
    "runtime/totp_askpass.py",
    "runtime/totp_askpass.cmd",
    "runtime/find_python.cmd",
    "otp_socks_proxy.py",
)


class ConfigError(Exception):
    pass


def _single_line(value: str, label: str) -> str:
    value = value.strip()
    if not value or any(char in value for char in ("\r", "\n", "\x00")):
        raise ConfigError(f"{label} must be a non-empty single-line value")
    return value


def _alias(value: str, label: str) -> str:
    value = _single_line(value, label)
    if not ALIAS_PATTERN.fullmatch(value):
        raise ConfigError(f"{label} contains unsupported characters: {value!r}")
    return value


def _resolve(path_value: str, label: str) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(path_value))
    if not expanded:
        raise ConfigError(f"{label} is empty")
    return Path(expanded).resolve()


def _default_profile_dir(alias: str) -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if not local_app_data:
        local_app_data = str(Path.home() / "AppData" / "Local")
    return Path(local_app_data) / "ssh-otp-app-connections" / alias


def _load_core_file(core_path: Path):
    if not core_path.is_file():
        raise ConfigError(f"metadata core not found: {core_path}")
    spec = importlib.util.spec_from_file_location(
        "_ssh_otp_app_connections_core", str(core_path)
    )
    if spec is None or spec.loader is None:
        raise ConfigError(f"cannot load ssh_totp.py: {core_path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def _load_core(wrapper_dir: Path, require_debug_proxy: bool = True):
    core_path = wrapper_dir / "ssh_totp.py"
    debug_proxy = wrapper_dir / "debug_proxy_win.py"
    if not core_path.is_file():
        raise ConfigError(f"ssh_totp.py not found under --wrapper-dir: {wrapper_dir}")
    if require_debug_proxy and not debug_proxy.is_file():
        raise ConfigError(f"debug_proxy_win.py not found under --wrapper-dir: {wrapper_dir}")
    return _load_core_file(core_path)


def _decode_config(data: bytes) -> str:
    return data.decode("utf-8-sig", errors="replace")


def _host_aliases(text: str) -> Iterable[List[str]]:
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lowered = stripped.lower()
        if lowered.startswith("host "):
            yield stripped[5:].split()
        elif lowered.startswith("match "):
            continue


def _exact_alias_present(text: str, alias: str) -> bool:
    wanted = alias.casefold()
    for patterns in _host_aliases(text):
        for pattern in patterns:
            if not pattern.startswith("!") and pattern.casefold() == wanted:
                return True
    return False


def _patterns_match(alias: str, patterns: Sequence[str]) -> bool:
    positive = False
    wanted = alias.casefold()
    for pattern in patterns:
        negative = pattern.startswith("!")
        raw = pattern[1:] if negative else pattern
        if fnmatch.fnmatchcase(wanted, raw.casefold()):
            if negative:
                return False
            positive = True
    return positive


def _gateway_has_totp(text: str, gateway_alias: str) -> bool:
    """Detect TOTP metadata without retaining or returning the secret value."""
    pending_secret = False
    current_patterns: List[str] = []
    current_has_secret = False
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        lowered = stripped.lower()
        if stripped.startswith("#"):
            if re.match(r"#\s*totp_secret\s*:", stripped, re.IGNORECASE):
                pending_secret = True
            continue
        if not stripped:
            continue
        if lowered.startswith("host "):
            current_patterns = stripped[5:].split()
            current_has_secret = pending_secret
            pending_secret = False
            if current_has_secret and _patterns_match(gateway_alias, current_patterns):
                return True
            continue
        if lowered.startswith("match "):
            current_patterns = []
            current_has_secret = False
            pending_secret = False
            continue
        if current_patterns:
            pending_secret = False
    return False


def _target_options(core, config_path: Path, target_alias: str) -> Dict[str, str]:
    return core._load_ssh_config(target_alias, str(config_path))


def _ssh_path(path: Path) -> str:
    return path.resolve().as_posix()


def _quoted_ssh_path(path: Path) -> str:
    value = _ssh_path(path)
    if '"' in value:
        raise ConfigError(f"path cannot be quoted for SSH config: {value}")
    return f'"{value}"'


def _include_line(config_path: Path) -> str:
    return f"Include {_quoted_ssh_path(config_path)}"


def _canonical_include_path(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    value = os.path.expandvars(os.path.expanduser(value))
    value = value.replace("/", "\\")
    return os.path.normcase(os.path.normpath(value))


def _loopback_socks(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{label} must be a string")
    socks = _single_line(value, label)
    host, separator, port_text = socks.rpartition(":")
    if (
        not separator
        or host not in {"127.0.0.1", "localhost"}
        or not port_text.isdigit()
        or not 1 <= int(port_text) <= 65535
    ):
        raise ConfigError(f"{label} must be a loopback host:port value")
    return socks


def _control_path_template(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{label} must be a string")
    normalized = Path(_single_line(value, label)).expanduser().as_posix()
    name = Path(normalized).name
    if name.count("%C") != 1 or not name.endswith("%C"):
        raise ConfigError(f"{label} must end in exactly one %C")
    prefix = name[:-2]
    if not prefix or "%" in prefix:
        raise ConfigError(f"{label} may contain only the trailing %C variable")
    return normalized


def _validate_master_state(state: object, label: str) -> dict:
    if not isinstance(state, dict):
        raise ConfigError(f"{label} must be a JSON object")
    missing = [
        key
        for key in ("gateway_alias", "socks", "control_path")
        if key not in state
    ]
    if missing:
        raise ConfigError(f"{label} is missing: {', '.join(missing)}")
    for key in ("gateway_alias", "control_path"):
        if not isinstance(state[key], str):
            raise ConfigError(f"{label}.{key} must be a string")
    return {
        "gateway_alias": _alias(state["gateway_alias"], f"{label}.gateway_alias"),
        "socks": _loopback_socks(state["socks"], f"{label}.socks"),
        "control_path": str(state["control_path"]).strip(),
    }


def _load_socks_bundle(spec_path: Path) -> dict:
    if not spec_path.is_file():
        raise ConfigError(f"socks bundle spec not found: {spec_path}")
    try:
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read socks bundle spec: {spec_path}") from exc
    if not isinstance(spec, dict):
        raise ConfigError("socks bundle spec must be a JSON object")
    entries = spec.get("files")
    if not isinstance(entries, list) or len(entries) != len(BUNDLE_PATHS):
        raise ConfigError(f"socks bundle must list exactly {len(BUNDLE_PATHS)} files")
    assets: Dict[str, dict] = {}
    for index, entry in enumerate(entries):
        label = f"socks bundle files[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{label} must be a JSON object")
        relative_path = entry.get("relative_path")
        if relative_path not in BUNDLE_PATHS:
            raise ConfigError(f"{label}.relative_path is not allowed: {relative_path!r}")
        if relative_path in assets:
            raise ConfigError(f"socks bundle contains duplicate path: {relative_path}")
        source_text = entry.get("source")
        if not isinstance(source_text, str) or not source_text.strip():
            raise ConfigError(f"{label}.source must be a non-empty string")
        source = Path(source_text)
        if not source.is_absolute():
            raise ConfigError(f"{label}.source must be an absolute cache path")
        if not source.is_file():
            raise ConfigError(f"socks bundle source not found: {source}")
        declared_hash = entry.get("sha256")
        if (
            not isinstance(declared_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", declared_hash) is None
        ):
            raise ConfigError(f"{label}.sha256 must be 64 lowercase hexadecimal digits")
        data = source.read_bytes()
        actual_hash = _sha256(data)
        if actual_hash != declared_hash:
            raise ConfigError(f"socks bundle source hash mismatch: {relative_path}")
        assets[relative_path] = {
            "source": source.resolve(),
            "sha256": actual_hash,
            "data": data,
        }
    missing_paths = sorted(set(BUNDLE_PATHS) - set(assets))
    if missing_paths:
        raise ConfigError("socks bundle is missing: " + ", ".join(missing_paths))
    master_state = _validate_master_state(
        spec.get("master_state"), "socks bundle master_state"
    )
    _control_path_template(
        master_state["control_path"], "socks bundle master_state.control_path"
    )
    return {"assets": assets, "master_state": master_state}


def _master_state_plan(profile_dir: Path, spec_state: dict) -> dict:
    state_path = profile_dir / MASTER_STATE_NAME
    if state_path.exists():
        if not state_path.is_file():
            raise ConfigError(f"master state is not a file: {state_path}")
        try:
            current_data = state_path.read_bytes()
            current_state = json.loads(current_data.decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"cannot read existing master state: {state_path}") from exc
        validated = _validate_master_state(current_state, "existing master_state")
        _control_path_template(
            validated["control_path"], "existing master_state.control_path"
        )
        return {
            "path": state_path,
            "data": current_data,
            "state": validated,
            "existing": True,
        }
    data = (json.dumps(spec_state, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return {
        "path": state_path,
        "data": data,
        "state": spec_state,
        "existing": False,
    }


def _validate_asset_targets(
    profile_dir: Path, assets: Dict[str, dict], manifest: Optional[dict]
) -> None:
    expected_pending: Dict[str, str] = {}
    if manifest and isinstance(manifest.get("bundle_assets"), list):
        for entry in manifest["bundle_assets"]:
            if isinstance(entry, dict):
                relative_path = entry.get("relative_path")
                digest = entry.get("sha256")
                if isinstance(relative_path, str) and isinstance(digest, str):
                    expected_pending[relative_path] = digest
    for relative_path, asset in assets.items():
        target = profile_dir / relative_path
        if not target.exists():
            continue
        if not target.is_file():
            raise ConfigError(f"profile asset path is not a file: {target}")
        current = target.read_bytes()
        if current == asset["data"]:
            continue
        if expected_pending.get(relative_path) == asset["sha256"]:
            continue
        raise ConfigError(
            f"profile asset differs from the requested bundle; refusing implicit upgrade: "
            f"{relative_path}"
        )


def _include_present(text: str, include_path: Path) -> bool:
    wanted = _canonical_include_path(str(include_path))
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped.lower().startswith("include "):
            continue
        value = stripped[len("include ") :].strip()
        if _canonical_include_path(value) == wanted:
            return True
    return False


def _insert_include(data: bytes, include: str, windows: bool) -> bytes:
    bom = b"\xef\xbb\xbf" if data.startswith(b"\xef\xbb\xbf") else b""
    body = data[len(bom) :]
    newline = b"\r\n" if windows or b"\r\n" in body else b"\n"
    return bom + include.encode("utf-8") + newline + body


def _batch_value(value: str) -> str:
    return value.replace("%", "%%")


def _proxy_cmd(
    alias: str,
    gateway_alias: str,
    python_exe: Path,
    debug_proxy: Path,
    askpass_log: Path,
) -> bytes:
    lines = [
        "@echo off",
        "setlocal EnableExtensions",
        # The fixture config is a planning/apply input only. Never let an
        # inherited SSH_TOTP_CONFIG leak into the App's runtime child.
        'set "SSH_TOTP_CONFIG="',
        f'set "SSH_TOTP_JUMP_ALIAS={_batch_value(gateway_alias)}"',
        'set "SSH_TOTP_MANAGED_ROUTE=0"',
        f'set "SSH_TOTP_REAL_SSH={_batch_value(SYSTEM32_SSH)}"',
        f'set "SSH_TOTP_ASKPASS_LOG={_batch_value(_ssh_path(askpass_log))}"',
        f'"{_batch_value(_ssh_path(python_exe))}" "{_batch_value(_ssh_path(debug_proxy))}" %*',
        "exit /b %errorlevel%",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def _socks_proxy_cmd(
    profile_dir: Path,
    runtime_dir: Path,
    python_exe: Path,
    real_git_ssh: Path,
) -> bytes:
    proxy_script = profile_dir / "otp_socks_proxy.py"
    lines = [
        "@echo off",
        "setlocal DisableDelayedExpansion",
        'set "SSH_TOTP_CONFIG="',
        'set "SSH_OTP_SOCKS="',
        f'set "SSH_OTP_PROFILE_DIR={_batch_value(_ssh_path(profile_dir))}"',
        f'set "SSH_OTP_RUNTIME_DIR={_batch_value(_ssh_path(runtime_dir))}"',
        f'set "SSH_OTP_PROXY_REAL_SSH={_batch_value(_ssh_path(real_git_ssh))}"',
        f'set "SSH_TOTP_PYTHON={_batch_value(_ssh_path(python_exe))}"',
        f'"{_batch_value(_ssh_path(python_exe))}" "{_batch_value(_ssh_path(proxy_script))}" %*',
        "exit /b %errorlevel%",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def _generated_ssh_config(
    alias: str,
    target_alias: str,
    proxy_cmd: Path,
    target: Dict[str, str],
) -> bytes:
    hostname = _single_line(target.get("hostname", ""), "target HostName")
    lines = [
        "# Generated by configure_app_connections.py; do not edit.",
        f"# target-alias: {target_alias}",
        f"Host {alias}",
        f"    HostName {hostname}",
    ]
    if target.get("user"):
        lines.append(f"    User {_single_line(target['user'], 'target User')}")
    if target.get("port"):
        port = _single_line(target["port"], "target Port")
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ConfigError(f"target Port is invalid: {port!r}")
        lines.append(f"    Port {port}")
    if target.get("identityfile"):
        lines.append(
            f"    IdentityFile {_single_line(target['identityfile'], 'target IdentityFile')}"
        )
    lines.append(f"    ProxyCommand {_quoted_ssh_path(proxy_cmd)} %h %p")
    lines.extend(["", "Host *", ""])
    return ("\n".join(lines) + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(
    alias: str,
    target_alias: str,
    gateway_alias: str,
    wrapper_dir: Path,
    profile_dir: Path,
    include: str,
    generated_files: Dict[str, bytes],
    proxy_mode: str,
    assets: Optional[Dict[str, dict]] = None,
    master_state_plan: Optional[dict] = None,
    real_git_ssh: Optional[Path] = None,
    python_exe: Optional[Path] = None,
) -> bytes:
    files = []
    for name in (PROXY_NAME, SSH_CONFIG_NAME):
        files.append(
            {
                "path": name,
                "sha256": _sha256(generated_files[name]),
                "bytes": len(generated_files[name]),
            }
        )
    files.append(
        {
            "path": ASKPASS_SOCKS_LOG_NAME if proxy_mode == "socks" else ASKPASS_LOG_NAME,
            "role": "mutable_askpass_log",
            "contains_secret": False,
        }
    )
    data = {
        "schema": 1,
        "alias": alias,
        "target_alias": target_alias,
        "gateway_alias": gateway_alias,
        "proxy_mode": proxy_mode,
        "proxy_sha256": _sha256(generated_files[PROXY_NAME]),
        "wrapper_dir": _ssh_path(wrapper_dir),
        "profile_dir": _ssh_path(profile_dir),
        "include": include,
        "files": files,
    }
    if python_exe is not None:
        data["python_exe"] = _ssh_path(python_exe)
    if real_git_ssh is not None:
        data["real_git_ssh"] = _ssh_path(real_git_ssh)
    if assets:
        data["bundle_assets"] = [
            {
                "relative_path": relative_path,
                "sha256": assets[relative_path]["sha256"],
            }
            for relative_path in sorted(assets)
        ]
    if master_state_plan is not None:
        data["master_state"] = {
            "path": MASTER_STATE_NAME,
            "sha256": _sha256(master_state_plan["data"]),
        }
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _windows_tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise ConfigError(f"required Windows tool not found: {name}")
    return found


def _run_windows_capture(command: Sequence[str], env: Optional[Dict[str, str]] = None) -> str:
    try:
        completed = subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=WINDOWS_TIMEOUT_SECONDS,
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise ConfigError(f"Windows helper timed out: {Path(command[0]).name}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot start Windows helper: {Path(command[0]).name}") from exc
    if completed.returncode != 0:
        raise ConfigError(
            f"Windows helper failed: {Path(command[0]).name} exit={completed.returncode}"
        )
    return completed.stdout


def _powershell(script: str, env_extra: Optional[Dict[str, str]] = None) -> str:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    command = [
        _windows_tool("powershell.exe"),
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "
        "$OutputEncoding=[Console]::OutputEncoding; $ErrorActionPreference='Stop'; "
        + script,
    ]
    return _run_windows_capture(command, env=env)


def _current_user_sid() -> str:
    sid = _powershell(
        "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
    ).strip()
    if not sid.startswith("S-1-"):
        raise ConfigError("cannot determine the current Windows user SID")
    return sid


def _profile_sid_set(profile_dir: Path, user_sid: str) -> set:
    return {user_sid, SYSTEM_SID, ADMINISTRATORS_SID}


def _protect_profile_dir(profile_dir: Path, user_sid: str) -> None:
    icacls = _windows_tool("icacls.exe")
    _run_windows_capture(
        [icacls, str(profile_dir), "/inheritance:r"]
    )
    for sid in _profile_sid_set(profile_dir, user_sid):
        _run_windows_capture(
            [icacls, str(profile_dir), "/grant:r", f"*{sid}:(OI)(CI)F"]
        )


def _reset_profile_children(profile_dir: Path) -> None:
    icacls = _windows_tool("icacls.exe")
    children = sorted(profile_dir.rglob("*"), key=lambda path: len(path.parts))
    for child in children:
        _run_windows_capture([icacls, str(child), "/reset", "/C"])


def _acl_sids(path: Path) -> set:
    output = _powershell(
        "(Get-Acl -LiteralPath $env:SSH_OTP_ACL_PATH).Access | "
        "ForEach-Object { try { $_.IdentityReference.Translate("
        "[System.Security.Principal.SecurityIdentifier]).Value } catch { "
        "$_.IdentityReference.Value } }",
        {"SSH_OTP_ACL_PATH": str(path)},
    )
    return {line.strip() for line in output.splitlines() if line.strip()}


def _verify_profile_acl(profile_dir: Path, user_sid: str) -> None:
    allowed = _profile_sid_set(profile_dir, user_sid)
    for path in [profile_dir, *sorted(profile_dir.rglob("*"))]:
        sids = _acl_sids(path)
        if not sids or not sids.issubset(allowed):
            raise ConfigError(f"profile ACL verification failed: {path}")


def _copy_acl_exact(source: Path, destination: Path) -> None:
    _powershell(
        "$acl = Get-Acl -LiteralPath $env:SSH_OTP_ACL_SOURCE; "
        "Set-Acl -LiteralPath $env:SSH_OTP_ACL_DESTINATION -AclObject $acl",
        {
            "SSH_OTP_ACL_SOURCE": str(source),
            "SSH_OTP_ACL_DESTINATION": str(destination),
        },
    )


def _atomic_write(path: Path, data: bytes, acl_source: Optional[Path] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "wb",
        delete=False,
        dir=str(path.parent),
        prefix=path.name + ".",
        suffix=".tmp",
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "nt" and acl_source is not None and acl_source.is_file():
            _copy_acl_exact(acl_source, temp_path)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def _backup_config(config_path: Path) -> Path:
    stamp = time.strftime("%Y%m%d%H%M%S")
    backup = config_path.with_name(config_path.name + f".bak-app-connections-{stamp}")
    suffix = 1
    while backup.exists():
        backup = config_path.with_name(
            config_path.name + f".bak-app-connections-{stamp}-{suffix}"
        )
        suffix += 1
    shutil.copyfile(config_path, backup)
    if os.name == "nt":
        original_sids = _acl_sids(config_path)
        try:
            _copy_acl_exact(config_path, backup)
            backup_sids = _acl_sids(backup)
            if not backup_sids.issubset(original_sids):
                raise ConfigError("backup ACL is broader than the source config ACL")
        except Exception:
            backup.unlink(missing_ok=True)
            raise
    return backup


def _validate_profile_ownership(profile_dir: Path, alias: str) -> Optional[dict]:
    if not profile_dir.exists():
        return None
    if not profile_dir.is_dir():
        raise ConfigError(f"profile path is not a directory: {profile_dir}")
    manifest_path = profile_dir / MANIFEST_NAME
    if not manifest_path.exists():
        if any(profile_dir.iterdir()):
            raise ConfigError(
                f"profile directory is non-empty and has no manifest: {profile_dir}"
            )
        return None
    if not manifest_path.is_file():
        raise ConfigError(f"profile manifest is not a file: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read profile manifest: {manifest_path}") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != 1
        or manifest.get("alias") != alias
    ):
        raise ConfigError(f"profile directory is not owned by this alias: {profile_dir}")
    return manifest


def _check_windows_prerequisites(wrapper_dir: Path, proxy_mode: str) -> None:
    if os.name != "nt":
        return
    system_ssh = Path(SYSTEM32_SSH)
    id_rsa = Path.home() / ".ssh" / "id_rsa"
    required = [system_ssh, id_rsa]
    if proxy_mode == "direct":
        required.append(wrapper_dir / "totp_askpass.cmd")
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise ConfigError("missing Windows runtime prerequisite(s): " + ", ".join(missing))


def _assert_config_unchanged(plan: dict) -> None:
    config_path: Path = plan["config_path"]
    current = config_path.read_bytes() if config_path.exists() else b""
    if current != plan["original"]:
        raise ConfigError(
            f"SSH config changed during planning; refusing to overwrite: {config_path}"
        )


def _preflight_windows(alias: str, target_alias: str, config_path: Path) -> None:
    if os.name != "nt":
        return
    default_config = (Path.home() / ".ssh" / "config").resolve()
    config_args = [] if config_path == default_config else ["-F", str(config_path)]
    for label, name in (("new alias", alias), ("existing target", target_alias)):
        try:
            completed = subprocess.run(
                [SYSTEM32_SSH, "-G", *config_args, "--", name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=WINDOWS_TIMEOUT_SECONDS,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            stdout_len = len(exc.stdout or b"")
            stderr_len = len(exc.stderr or b"")
            raise ConfigError(
                f"System32 ssh -G preflight timed out for {label}: "
                f"timeout={WINDOWS_TIMEOUT_SECONDS}s stdout_bytes={stdout_len} "
                f"stderr_bytes={stderr_len}"
            ) from exc
        except OSError as exc:
            raise ConfigError(f"cannot run System32 ssh -G for {label}") from exc
        if completed.returncode != 0:
            raise ConfigError(
                f"System32 ssh -G preflight failed for {label}: exit={completed.returncode}"
            )


def _rollback_config(plan: dict, written_bytes: bytes) -> None:
    config_path: Path = plan["config_path"]
    current = config_path.read_bytes() if config_path.exists() else b""
    if current != written_bytes:
        raise ConfigError(
            f"rollback skipped because config changed after apply: {config_path}"
        )
    if plan["original"]:
        acl_source = Path(plan["backup"]) if plan.get("backup") else None
        _atomic_write(config_path, plan["original"], acl_source=acl_source)
    else:
        config_path.unlink(missing_ok=True)


def build_plan(args: argparse.Namespace) -> dict:
    alias = _alias(args.alias, "--alias")
    target_alias = _alias(args.target_alias, "--target-alias")
    proxy_mode = args.proxy_mode
    if proxy_mode not in {"direct", "socks"}:
        raise ConfigError(f"unsupported --proxy-mode: {proxy_mode!r}")
    config_path = _resolve(args.config, "--config")
    profile_dir = (
        _resolve(args.profile_dir, "--profile-dir")
        if args.profile_dir
        else _default_profile_dir(alias)
    )
    existing_manifest = _validate_profile_ownership(profile_dir, alias)

    assets: Dict[str, dict] = {}
    master_state_plan = None
    real_git_ssh = None
    if proxy_mode == "socks":
        if not args.socks_bundle:
            raise ConfigError("--socks-bundle is required with --proxy-mode socks")
        bundle = _load_socks_bundle(_resolve(args.socks_bundle, "--socks-bundle"))
        assets = bundle["assets"]
        master_state_plan = _master_state_plan(profile_dir, bundle["master_state"])
        effective_state = master_state_plan["state"]
        gateway_alias = _alias(
            effective_state["gateway_alias"], "effective master_state.gateway_alias"
        )
        real_git_ssh = _resolve(args.real_git_ssh, "--real-git-ssh")
        if not real_git_ssh.is_file():
            raise ConfigError(f"Git/MSYS ssh executable not found: {real_git_ssh}")
        wrapper_dir = profile_dir / "runtime"
        core = _load_core_file(assets["runtime/ssh_totp.py"]["source"])
        _validate_asset_targets(profile_dir, assets, existing_manifest)
    else:
        gateway_alias = _alias(args.gateway_alias, "--gateway-alias")
        wrapper_dir = _resolve(args.wrapper_dir, "--wrapper-dir")
        core = _load_core(wrapper_dir)
    _check_windows_prerequisites(wrapper_dir, proxy_mode)

    if config_path.exists():
        original = config_path.read_bytes()
    else:
        original = b""
    text = _decode_config(original)
    if _exact_alias_present(text, alias):
        raise ConfigError(f"alias already exists in the selected SSH config: {alias}")
    if not _exact_alias_present(text, target_alias):
        raise ConfigError(f"target alias not found in SSH config: {target_alias}")
    if not _gateway_has_totp(text, gateway_alias):
        raise ConfigError(f"gateway TOTP metadata not found: {gateway_alias}")

    target = _target_options(core, config_path, target_alias)
    if not target.get("hostname"):
        raise ConfigError(f"target alias has no HostName: {target_alias}")

    python_exe = Path(sys.executable).resolve()
    if not python_exe.is_file():
        raise ConfigError(f"current Python executable is unavailable: {python_exe}")
    proxy_cmd = profile_dir / PROXY_NAME
    profile_config = profile_dir / SSH_CONFIG_NAME
    askpass_log = profile_dir / (
        ASKPASS_SOCKS_LOG_NAME if proxy_mode == "socks" else ASKPASS_LOG_NAME
    )
    if proxy_mode == "socks":
        if real_git_ssh is None:
            raise ConfigError("--real-git-ssh is required with --proxy-mode socks")
        generated_proxy = _socks_proxy_cmd(
            profile_dir,
            wrapper_dir,
            python_exe,
            real_git_ssh,
        )
    else:
        generated_proxy = _proxy_cmd(
            alias,
            gateway_alias,
            python_exe,
            wrapper_dir / "debug_proxy_win.py",
            askpass_log,
        )
    generated = {
        PROXY_NAME: generated_proxy,
        SSH_CONFIG_NAME: _generated_ssh_config(alias, target_alias, proxy_cmd, target),
    }
    include = _include_line(profile_config)
    include_present = _include_present(text, profile_config)
    return {
        "alias": alias,
        "target_alias": target_alias,
        "gateway_alias": gateway_alias,
        "proxy_mode": proxy_mode,
        "wrapper_dir": wrapper_dir,
        "config_path": config_path,
        "profile_dir": profile_dir,
        "profile_config": profile_config,
        "askpass_log": askpass_log,
        "assets": assets,
        "master_state_plan": master_state_plan,
        "real_git_ssh": real_git_ssh,
        "python_exe": python_exe,
        "generated": generated,
        "generated_manifest": _manifest(
            alias,
            target_alias,
            gateway_alias,
            wrapper_dir,
            profile_dir,
            include,
            generated,
            proxy_mode,
            assets=assets,
            master_state_plan=master_state_plan,
            real_git_ssh=real_git_ssh,
            python_exe=python_exe,
        ),
        "include": include,
        "include_present": include_present,
        "original": original,
        "existing_manifest": existing_manifest,
    }


def _apply(plan: dict) -> Tuple[bool, List[str]]:
    profile_dir: Path = plan["profile_dir"]
    changed = False
    wrote: List[str] = []
    if not plan["include_present"]:
        _assert_config_unchanged(plan)
    profile_dir.mkdir(parents=True, exist_ok=True)
    user_sid = None
    if os.name == "nt":
        user_sid = _current_user_sid()
        _protect_profile_dir(profile_dir, user_sid)
        _reset_profile_children(profile_dir)
        _verify_profile_acl(profile_dir, user_sid)

    manifest_path = profile_dir / MANIFEST_NAME
    manifest_data: bytes = plan["generated_manifest"]
    if not manifest_path.is_file() or manifest_path.read_bytes() != manifest_data:
        _atomic_write(manifest_path, manifest_data)
        wrote.append(str(manifest_path))
        changed = True

    for relative_path in sorted(plan["assets"]):
        asset = plan["assets"][relative_path]
        source: Path = asset["source"]
        if not source.is_file() or _sha256(source.read_bytes()) != asset["sha256"]:
            raise ConfigError(f"socks bundle source changed during apply: {relative_path}")
        path = profile_dir / relative_path
        if path.exists() and not path.is_file():
            raise ConfigError(f"profile asset path is not a file: {path}")
        if not path.is_file() or path.read_bytes() != asset["data"]:
            _atomic_write(path, asset["data"])
            wrote.append(str(path))
            changed = True

    state_plan = plan["master_state_plan"]
    if state_plan is not None:
        state_path: Path = state_plan["path"]
        state_data: bytes = state_plan["data"]
        if state_plan["existing"]:
            current = state_path.read_bytes() if state_path.exists() else b""
            if current != state_data:
                raise ConfigError("existing master_state changed during apply; preserving it")
        elif state_path.exists():
            if state_path.read_bytes() != state_data:
                raise ConfigError("master_state appeared during apply with different bytes")
        else:
            _atomic_write(state_path, state_data)
            wrote.append(str(state_path))
            changed = True

    for name in (PROXY_NAME, SSH_CONFIG_NAME):
        data = plan["generated"][name]
        path = profile_dir / name
        if not path.is_file() or path.read_bytes() != data:
            _atomic_write(path, data)
            wrote.append(str(path))
            changed = True

    askpass_log: Path = plan["askpass_log"]
    if not askpass_log.exists():
        _atomic_write(askpass_log, b"")
        wrote.append(str(askpass_log))
        changed = True

    if os.name == "nt":
        _reset_profile_children(profile_dir)
        _verify_profile_acl(profile_dir, user_sid)

    config_path: Path = plan["config_path"]
    original: bytes = plan["original"]
    config_written = False
    written_bytes = b""
    try:
        if not plan["include_present"]:
            _assert_config_unchanged(plan)
            written_bytes = _insert_include(original, plan["include"], os.name == "nt")
            acl_source = None
            if config_path.exists():
                plan["backup"] = str(_backup_config(config_path))
                acl_source = config_path
            parent = config_path.parent
            parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(config_path, written_bytes, acl_source=acl_source)
            wrote.append(str(config_path))
            changed = True
            config_written = True
        _preflight_windows(plan["alias"], plan["target_alias"], config_path)
    except Exception as exc:
        if config_written:
            try:
                _rollback_config(plan, written_bytes)
            except ConfigError as rollback_error:
                raise ConfigError(
                    f"{exc}; automatic config rollback failed: {rollback_error}"
                ) from exc
        raise
    return changed, wrote


def _print_plan(plan: dict, mode: str, changed: Optional[bool], wrote: Sequence[str]) -> None:
    print(f"mode={mode}")
    print(f"proxy_mode={plan['proxy_mode']}")
    print(f"alias={plan['alias']}")
    print(f"target_alias={plan['target_alias']}")
    print(f"gateway_alias={plan['gateway_alias']}")
    print(f"profile_dir={plan['profile_dir']}")
    print(f"include={plan['include']}")
    if changed is not None:
        print(f"changed={'true' if changed else 'false'}")
    else:
        print(f"would_change={'true' if (not plan['include_present']) else 'false'}")
    if plan.get("backup"):
        print(f"backup={plan['backup']}")
    if wrote:
        print("wrote=" + ",".join(wrote))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Configure an isolated ChatGPT/Codex App SSH alias for OTP."
    )
    parser.add_argument("--alias", default="codex-totp-f102")
    parser.add_argument("--target-alias", default="debug")
    parser.add_argument("--gateway-alias", default="X")
    parser.add_argument("--wrapper-dir", default="~/.ssh/ssh_otp")
    parser.add_argument(
        "--proxy-mode",
        choices=("direct", "socks"),
        default="direct",
    )
    parser.add_argument("--socks-bundle", default="")
    parser.add_argument("--real-git-ssh", default=DEFAULT_REAL_GIT_SSH)
    parser.add_argument("--config", default="~/.ssh/config")
    parser.add_argument("--profile-dir", default="")
    parser.add_argument("--apply", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        plan = build_plan(args)
        if not args.apply:
            _print_plan(plan, "dry-run", None, [])
            return 0
        changed, wrote = _apply(plan)
        _print_plan(plan, "apply", changed, wrote)
        return 0
    except (ConfigError, OSError, ValueError) as exc:
        print(f"configure_app_connections: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
