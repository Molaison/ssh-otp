#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_PROMPT_PATTERN = (
    r"verification|verify|otp|2fa|two[- ]factor|authenticator|"
    r"one[- ]time password|oath|code|验证码|校验码|动态口令|二次验证"
)
DEFAULT_PERIOD = 30
MIN_VALID_SECONDS = 3
LOCK_TIMEOUT_SECONDS = 90
STALE_LOCK_SECONDS = 120
UNOWNED_LOCK_GRACE_SECONDS = 5


def _wait_for_stable_totp_window(period: int = DEFAULT_PERIOD, min_valid_seconds: int = MIN_VALID_SECONDS) -> None:
    remaining = period - (time.time() % period)
    if remaining < min_valid_seconds:
        time.sleep(remaining + 0.25)


def _totp_now(secret: str, period: int = DEFAULT_PERIOD, digits: int = 6) -> str:
    return _totp_for_counter(secret, int(time.time() // period), period, digits)


def _totp_for_counter(secret: str, counter: int, period: int = DEFAULT_PERIOD, digits: int = 6) -> str:
    normalized = re.sub(r"\s+", "", secret).upper()
    normalized += "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def _log_askpass_event(message: str) -> None:
    log_path = os.environ.get("SSH_TOTP_ASKPASS_LOG", "")
    if not log_path:
        return
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    except Exception:
        pass


def _state_dir() -> Path:
    configured = os.environ.get("SSH_TOTP_STATE_DIR", "")
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / "codex-ssh-totp"


def _secret_key(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False

    if os.name == "nt":
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


def _read_json(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return {}
    if not raw:
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid TOTP state object: {path}")
    return data


def _write_json(path: Path, data: dict) -> None:
    temp_path = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temp_path.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    os.replace(temp_path, path)


def _write_lock(lock_fd: int) -> None:
    payload = json.dumps(
        {"pid": os.getpid(), "created_at": time.time()},
        separators=(",", ":"),
    ).encode("utf-8")
    os.write(lock_fd, payload)
    os.fsync(lock_fd)


def _lock_is_stale(lock_path: Path) -> bool:
    try:
        stat = lock_path.stat()
    except FileNotFoundError:
        return False

    data = _read_json(lock_path)
    now = time.time()
    pid = data.get("pid")
    created_at = data.get("created_at", stat.st_mtime)

    if pid is None:
        return now - stat.st_mtime > UNOWNED_LOCK_GRACE_SECONDS

    try:
        pid = int(pid)
        created_at = float(created_at)
    except (TypeError, ValueError):
        return now - stat.st_mtime > UNOWNED_LOCK_GRACE_SECONDS

    return not _process_is_alive(pid) or now - created_at > STALE_LOCK_SECONDS


def _acquire_lock(lock_path: Path, deadline: float) -> int:
    while True:
        try:
            lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            _write_lock(lock_fd)
            return lock_fd
        except FileExistsError:
            if time.time() > deadline:
                owner = _read_json(lock_path)
                raise TimeoutError(f"Timed out waiting for TOTP lease: {owner}")
            if _lock_is_stale(lock_path):
                lock_path.unlink(missing_ok=True)
                continue
            time.sleep(0.2)


def _reserve_totp_counter(secret: str, period: int = DEFAULT_PERIOD) -> int:
    state_dir = _state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    key = _secret_key(secret)
    state_path = state_dir / f"{key}.json"
    lock_path = state_dir / f"{key}.lock"
    deadline = time.time() + LOCK_TIMEOUT_SECONDS

    while True:
        lock_fd = _acquire_lock(lock_path, deadline)
        wait_seconds = 0.0
        try:
            state = _read_json(state_path)
            now = time.time()
            counter = int(now // period)
            remaining = period - (now % period)
            last_counter = state.get("last_counter", state.get("last_step"))

            if remaining < MIN_VALID_SECONDS or last_counter == counter:
                wait_seconds = remaining + 0.25
            else:
                _write_json(
                    state_path,
                    {
                        "last_counter": counter,
                        "last_step": counter,
                        "issued_at": now,
                        "pid": os.getpid(),
                    },
                )
                return counter
        finally:
            os.close(lock_fd)
            lock_path.unlink(missing_ok=True)

        if time.time() + wait_seconds > deadline:
            raise TimeoutError("Timed out waiting for next unused TOTP window")
        _log_askpass_event(f"wait-next-window seconds={wait_seconds:.3f}")
        time.sleep(wait_seconds)


def generate_response(prompt: str, secret: str, prompt_pattern: str = "") -> str:
    if not secret:
        _log_askpass_event(f"missing-secret prompt={prompt!r}")
        raise ValueError("SSH_TOTP_SECRET is required")
    pattern = prompt_pattern or DEFAULT_PROMPT_PATTERN
    matched = bool(re.search(pattern, prompt, re.IGNORECASE))
    _log_askpass_event(f"prompt={prompt!r} pattern={pattern!r} matched={matched}")
    if not matched:
        raise ValueError(f"Unsupported SSH prompt: {prompt}")
    counter = _reserve_totp_counter(secret)
    return _totp_for_counter(secret, counter)


def main() -> int:
    prompt = " ".join(sys.argv[1:])
    secret = os.environ.get("SSH_TOTP_SECRET", "")
    prompt_pattern = os.environ.get("SSH_TOTP_PROMPT_PATTERN", "")
    try:
        print(generate_response(prompt, secret, prompt_pattern))
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
