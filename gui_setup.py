#!/usr/bin/env python3
"""Point GUI SSH clients at the ssh-otp wrapper.

VS Code (and its forks) spawn the local ``ssh`` binary named by
``remote.SSH.path``, so pointing that setting at ``sshotp`` gives the Remote -
SSH extension, its terminals and their git calls the same automatic OTP.

Apps that implement SSH themselves (Termius, JetBrains, ...) cannot be pointed
at a binary. They get the base SOCKS listener instead: add
``127.0.0.1:7070`` (second entry: ``:7071``) as a SOCKS5 proxy on the host and
keep it alive with ``otp-up``.

Usage:
    python3 gui_setup.py [--wrapper-dir DIR] [--platform auto|posix|windows]
                         [--print-only] [--quiet]

Exit status is 0 even when nothing was found; the summary explains why.
"""

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
SETTING_KEY = "remote.SSH.path"
BACKUP_SUFFIX = ".bak-ssh-otp-"


def wrapper_path(wrapper_dir: Path, platform: str) -> str:
    launcher = "sshotp.cmd" if platform == "windows" else "sshotp"
    return (wrapper_dir / launcher).resolve().as_posix()


def settings_candidates(platform: str, home: Optional[Path] = None) -> List[Path]:
    home = home or Path.home()
    if platform == "windows":
        appdata = os.environ.get("APPDATA", str(home / "AppData" / "Roaming"))
        return [
            Path(appdata) / name / "User" / "settings.json"
            for name in ("Code", "Code - Insiders", "VSCodium")
        ]
    if sys.platform == "darwin":
        base = home / "Library" / "Application Support"
        return [
            base / name / "User" / "settings.json"
            for name in ("Code", "Code - Insiders", "VSCodium")
        ]
    base = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
    return [
        base / name / "User" / "settings.json"
        for name in ("Code", "Code - Insiders", "VSCodium", "Code - OSS")
    ]


def _json_string(value: str) -> str:
    return json.dumps(value)


def set_jsonc_key(text: str, key: str, value: str) -> Tuple[str, bool]:
    """Set one key in JSON-with-comments text, preserving everything else."""
    import re

    pattern = re.compile(
        r'(?m)^(?P<indent>[ \t]*)"' + re.escape(key) + r'"\s*:\s*"(?P<value>(?:[^"\\]|\\.)*)"'
    )
    match = pattern.search(text)
    if match:
        raw = match.group("value")
        try:
            current = json.loads('"' + raw + '"')
        except ValueError:
            current = raw
        if current == value:
            return text, False
        replacement = _json_string(value)[1:-1]
        new_text = text[: match.start("value")] + replacement + text[match.end("value") :]
        return new_text, True

    brace = text.find("{")
    if brace < 0:
        raise ValueError("not a JSON object")
    rest = text[brace + 1 :]
    stripped = rest.lstrip()
    if stripped.startswith("}"):
        # Empty object: keep it on one line.
        insert_at = brace + 1
        return text[:insert_at] + f' "{key}": {_json_string(value)} ' + text[insert_at:], True
    insertion = f'\n    "{key}": {_json_string(value)},'
    insert_at = brace + 1
    return text[:insert_at] + insertion + text[insert_at:], True


def update_settings(path: Path, value: str, dry_run: bool = False) -> Tuple[bool, Optional[Path]]:
    original = path.read_text(encoding="utf-8-sig")
    updated, changed = set_jsonc_key(original, SETTING_KEY, value)
    if not changed or dry_run:
        return changed, None
    stamp = time.strftime("%Y%m%d%H%M%S")
    backup = path.with_name(path.name + BACKUP_SUFFIX + stamp)
    shutil.copy2(path, backup)
    path.write_text(updated, encoding="utf-8")
    return True, backup


def socks_report(wrapper_dir: Path) -> List[str]:
    """One line per base entry point for app-based clients."""
    lines: List[str] = []
    try:
        sys.path.insert(0, str(wrapper_dir))
        import ssh_totp  # noqa: WPS433 (deliberate optional import)

        config_file = ssh_totp.ssh_config_path()
        gateways = ssh_totp._config_gateways(config_file)
    except Exception:
        return lines
    for alias in gateways:
        try:
            lines.append(f"    {alias:<6} {ssh_totp.gateway_socks(alias)}")
        except Exception:
            continue
    return lines


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Point GUI SSH clients at ssh-otp.")
    parser.add_argument("--wrapper-dir", default=str(SCRIPT_DIR))
    parser.add_argument("--platform", choices=("auto", "posix", "windows"), default="auto")
    parser.add_argument("--print-only", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    platform = args.platform
    if platform == "auto":
        platform = "windows" if os.name == "nt" else "posix"
    wrapper = wrapper_path(Path(args.wrapper_dir), platform)

    changed_files: List[str] = []
    skipped: List[str] = []
    found_any = False
    for candidate in settings_candidates(platform):
        if not candidate.is_file():
            skipped.append(str(candidate))
            continue
        found_any = True
        try:
            changed, backup = update_settings(candidate, wrapper, dry_run=args.print_only)
        except (OSError, ValueError) as exc:
            print(f"gui: cannot update {candidate}: {exc}", file=sys.stderr)
            continue
        state = "updated" if changed else "already set"
        if args.print_only and changed:
            state = "would update"
        print(f"  vscode: {state} {candidate}")
        if changed:
            changed_files.append(str(candidate))
            if backup:
                print(f"          backup: {backup}")

    if not found_any and not args.quiet:
        print("  vscode: no settings.json found (install VS Code, or set")
        print(f'          "remote.SSH.path": {json.dumps(wrapper)}')

    socks = socks_report(Path(args.wrapper_dir))
    if socks and not args.quiet:
        print("  GUI apps that cannot spawn ssh (Termius, JetBrains): set a SOCKS5")
        print("  proxy on the host entry and keep it alive with `otp-up`:")
        for line in socks:
            print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
