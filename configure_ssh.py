#!/usr/bin/env python3
"""Idempotently generate the host-specific ssh-otp block in ~/.ssh/config."""

import argparse
import base64
import getpass
import os
import re
import shlex
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
BLOCK_BEGIN = "# >>> ssh-otp managed >>>"
BLOCK_END = "# <<< ssh-otp managed <<<"
DEFAULT_PROMPT = (
    r"verification|verify|otp|2fa|two[- ]factor|authenticator|"
    r"one[- ]time password|oath|code"
)
ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
MANAGED_BLOCK_PATTERN = re.compile(
    rf"(?ms)^{re.escape(BLOCK_BEGIN)}\r?\n.*?^{re.escape(BLOCK_END)}\r?\n?"
)


@dataclass(frozen=True)
class Gateway:
    """One OTP entry point for the cluster (a master that can hold SOCKS)."""

    alias: str
    hostname: str
    user: str
    port: int = 22
    identity_file: str = ""


@dataclass(frozen=True)
class ProxyHost:
    alias: str
    hostname: str
    user: str = ""
    port: Optional[int] = None
    gateway: str = ""


@dataclass(frozen=True)
class ConfigureOptions:
    config_path: Path
    gateways: Sequence[Gateway]
    totp_prompt: str
    platform: str
    wrapper_dir: Path
    proxies: Sequence[ProxyHost]
    identity_file: str = "~/.ssh/id_rsa"
    backup: bool = True

    @property
    def primary(self) -> Gateway:
        return self.gateways[0]


@dataclass(frozen=True)
class ConfigureResult:
    changed: bool
    config_path: Path
    backup_path: Optional[Path]
    aliases: Sequence[str]
    shadowed: Sequence[str] = ()


def _single_line(value: str, label: str) -> str:
    value = value.strip()
    if not value or any(char in value for char in ("\r", "\n", "\x00")):
        raise ValueError(f"{label} must be a non-empty single-line value")
    return value


def _alias(value: str, label: str = "alias") -> str:
    value = _single_line(value, label)
    if not ALIAS_PATTERN.fullmatch(value):
        raise ValueError(f"{label} contains unsupported characters: {value!r}")
    return value


def _port(value: int, label: str = "port") -> int:
    value = int(value)
    if not 1 <= value <= 65535:
        raise ValueError(f"{label} must be between 1 and 65535")
    return value


def normalize_totp_secret(secret: str) -> str:
    raw = secret.strip()
    if "\n" in raw or "\r" in raw:
        # A pasted block of lines (e.g. two secrets) would otherwise be merged
        # into one long, silently wrong Base32 string.
        raise ValueError("TOTP secret must be a single line")
    normalized = re.sub(r"\s+", "", raw).upper().rstrip("=")
    if not normalized:
        raise ValueError("TOTP secret is empty")
    if not re.fullmatch(r"[A-Z2-7]+", normalized):
        raise ValueError("TOTP secret must be Base32")
    padded = normalized + "=" * ((8 - len(normalized) % 8) % 8)
    try:
        decoded = base64.b32decode(padded, casefold=True)
    except Exception as exc:
        raise ValueError("TOTP secret must be valid Base32") from exc
    if len(decoded) < 10:
        raise ValueError("TOTP secret must decode to at least 10 bytes")
    return normalized


def parse_gateway(value: str) -> Gateway:
    """Parse ALIAS=HOST[,USER[,PORT[,IDENTITY]]]."""
    alias, separator, remainder = value.partition("=")
    if not separator:
        raise ValueError("gateway must use ALIAS=HOST[,USER[,PORT[,IDENTITY]]]")
    parts = [part.strip() for part in remainder.split(",")]
    if not 1 <= len(parts) <= 4 or not parts[0]:
        raise ValueError("gateway must use ALIAS=HOST[,USER[,PORT[,IDENTITY]]]")
    user = _single_line(parts[1], "gateway user") if len(parts) >= 2 and parts[1] else ""
    port = _port(int(parts[2]), "gateway port") if len(parts) >= 3 and parts[2] else 22
    identity = _single_line(parts[3], "gateway identity") if len(parts) == 4 and parts[3] else ""
    return Gateway(
        alias=_alias(alias, "gateway alias"),
        hostname=_single_line(parts[0], "gateway hostname"),
        user=user,
        port=port,
        identity_file=identity,
    )


def parse_proxy(value: str) -> ProxyHost:
    """Parse ALIAS=HOST[,USER[,PORT]][@GATEWAY]."""
    alias, separator, remainder = value.partition("=")
    if not separator:
        raise ValueError("proxy must use ALIAS=HOST[,USER[,PORT]][@GATEWAY]")
    gateway = ""
    if "@" in remainder:
        remainder, _, gateway = remainder.rpartition("@")
        gateway = _alias(gateway, "proxy gateway")
    parts = [part.strip() for part in remainder.split(",")]
    if not 1 <= len(parts) <= 3 or not parts[0]:
        raise ValueError("proxy must use ALIAS=HOST[,USER[,PORT]]")
    user = _single_line(parts[1], "proxy user") if len(parts) >= 2 and parts[1] else ""
    port = _port(int(parts[2]), "proxy port") if len(parts) == 3 and parts[2] else None
    return ProxyHost(
        alias=_alias(alias, "proxy alias"),
        hostname=_single_line(parts[0], "proxy hostname"),
        user=user,
        port=port,
        gateway=gateway,
    )


def _platform_name(requested: str) -> str:
    if requested == "auto":
        return "windows" if os.name == "nt" else "posix"
    return requested


def _proxy_command(options: ConfigureOptions, jump_alias: str) -> str:
    launcher = "sshotp.cmd" if options.platform == "windows" else "sshotp"
    wrapper = (options.wrapper_dir / launcher).resolve().as_posix()
    if options.platform == "windows":
        executable = '"' + wrapper.replace('"', '\\"') + '"'
    else:
        executable = shlex.quote(wrapper)
    # The alias is carried explicitly so automatic gateway startup works even
    # when --jump-alias is not the historical default ``x``.
    return f"{executable} --gateway {jump_alias} --socks %h %p"


def build_managed_block(options: ConfigureOptions, secret: str) -> str:
    prompt = _single_line(options.totp_prompt, "TOTP prompt pattern")
    secret = normalize_totp_secret(secret)
    gateways = [
        Gateway(
            alias=_alias(gateway.alias, "gateway alias"),
            hostname=_single_line(gateway.hostname, "gateway hostname"),
            user=_single_line(gateway.user, "gateway user"),
            port=_port(gateway.port, "gateway port"),
            identity_file=gateway.identity_file,
        )
        for gateway in options.gateways
    ]
    if not gateways:
        raise ValueError("at least one gateway is required")
    primary = gateways[0]

    lines = [
        BLOCK_BEGIN,
        "# Generated by configure_ssh.py. Re-run the command to update this block.",
        f"# totp_secret: {secret}",
        f"# totp_prompt: {prompt}",
        "# totp_master: yes",
        f"# totp_gateway: {primary.alias}",
    ]
    for index, gateway in enumerate(gateways):
        if index:
            # Each entry point needs its own metadata: comments apply to the
            # Host block that follows, so repeating them keeps every gateway
            # answering its own code (and being usable as a SOCKS master).
            lines.extend(
                [
                    "",
                    f"# totp_secret: {secret}",
                    f"# totp_prompt: {prompt}",
                    "# totp_master: yes",
                ]
            )
        lines.extend(
            [
                f"Host {gateway.alias}",
                f"    HostName {gateway.hostname}",
                f"    User {gateway.user}",
                f"    Port {gateway.port}",
                f"    IdentityFile {gateway.identity_file or options.identity_file}",
                "    PreferredAuthentications publickey,keyboard-interactive",
                "    KbdInteractiveAuthentication yes",
                "    NumberOfPasswordPrompts 3",
            ]
        )

    gateway_aliases = {gateway.alias for gateway in gateways}
    proxy_aliases = set()
    for proxy in options.proxies:
        alias = _alias(proxy.alias, "proxy alias")
        if alias in gateway_aliases:
            raise ValueError(f"proxy alias duplicates a gateway alias: {alias}")
        if alias in proxy_aliases:
            raise ValueError(f"duplicate proxy alias: {alias}")
        proxy_aliases.add(alias)
        gateway = proxy.gateway or primary.alias
        if gateway not in gateway_aliases:
            raise ValueError(f"proxy {alias} uses unknown gateway: {gateway}")
        lines.extend(["", f"Host {alias}"])
        lines.append(f"    HostName {_single_line(proxy.hostname, 'proxy hostname')}")
        if proxy.user:
            lines.append(f"    User {_single_line(proxy.user, 'proxy user')}")
        if proxy.port is not None:
            lines.append(f"    Port {_port(proxy.port, 'proxy port')}")
        lines.append(f"    ProxyCommand {_proxy_command(options, gateway)}")
    lines.append(BLOCK_END)
    return "\n".join(lines) + "\n"


def existing_host_aliases(existing: str) -> set:
    """Host aliases already declared outside the managed block."""
    outside = MANAGED_BLOCK_PATTERN.sub("", existing)
    aliases = set()
    for line in outside.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        keyword, _, rest = stripped.partition(" ")
        keyword = keyword.lower()
        if keyword == "match":
            # Everything below a Match block is conditional; stop scanning.
            break
        if keyword == "host":
            aliases.update(rest.split())
    return aliases


def _replace_managed_block(existing: str, block: str) -> str:
    begin_count = existing.count(BLOCK_BEGIN)
    end_count = existing.count(BLOCK_END)
    if begin_count != end_count or begin_count > 1:
        raise ValueError("SSH config contains malformed or duplicate ssh-otp managed markers")
    if begin_count == 1:
        return MANAGED_BLOCK_PATTERN.sub(block, existing, count=1)
    if not existing:
        return block
    return block + "\n" + existing.lstrip("\ufeff")


def update_ssh_config(options: ConfigureOptions, secret: str) -> ConfigureResult:
    config_path = options.config_path.expanduser().resolve()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    existing = ""
    if config_path.exists():
        existing = config_path.read_text(encoding="utf-8-sig")
    block = build_managed_block(options, secret)
    updated = _replace_managed_block(existing, block)
    aliases = [
        *(gateway.alias for gateway in options.gateways),
        *(proxy.alias for proxy in options.proxies),
    ]
    shadowed = sorted(set(aliases) & existing_host_aliases(existing))
    if updated == existing:
        return ConfigureResult(False, config_path, None, aliases, shadowed)

    backup_path = None
    if options.backup and config_path.exists():
        stamp = time.strftime("%Y%m%d%H%M%S")
        backup_path = config_path.with_name(config_path.name + f".bak-ssh-otp-{stamp}")
        suffix = 1
        while backup_path.exists():
            backup_path = config_path.with_name(
                config_path.name + f".bak-ssh-otp-{stamp}-{suffix}"
            )
            suffix += 1
        shutil.copy2(config_path, backup_path)

    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="\n",
        delete=False,
        dir=str(config_path.parent),
        prefix=config_path.name + ".",
        suffix=".tmp",
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, config_path)
        if os.name != "nt":
            os.chmod(config_path, 0o600)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return ConfigureResult(True, config_path, backup_path, aliases, shadowed)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate an idempotent ssh-otp block in ~/.ssh/config.",
        allow_abbrev=False,
    )
    parser.add_argument("--jump-host", default="", help="Primary gateway DNS name or IP")
    parser.add_argument("--jump-user", default="", help="Primary gateway SSH user")
    parser.add_argument("--jump-alias", default=os.environ.get("SSH_TOTP_JUMP_ALIAS", "x"))
    parser.add_argument("--jump-port", type=int, default=22)
    parser.add_argument("--identity-file", default="~/.ssh/id_rsa")
    parser.add_argument(
        "--gateway",
        action="append",
        default=[],
        metavar="ALIAS=HOST[,USER[,PORT[,IDENTITY]]]",
        help="Additional entry point for the same cluster (repeatable)",
    )
    parser.add_argument(
        "--proxy",
        action="append",
        default=[],
        metavar="ALIAS=HOST[,USER[,PORT]][@GATEWAY]",
    )
    parser.add_argument("--config", default=str(Path.home() / ".ssh" / "config"))
    parser.add_argument("--wrapper-dir", default=str(SCRIPT_DIR))
    parser.add_argument("--platform", choices=("auto", "windows", "posix"), default="auto")
    parser.add_argument("--totp-secret-env", default="SSH_TOTP_SECRET")
    parser.add_argument("--totp-prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--no-backup", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def _gateways_from_args(args: argparse.Namespace) -> List[Gateway]:
    gateways: List[Gateway] = []
    if args.jump_host:
        if not args.jump_user:
            raise ValueError("--jump-user is required with --jump-host")
        gateways.append(
            Gateway(
                alias=args.jump_alias,
                hostname=args.jump_host,
                user=args.jump_user,
                port=args.jump_port,
                identity_file=args.identity_file,
            )
        )
    elif args.jump_alias == "x" and not args.gateway:
        raise ValueError("provide --jump-host/--jump-user or at least one --jump")
    gateways.extend(parse_gateway(value) for value in args.gateway)
    if not gateways:
        raise ValueError("provide --jump-host/--jump-user or at least one --jump")
    seen = set()
    for gateway in gateways:
        if gateway.alias in seen:
            raise ValueError(f"duplicate gateway alias: {gateway.alias}")
        seen.add(gateway.alias)
    return gateways


def _options_from_args(args: argparse.Namespace) -> ConfigureOptions:
    return ConfigureOptions(
        config_path=Path(args.config),
        gateways=_gateways_from_args(args),
        totp_prompt=args.totp_prompt,
        platform=_platform_name(args.platform),
        wrapper_dir=Path(args.wrapper_dir),
        proxies=[parse_proxy(value) for value in args.proxy],
        identity_file=args.identity_file,
        backup=not args.no_backup,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        options = _options_from_args(args)
        secret = os.environ.get(args.totp_secret_env, "")
        if not secret:
            if args.non_interactive:
                raise ValueError(
                    f"{args.totp_secret_env} must be set in non-interactive mode"
                )
            secret = getpass.getpass("TOTP Base32 secret (input hidden): ")
        secret = normalize_totp_secret(secret)
        if args.dry_run:
            block = build_managed_block(options, secret)
            print(re.sub(r"(?m)^# totp_secret:.*$", "# totp_secret: <redacted>", block), end="")
            return 0
        result = update_ssh_config(options, secret)
    except (OSError, ValueError) as exc:
        print(f"configure_ssh: {exc}", file=sys.stderr)
        return 2

    state = "updated" if result.changed else "unchanged"
    print(f"ssh-otp config: {state} {result.config_path}")
    if result.backup_path:
        print(f"backup: {result.backup_path}")
    print("configured aliases: " + ", ".join(result.aliases))
    if result.shadowed:
        print(
            "warning: these aliases already exist outside the managed block and will be "
            "shadowed by it: " + ", ".join(result.shadowed) + "\n"
            "         (the managed block is first, and ssh uses the first value it sees)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
