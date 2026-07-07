#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

import ssh_totp


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 2:
        print(f"usage: {sys.argv[0]} <host> <port>", file=sys.stderr)
        return 2

    host, port = argv
    script_dir = Path(__file__).resolve().parent
    config_file = os.environ.get("SSH_TOTP_CONFIG", str(Path.home() / ".ssh" / "config"))
    jump_alias = os.environ.get("SSH_TOTP_JUMP_ALIAS", "X")
    real_ssh = os.environ.get("SSH_TOTP_REAL_SSH", r"C:\Windows\System32\OpenSSH\ssh.exe")

    totp = ssh_totp.resolve_totp_for_args([jump_alias], config_file)
    env = os.environ.copy()
    env["SSH_TOTP_REAL_SSH"] = real_ssh
    env["SSH_ASKPASS"] = str(script_dir / "totp_askpass.cmd")
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env.setdefault("SSH_TOTP_ASKPASS_LOG", str(script_dir / "debug_proxy_askpass.log"))
    env.setdefault("DISPLAY", ":0")

    if totp:
        env["SSH_TOTP_SECRET"] = totp["secret"]
        # The debug proxy only authenticates to the OTP jump host. Windows
        # OpenSSH often exposes that OTP challenge as a generic
        # keyboard-interactive prompt, so the proxy must answer any askpass
        # prompt with the current TOTP code.
        env["SSH_TOTP_PROMPT_PATTERN"] = ".*"

    return subprocess.call(
        [
            real_ssh,
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "PreferredAuthentications=publickey,keyboard-interactive",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=yes",
            "-o", "NumberOfPasswordPrompts=3",
            "-i", str(Path.home() / ".ssh" / "id_rsa"),
            "-W", f"{host}:{port}",
            jump_alias,
        ],
        env=env,
    )


if __name__ == "__main__":
    raise SystemExit(main())
