# ssh-otp

Reusable OpenSSH wrapper for hosts that require a key plus a TOTP
keyboard-interactive challenge. It supports Windows, macOS, Linux, and Termux.

## What It Provides

- Direct OTP aliases such as `X` and `x`.
- On-demand startup of the default gateway master (`x` unless the ssh config says otherwise).
- One local SOCKS listener (default `127.0.0.1:7070`) reused for about eight hours.
- One verification code per host per eight hours: every OTP connection multiplexes, and the
  SOCKS listener attaches to a master that is already running instead of authenticating again.
- Cross-process startup locking so concurrent IDE, Git, and terminal probes issue one OTP.
- Transparent behavior for hosts without TOTP metadata.
- Idempotent shell, PowerShell, Git, and SSH-config setup.

## From Scratch (empty ssh config)

```sh
git clone https://github.com/Molaison/ssh-otp.git ~/.ssh/ssh_otp
sh ~/.ssh/ssh_otp/install.sh
~/.ssh/ssh_otp/configure \
  --base x=10.10.1.100,alice,22 \
  --base X=public.example.com,alice,50001 \
  --host f101=10.10.1.101,alice@x \
  --host f103=10.10.1.103,alice@X
```

`--base` is an entry point of the cluster (`x` internal, `X` public); `--host` is a
machine reached through one of them, with `@BASE` choosing the entry (the first base
is the default). One managed block keeps everything, so re-running the same command
updates in place and never drops an entry.

Plain `ssh x` opens an interactive session on that entry point (no remote command
needed); the first code is reused for the next eight hours. `ssh f101` then tunnels
through its base. Each base owns a SOCKS listener (`7070`, `7071`, ... in config
order) so several entries can run side by side, and `otp-up` / `otp-status` /
`otp-down` default to the first base (pass `X` to control another one).

The older `--jump-host` / `--jump-user` / `--jump-alias` / `--jump-port` flags still
work and describe the first base.

| Platform | Installer | SSH launcher | Automatic integration |
| --- | --- | --- | --- |
| Windows | `install.ps1` | `sshotp.cmd` | PowerShell profile, Python path, Git |
| macOS | `install.sh` | `sshotp` | zsh profile, `~/.local/bin/ssh`, Git |
| Linux | `install.sh` | `sshotp` | bash/profile, `~/.local/bin/ssh`, Git |
| Termux | `install.sh` | `sshotp` | bash/profile, `~/.local/bin/ssh`, Git |

## Requirements

- Python 3
- OpenSSH client
- Git (optional, but automatically configured when installed)

Termux users can install them with:

```sh
pkg install python openssh git
```

## Install

Windows PowerShell:

```powershell
git clone https://github.com/Molaison/ssh-otp.git "$HOME\.ssh\ssh_otp"
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$HOME\.ssh\ssh_otp\install.ps1"
```

macOS, Linux, and Termux:

```sh
git clone https://github.com/Molaison/ssh-otp.git ~/.ssh/ssh_otp
sh ~/.ssh/ssh_otp/install.sh
```

Both installers are idempotent. They discover Python automatically, put the
wrapper on the shell path, install the `otp-*` helpers, and set Git's global
`core.sshCommand`. Use `-SkipGitConfig` on Windows or
`SSH_TOTP_SKIP_GIT=1` on POSIX to leave Git unchanged.

## GUI Clients

`install.sh` / `install.ps1` point VS Code (Code, Insiders, VSCodium) at the wrapper by
setting `remote.SSH.path` in the user `settings.json`. Only that one key is touched, so
comments and unrelated settings survive; `SSH_TOTP_SKIP_GUI=1` (or `-SkipGuiConfig`)
skips it. Remote - SSH, its terminals and the git calls they make then answer the code
automatically, with no per-workspace tuning.

Apps that implement SSH themselves (Termius, JetBrains, ...) cannot run a helper binary.
Give the host a SOCKS5 proxy on the base listener instead:

| base | SOCKS5 endpoint | notes |
| --- | --- | --- |
| `x` | `127.0.0.1:7070` | first entry point |
| `X` | `127.0.0.1:7071` | second entry point |

```sh
otp-up          # opens the first base's listener (one code, reused for 8 h)
otp-status      # "Master running (pid=...)" when the listener is alive
```

The listener is the same one `ProxyCommand` uses, so the app gets exactly the ssh
experience through that base. The code is answered once by `otp-up`; afterwards the app
connects without prompting.

## Configure Without Editing SSH Config

The configurator asks for the TOTP secret with hidden input, validates it, and
creates or replaces one marked block at the top of `~/.ssh/config`. Existing
unmanaged host entries are preserved. Changed configs are backed up before an
atomic replacement; POSIX permissions are set to `0600`.

Windows:

```powershell
& "$HOME\.ssh\ssh_otp\configure.cmd" `
  --jump-host gateway.example.com `
  --jump-user alice `
  --jump-port 22 `
  --identity-file ~/.ssh/id_rsa `
  --proxy "compute=compute.internal,alice,22"
```

macOS, Linux, or Termux:

```sh
~/.ssh/ssh_otp/configure \
  --jump-host gateway.example.com \
  --jump-user alice \
  --jump-port 22 \
  --identity-file ~/.ssh/id_rsa \
  --proxy 'compute=compute.internal,alice,22'
```

A cluster with two entry points keeps both in the same managed block:

```sh
~/.ssh/ssh_otp/configure \
  --base x=10.10.1.100,alice,22 \
  --base X=public.example.com,alice,50001 \
  --host compute=compute.internal,alice,22@X
```

Repeat `--host ALIAS=HOST[,USER[,PORT]][@BASE]` for additional nodes. The jump alias
defaults to lowercase `x`; use `--jump-alias` or `SSH_TOTP_JUMP_ALIAS` to
override it. The alias is written into the block as `# totp_gateway:` and into
each `ProxyCommand`, so automatic startup follows it without any extra
environment. `--platform auto` selects `sshotp.cmd` on Windows and `sshotp` on
POSIX. Use `--dry-run` to preview a redacted generated block.

For unattended configuration, put the Base32 secret in `SSH_TOTP_SECRET` and
add `--non-interactive`. Do not pass the secret as a command-line argument or
commit the generated SSH config.

A sanitized manual configuration remains available in
`examples/ssh_config.example`.

## Use

Connect normally. If the SOCKS listener is absent, the first proxied connection
starts the gateway master (or adds the listener to a master that is already
running) and answers its OTP automatically:

```sh
ssh x
ssh compute
```

Interactive logins never prompt for the code. OpenSSH before 8.4 cannot be told to use
the askpass helper while a terminal is attached, so the first interactive connection
authenticates once in a detached master (which has no controlling terminal) and the
session multiplexes onto it. Only if that background start fails does ssh fall back to
asking on the terminal, and a typed code still works.

Later connections reuse the same master and listener. Manual controls default to
the gateway recorded in the ssh config:

```sh
otp-up
otp-status
otp-down
```

Useful overrides:

- `SSH_TOTP_AUTO_START=0` disables on-demand master startup.
- `SSH_TOTP_JUMP_ALIAS` overrides the gateway alias read from the ssh config.
- `SSH_TOTP_CONFIG=/path/to/config` points the wrapper (and automatic startup) at another ssh config.
- `SSH_OTP_SOCKS=127.0.0.1:7071` changes the listener.
- `SSH_TOTP_PYTHON=/path/to/python3` pins the interpreter.
- `SSH_TOTP_SOCKS_LOG=/path/to/log` enables payload-free relay diagnostics.

## Test

```sh
python3 test_ssh_totp_regression.py
python3 test_installers.py
```

On Windows, `python` or the Python launcher may be used instead of `python3`.
