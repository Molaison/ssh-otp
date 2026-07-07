# ssh-otp

Reusable OpenSSH OTP helper for hosts that require TOTP through keyboard-interactive auth.

## What It Provides

- Direct OTP aliases such as `X` and `x`.
- A gateway master opened by `otp-up X`.
- A local SOCKS listener, default `127.0.0.1:7070`, for hosts behind the gateway.
- Transparent handling for ordinary hosts.
- Windows and POSIX launchers.

## Install

Windows PowerShell:

```powershell
git clone <repo-url> $HOME\.ssh\ssh_otp
pwsh -NoProfile -File $HOME\.ssh\ssh_otp\install.ps1
```

POSIX shells:

```sh
git clone <repo-url> ~/.ssh/ssh_otp
sh ~/.ssh/ssh_otp/install.sh
```

## Configure

Copy the relevant blocks from `examples/ssh_config.example` into `~/.ssh/config`.
Replace host names, users, key paths, and `totp_secret` values.

The direct OTP aliases are ordinary `Host` blocks with metadata comments:

```sshconfig
# totp_secret: BASE32SECRET
# totp_prompt: verification|otp|code
Host X
    HostName gateway.example.com
    User user
    Port 50001
    IdentityFile ~/.ssh/id_rsa

# totp_secret: BASE32SECRET
# totp_prompt: verification|otp|code
Host x
    HostName 192.168.1.10
    User user
    IdentityFile ~/.ssh/id_rsa
```

Hosts behind `X` use the SOCKS relay:

```sshconfig
Host f101
    HostName f101.internal.example.com
    User user
    ProxyCommand C:/Users/YOU/.ssh/ssh_otp/sshotp.cmd --socks %h %p
```

For POSIX machines use:

```sshconfig
    ProxyCommand ~/.ssh/ssh_otp/sshotp --socks %h %p
```

## Use

Start the gateway master:

```sh
otp-up X
```

Connect:

```sh
ssh X
ssh x
ssh f101
```

Stop the gateway master:

```sh
otp-down X
```

## Test

```sh
python ~/.ssh/ssh_otp/test_ssh_totp_regression.py
```

