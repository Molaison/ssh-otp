#!/bin/sh
# install.sh -- set up ssh-otp on macOS / Linux / Termux (idempotent).
#
#   sh ~/.ssh/ssh_otp/install.sh
#
# Does NOT touch ~/.ssh/config (rewrite that once, it's synced). It:
#   * creates ~/.ssh/cm (the ControlMaster socket dir) with safe perms
#   * makes the wrapper/shim/scripts executable
#   * adds an idempotent shellrc.sh block to the active shell profile
#   * links ~/.local/bin/ssh -> wrapper (matches the existing Mac layout)
#   * configures git core.sshCommand automatically (unless SSH_TOTP_SKIP_GIT=1)
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
home_dir=${SSH_TOTP_HOME:-$HOME}

echo "ssh-otp install: $dir"

# 1. socket dir + perms
mkdir -p "$home_dir/.ssh/cm"
chmod 700 "$home_dir/.ssh" "$home_dir/.ssh/cm" 2>/dev/null || true
for k in id_rsa for_dg_rsa for_ty_A800_rsa for_ty_H800_rsa xuchunfu.id yuanquan; do
  [ -f "$home_dir/.ssh/$k" ] && chmod 600 "$home_dir/.ssh/$k" 2>/dev/null || true
done
chmod +x "$dir/sshotp" "$dir/configure" "$dir/bin/ssh" 2>/dev/null || true
chmod +x "$dir/ssh_totp.py" "$dir/totp_askpass.py" "$dir/configure_ssh.py" 2>/dev/null || true

# 2. Shell integration (replace one managed block in the active shell profile).
block_begin="# >>> ssh-otp >>>"
block_end="# <<< ssh-otp <<<"
line="SSH_TOTP_DIR=\"$dir\"; export SSH_TOTP_DIR; [ -f \"$dir/shellrc.sh\" ] && . \"$dir/shellrc.sh\""
if [ -n "${SSH_TOTP_RC:-}" ]; then
  rc=$SSH_TOTP_RC
else
  case "${SHELL:-}" in
    */zsh) rc="$home_dir/.zshrc" ;;
    */bash) rc="$home_dir/.bashrc" ;;
    *)
      if [ -e "$home_dir/.zshrc" ]; then rc="$home_dir/.zshrc"
      elif [ -e "$home_dir/.bashrc" ]; then rc="$home_dir/.bashrc"
      else rc="$home_dir/.profile"
      fi
      ;;
  esac
fi
mkdir -p "$(dirname -- "$rc")"
[ -e "$rc" ] || : > "$rc"
rc_temp="$rc.ssh-otp.$$"
if grep -qF "$block_begin" "$rc" 2>/dev/null; then
  sed "/^# >>> ssh-otp >>>$/,/^# <<< ssh-otp <<<$/d" "$rc" > "$rc_temp"
else
  cp "$rc" "$rc_temp"
fi
printf '\n%s\n%s\n%s\n' "$block_begin" "$line" "$block_end" >> "$rc_temp"
mv "$rc_temp" "$rc"
echo "  shell: configured $rc"

# 3. ~/.local/bin/ssh convenience link (kept from the earlier Mac setup)
if command -v ln >/dev/null 2>&1; then
  mkdir -p "$home_dir/.local/bin"
  ln -sf "$dir/bin/ssh" "$home_dir/.local/bin/ssh" 2>/dev/null \
    && echo "  linked $home_dir/.local/bin/ssh -> $dir/bin/ssh" || true
fi

# 4. Git integration.
if [ "${SSH_TOTP_SKIP_GIT:-0}" != "1" ] && command -v git >/dev/null 2>&1; then
  git_wrapper_quoted=$(printf "%s" "$dir/sshotp" | sed "s/'/'\\\\''/g")
  git_command="'$git_wrapper_quoted'"
  HOME="$home_dir" git config --global core.sshCommand "$git_command"
  echo "  git: core.sshCommand=$git_command"
fi

if ! "$dir/sshotp" --resolve-totp "$("$dir/sshotp" --default-jump 2>/dev/null || echo x)" >/dev/null 2>&1; then
  echo "  note: no TOTP host is configured yet -- run $dir/configure ... to generate the ssh block"
fi

cat <<EOF

Done. Next:
  * Configure host-specific values without editing SSH config: $dir/configure --help
  * Restart your shell (or: . "$rc"), then use ssh normally (x starts automatically)
  * Manual controls remain available: otp-up x / otp-status x / otp-down x
  * VS Code:  set  "remote.SSH.path": "$dir/sshotp"
  * rsync:    rsync -e "$dir/sshotp" ...
EOF
