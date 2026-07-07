#!/bin/sh
# install.sh -- set up ssh-otp on macOS / Linux / Termux (idempotent).
#
#   sh ~/.ssh/ssh_otp/install.sh
#
# Does NOT touch ~/.ssh/config (rewrite that once, it's synced). It:
#   * creates ~/.ssh/cm (the ControlMaster socket dir) with safe perms
#   * makes the wrapper/shim/scripts executable
#   * adds the shellrc.sh source line to ~/.zshrc and ~/.bashrc (guarded)
#   * links ~/.local/bin/ssh -> wrapper (matches the existing Mac layout)
#   * prints the VS Code / git one-liners
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
sshdir=$(CDPATH= cd -- "$dir/.." && pwd -P)

echo "ssh-otp install: $dir"

# 1. socket dir + perms
mkdir -p "$HOME/.ssh/cm"
chmod 700 "$HOME/.ssh" "$HOME/.ssh/cm" 2>/dev/null || true
for k in id_rsa for_dg_rsa for_ty_A800_rsa for_ty_H800_rsa xuchunfu.id yuanquan; do
  [ -f "$HOME/.ssh/$k" ] && chmod 600 "$HOME/.ssh/$k" 2>/dev/null || true
done
chmod +x "$dir/sshotp" "$dir/bin/ssh" 2>/dev/null || true
chmod +x "$dir/ssh_totp.py" "$dir/totp_askpass.py" 2>/dev/null || true

# 2. shell integration (idempotent block via markers)
block_begin="# >>> ssh-otp >>>"
block_end="# <<< ssh-otp <<<"
line='[ -f "$HOME/.ssh/ssh_otp/shellrc.sh" ] && . "$HOME/.ssh/ssh_otp/shellrc.sh"'
for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
  [ -e "$rc" ] || continue
  if grep -qF "$block_begin" "$rc" 2>/dev/null; then
    echo "  shell: already wired in $rc"
  else
    printf '\n%s\n%s\n%s\n' "$block_begin" "$line" "$block_end" >> "$rc"
    echo "  shell: added source line to $rc"
  fi
done

# 3. ~/.local/bin/ssh convenience link (kept from the earlier Mac setup)
if command -v ln >/dev/null 2>&1; then
  mkdir -p "$HOME/.local/bin"
  ln -sf "$dir/bin/ssh" "$HOME/.local/bin/ssh" 2>/dev/null \
    && echo "  linked ~/.local/bin/ssh -> $dir/bin/ssh" || true
fi

cat <<EOF

Done. Next:
  * Restart your shell (or: . ~/.zshrc), then:  otp-up X   &&  ssh f101 true
  * VS Code:  set  "remote.SSH.path": "$dir/sshotp"
  * git:      git config --global core.sshCommand "$dir/sshotp"
  * rsync:    rsync -e "$dir/sshotp" ...
EOF
