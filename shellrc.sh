# ssh-otp shell integration -- source from ~/.zshrc (and/or ~/.bashrc):
#     [ -f ~/.ssh/ssh_otp/shellrc.sh ] && . ~/.ssh/ssh_otp/shellrc.sh
#
# Routes `ssh` (and scp/rsync/git that spawn ssh) through the OTP wrapper and
# defines the otp-* helpers. Safe to source on every machine: it only activates
# where ssh_otp is actually installed, so the synced .zshrc stays portable.
_ssh_otp_dir="${SSH_TOTP_DIR:-$HOME/.ssh/ssh_otp}"
if [ -f "$_ssh_otp_dir/ssh_totp.py" ]; then
  case ":$PATH:" in
    *":$_ssh_otp_dir/bin:"*) ;;
    *) PATH="$_ssh_otp_dir/bin:$PATH"; export PATH ;;
  esac

  # Gateway alias comes from the ssh config (# totp_gateway / # totp_master), so
  # `configure --jump-alias NAME` needs no extra environment variable.
  _ssh_otp_jump() {
    if [ -n "${SSH_TOTP_JUMP_ALIAS:-}" ]; then printf '%s\n' "$SSH_TOTP_JUMP_ALIAS"; return; fi
    _alias=$("$_ssh_otp_dir/sshotp" --default-jump 2>/dev/null) || _alias=
    printf '%s\n' "${_alias:-x}"
    unset _alias
  }

  # Manual master controls. Proxied connections auto-start the gateway when
  # needed; otp-up remains useful for prewarming or diagnostics.
  otp_up() {
    set -- "${*:-$(_ssh_otp_jump)}"
    for _h in "$@"; do
      # --up attaches the SOCKS listener to a running master (no second code)
      # and never inherits our stdio, so piping this stays safe.
      if "$_ssh_otp_dir/sshotp" --up "$_h"; then
        echo "otp: master up ($_h, SOCKS ${SSH_OTP_SOCKS:-127.0.0.1:7070})"
      else
        echo "otp: FAILED for $_h" >&2
      fi
    done
    unset _h
  }
  otp_status() { "$_ssh_otp_dir/sshotp" --status "${1:-$(_ssh_otp_jump)}"; }
  otp_down()   { "$_ssh_otp_dir/sshotp" --down   "${1:-$(_ssh_otp_jump)}"; }
  alias otp-up=otp_up
  alias otp-status=otp_status
  alias otp-down=otp_down
fi
