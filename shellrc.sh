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

  # Manual master controls. Proxied connections auto-start x when needed;
  # otp-up remains useful for prewarming or diagnostics.
  otp_up() {
    set -- "${@:-x}"
    _socks="${SSH_OTP_SOCKS:-127.0.0.1:7070}"
    for _h in "$@"; do
      if ssh -MNf -D "$_socks" "$_h"; then echo "otp: master up ($_h, SOCKS $_socks)"; else echo "otp: FAILED for $_h" >&2; fi
    done
    unset _socks
    unset _h
  }
  otp_status() { ssh -O check "${1:-x}"; }
  otp_down()   { ssh -O exit  "${1:-x}"; }
  alias otp-up=otp_up
  alias otp-status=otp_status
  alias otp-down=otp_down
fi
