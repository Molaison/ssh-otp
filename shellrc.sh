# ssh-otp shell integration -- source from ~/.zshrc (and/or ~/.bashrc):
#     [ -f ~/.ssh/ssh_otp/shellrc.sh ] && . ~/.ssh/ssh_otp/shellrc.sh
#
# Routes `ssh` (and scp/rsync/git that spawn ssh) through the OTP wrapper and
# defines the otp-* helpers. Safe to source on every machine: it only activates
# where ssh_otp is actually installed, so the synced .zshrc stays portable.
_ssh_otp_dir="$HOME/.ssh/ssh_otp"
if [ -f "$_ssh_otp_dir/ssh_totp.py" ]; then
  case ":$PATH:" in
    *":$_ssh_otp_dir/bin:"*) ;;
    *) PATH="$_ssh_otp_dir/bin:$PATH"; export PATH ;;
  esac

  # Open/refresh the multiplex master(s); later connections reuse them (~8h)
  # with no further OTP. Pass one or more hosts; defaults to the gateway X.
  otp-up() {
    set -- "${@:-X}"
    _socks="${SSH_OTP_SOCKS:-127.0.0.1:7070}"
    for _h in "$@"; do
      if ssh -MNf -D "$_socks" "$_h"; then echo "otp: master up ($_h, SOCKS $_socks)"; else echo "otp: FAILED for $_h" >&2; fi
    done
    unset _socks
    unset _h
  }
  otp-status() { ssh -O check "${1:-X}"; }
  otp-down()   { ssh -O exit  "${1:-X}"; }
fi
