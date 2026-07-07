#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <host> <port>" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
askpass="$script_dir/totp_askpass.py"
config_file="${SSH_TOTP_CONFIG:-$HOME/.ssh/config}"
jump_alias="${SSH_TOTP_JUMP_ALIAS:-X}"
real_ssh="${SSH_TOTP_REAL_SSH:-}"

if [ -z "$real_ssh" ]; then
    for candidate in /usr/bin/ssh /opt/homebrew/bin/ssh /usr/local/bin/ssh; do
        if [ -x "$candidate" ]; then
            real_ssh="$candidate"
            break
        fi
    done
fi

if [ -z "$real_ssh" ]; then
    real_ssh=$(command -v ssh)
fi

secret_and_prompt=$(
    SCRIPT_DIR="$script_dir" CONFIG_FILE="$config_file" JUMP_ALIAS="$jump_alias" python3 - <<'PY'
import importlib.util
import os
import sys

script_dir = os.environ["SCRIPT_DIR"]
config_file = os.environ["CONFIG_FILE"]
jump_alias = os.environ["JUMP_ALIAS"]
module_path = os.path.join(script_dir, "ssh_totp.py")

spec = importlib.util.spec_from_file_location("ssh_totp", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

totp = module.resolve_totp_for_args([jump_alias], config_file)
if not totp:
    sys.exit(1)
print(totp["secret"])
print(totp.get("prompt", ""))
PY
)

SSH_TOTP_SECRET=$(printf '%s\n' "$secret_and_prompt" | sed -n '1p')
SSH_TOTP_PROMPT_PATTERN=$(printf '%s\n' "$secret_and_prompt" | sed -n '2p')
export SSH_ASKPASS="$askpass"
export SSH_ASKPASS_REQUIRE=force
export SSH_TOTP_SECRET
export SSH_TOTP_REAL_SSH="$real_ssh"
export DISPLAY="${DISPLAY:-:0}"
if [ -n "$SSH_TOTP_PROMPT_PATTERN" ]; then
    export SSH_TOTP_PROMPT_PATTERN
fi

period=30
now=$(date +%s)
remaining=$((period - (now % period)))
if [ "$remaining" -lt 4 ]; then
    sleep $((remaining + 1))
fi

exec "$real_ssh" \
    -o ControlMaster=no \
    -o ControlPath=none \
    -o NumberOfPasswordPrompts=3 \
    -W "$1:$2" \
    "$jump_alias"
