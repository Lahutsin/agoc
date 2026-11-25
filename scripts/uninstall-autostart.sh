#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) != 0 ]] || fail "Run as the desktop user who installed AGOC, without sudo."
[[ $# == 0 ]] || fail "Usage: bash scripts/uninstall-autostart.sh"
uid=$(id -u)
home=$(cd -- "$HOME" && pwd -P)
case $(uname -s) in
    Linux)
        destination=/opt/agoc
        autostart="$home/.config/autostart/agoc.desktop"
        ;;
    Darwin)
        destination=/Library/PrivilegedHelperTools/dev.agoc
        autostart="$home/Library/LaunchAgents/dev.agoc.tray.plist"
        ;;
    *) fail "Only Linux and macOS are supported." ;;
esac

# PIDs of processes whose executable is exactly $1 (macOS: ps "comm" is the
# executable path; Linux: /proc/<pid>/exe).
process_pids() {
    local executable="$1" process link
    if [[ $(uname -s) == Darwin ]]; then
        /bin/ps -axo pid=,comm= | awk -v executable="$executable" \
            '$2 == executable { print $1 }' || true
        return 0
    fi
    for process in /proc/[0-9]*; do
        [[ -e "$process/exe" ]] || continue
        link=$(readlink -- "$process/exe" 2>/dev/null) || continue
        [[ "$link" == "$executable" ]] || continue
        printf '%s\n' "${process##*/}"
    done
    return 0
}

# Terminate the tray, then wait until no tray, monitor or guardian process
# from the installation directory remains: the monitor and its guardian exit
# on their own once the tray's control socket closes, which frees the AGOC
# lock for rule removal below.
stop_agoc() {
    local _
    process_pids "$destination/agoc-tray" | while read -r pid; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    for _ in {1..450}; do
        if [[ -z $(process_pids "$destination/agoc-tray") && -z $(process_pids "$destination/agoc") ]]; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

if [[ $(uname -s) == Darwin ]]; then
    # Stop the login LaunchAgent and any tray started from the installation
    # directory, so the monitor and its guardian exit before removal.
    # Quitting the tray first is also fine.
    printf 'Stopping the AGOC tray...\n'
    if /bin/launchctl print "gui/$uid/dev.agoc.tray" >/dev/null 2>&1; then
        /bin/launchctl bootout "gui/$uid/dev.agoc.tray" || true
    fi
    stop_agoc || fail "AGOC did not stop cleanly. Quit the tray and retry."
else
    printf 'Choose Quit (remove protection) in the AGOC tray before uninstalling.\n'
fi
sudo /bin/bash -s -- "$destination" "$uid" <<'ROOT'
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
destination=$1
uid=$2
case "$destination" in
    /opt/agoc|/Library/PrivilegedHelperTools/dev.agoc) ;;
    *) exit 1 ;;
esac
[[ -d "$destination" && ! -L "$destination" && -f "$destination/.managed" &&
   ! -L "$destination/.managed" ]] || {
    echo "Not a managed AGOC installation; refusing deletion." >&2; exit 1;
}
expected=$(printf 'agoc-login-v1\n%s' "$uid")
[[ $(cat "$destination/.managed") == "$expected" ]] || {
    echo "This installation belongs to another desktop account." >&2; exit 1;
}
policy=/etc/sudoers.d/agoc-desktop
[[ -f "$policy" && ! -L "$policy" ]] &&
    grep -qxF "# Managed by AGOC login installer; desktop UID $uid" "$policy" || {
        echo "Sudoers policy is not managed by this installation; refusing removal." >&2; exit 1;
    }
# The lock prevents removal while a guardian is running; no host rules are flushed.
if ! "$destination/agoc" uninstall --if-present; then
    echo "Could not remove AGOC rules. Quit the running monitor first." >&2
    exit 1
fi
rm -- "$policy"
visudo -c
rm -- "$destination/agoc" "$destination/agoc-tray" "$destination/.managed"
rmdir -- "$destination"
ROOT
if [[ -e "$autostart" || -L "$autostart" ]]; then
    rm -- "$autostart"
fi
printf 'AGOC login autostart and passwordless permission removed.\n'
