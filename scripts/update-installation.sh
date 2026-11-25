#!/bin/bash
# Update an installed AGOC login-autostart installation in place (Linux and
# macOS), as the desktop user: build, stop the tray and the privileged
# monitor, remove AGOC's firewall rules, replace the root-owned binaries,
# and start the tray again. The autostart entry and sudoers permission stay.
set -euo pipefail
umask 077

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) != 0 ]] || fail "Run as your desktop user, without sudo."
[[ $# == 0 ]] || fail "Usage: bash scripts/update-installation.sh"

uid=$(id -u)
home=$(cd -- "$HOME" && pwd -P)
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
repo_dir=$(cd -- "$script_dir/.." && pwd -P)
binary_dir="$repo_dir/target/release"
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

cargo_bin="${CARGO_HOME:-$HOME/.cargo}/bin"
[[ ! -x "$cargo_bin/cargo" ]] || PATH="$cargo_bin:$PATH"
command -v cargo >/dev/null || fail "Cargo is not installed or is missing from PATH. Install Rust stable and retry."

printf 'Building AGOC release binaries...\n'
cargo build --locked --release --features tray
for binary in agoc agoc-tray; do
    [[ -f "$binary_dir/$binary" && -x "$binary_dir/$binary" ]] ||
        fail "Build did not produce $binary_dir/$binary"
done
"$binary_dir/agoc-tray" --help | grep -q -- --installed-helper ||
    fail "The tray binary does not support installed-helper mode."

export PATH=/usr/bin:/bin:/usr/sbin:/sbin
command -v sudo >/dev/null || fail "sudo is required."
sudo -v

# PIDs of processes whose executable is exactly $1. On macOS, ps "comm" is
# the executable path; on Linux, resolve /proc/<pid>/exe. Root-owned monitor
# and guardian processes are listed as well.
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

# Terminate the tray, then wait up to 30 seconds until it has exited.
stop_tray() {
    process_pids "$destination/agoc-tray" | while read -r pid; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    local _
    for _ in {1..150}; do
        if [[ -z $(process_pids "$destination/agoc-tray") ]]; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# The privileged monitor and its guardian exit on their own once the tray's
# control socket closes; an in-flight network probe may delay them. The
# uninstall inside the root step below needs their AGOC lock to be free.
wait_for_monitor() {
    local _
    for _ in {1..450}; do
        if [[ -z $(process_pids "$destination/agoc") ]]; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

printf 'Stopping the installed AGOC tray...\n'
stop_tray ||
    fail "AGOC did not stop cleanly. No binaries were replaced; check the tray and retry."
printf 'Waiting for the AGOC monitor and its guardian to exit...\n'
wait_for_monitor ||
    fail "The AGOC monitor did not stop cleanly. No binaries were replaced; check the tray and retry."

printf 'Updating root-owned binaries in %s...\n' "$destination"
sudo /bin/bash -s -- "$uid" "$binary_dir" "$destination" <<'ROOT'
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077

uid=$1
source_dir=$2
destination=$3
case "$destination" in
    /opt/agoc|/Library/PrivilegedHelperTools/dev.agoc) ;;
    *) echo "Unexpected installation path: $destination" >&2; exit 1 ;;
esac
[[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 ]] || {
    echo "Invalid desktop UID." >&2; exit 1;
}
[[ -d "$destination" && ! -L "$destination" &&
   -f "$destination/.managed" && ! -L "$destination/.managed" ]] || {
    echo "Not a managed installation: $destination" >&2; exit 1;
}
expected=$(printf 'agoc-login-v1\n%s' "$uid")
[[ $(cat "$destination/.managed") == "$expected" ]] || {
    echo "This installation belongs to another account or is not managed." >&2; exit 1;
}
if [[ $(uname -s) == Darwin ]]; then
    owner=$(stat -f %u "$destination")
    root_group=wheel
else
    owner=$(stat -c %u "$destination")
    root_group=root
fi
[[ "$owner" == 0 ]] || {
    echo "Installation directory must be root-owned." >&2; exit 1;
}
for binary in agoc agoc-tray; do
    [[ -f "$destination/$binary" && ! -L "$destination/$binary" &&
       -f "$source_dir/$binary" && ! -L "$source_dir/$binary" ]] || {
        echo "Missing or unsafe binary: $binary" >&2; exit 1;
    }
done

"$destination/agoc" uninstall --if-present
staging=$(mktemp -d "$destination/.update.XXXXXX")
replacing=false
complete=false
cleanup() {
    status=$?
    trap - EXIT
    if [[ "$replacing" == true && "$complete" != true ]]; then
        mv -f -- "$staging/agoc.old" "$destination/agoc" ||
            echo "ERROR: failed to restore the previous agoc binary" >&2
        mv -f -- "$staging/agoc-tray.old" "$destination/agoc-tray" ||
            echo "ERROR: failed to restore the previous agoc-tray binary" >&2
    fi
    rm -rf -- "$staging"
    exit "$status"
}
trap cleanup EXIT

install -o root -g "$root_group" -m 0755 "$source_dir/agoc" "$staging/agoc.new"
install -o root -g "$root_group" -m 0755 "$source_dir/agoc-tray" "$staging/agoc-tray.new"
install -o root -g "$root_group" -m 0755 "$destination/agoc" "$staging/agoc.old"
install -o root -g "$root_group" -m 0755 "$destination/agoc-tray" "$staging/agoc-tray.old"
replacing=true
mv -f -- "$staging/agoc.new" "$destination/agoc"
mv -f -- "$staging/agoc-tray.new" "$destination/agoc-tray"
complete=true
ROOT

if [[ $(uname -s) == Darwin ]]; then
    log_dir="$home/Library/Logs/agoc"
else
    log_dir="$home/.local/state/agoc"
fi
mkdir -p -- "$log_dir"
chmod 0700 "$log_dir"
log_file="$log_dir/update.log"

restarted=false
if [[ $(uname -s) == Darwin ]]; then
    if /bin/launchctl print "gui/$uid/dev.agoc.tray" >/dev/null 2>&1; then
        printf 'Starting the AGOC tray through its login LaunchAgent...\n'
        if /bin/launchctl kickstart "gui/$uid/dev.agoc.tray"; then
            restarted=true
        fi
    elif [[ -f "$autostart" && ! -L "$autostart" ]]; then
        printf 'Loading the AGOC login LaunchAgent...\n'
        if /bin/launchctl bootstrap "gui/$uid" "$autostart"; then
            restarted=true
        fi
    fi
    if [[ "$restarted" == true ]]; then
        # launchd throttles rapid restarts; allow up to 20 seconds to appear.
        for _ in {1..100}; do
            if [[ -n $(process_pids "$destination/agoc-tray") ]]; then
                break
            fi
            sleep 0.2
        done
        sleep 1
        if [[ -z $(process_pids "$destination/agoc-tray") ]]; then
            restarted=false
        fi
    fi
fi
if [[ "$restarted" != true ]]; then
    nohup "$destination/agoc-tray" --installed-helper >>"$log_file" 2>&1 </dev/null &
    tray_pid=$!
    sleep 1
    if ! kill -0 "$tray_pid" 2>/dev/null; then
        wait "$tray_pid" || true
        fail "Updated binaries were installed, but the tray did not stay running. See $log_file"
    fi
    printf 'AGOC updated and started. Startup output: %s\n' "$log_file"
else
    printf 'AGOC updated and started through the login LaunchAgent.\n'
fi
