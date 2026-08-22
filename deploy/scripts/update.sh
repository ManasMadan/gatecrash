#!/usr/bin/env bash
#
# update.sh — swap the binary with a way back.
#
# The problem this solves is not upgrading. It is upgrading at 17:00 on the day of an
# event, discovering the new build has a bug, and having no way to return to the one
# that worked — with four thousand people arriving at 19:00.
#
# So: two slots, an atomic symlink swap, and a health check that reverts on its own.
# An A/B update rather than a package upgrade, because a package upgrade that fails
# halfway leaves a box that is neither version.

set -euo pipefail

PREFIX="/usr/local/lib/gatecrash"
LINK="/usr/local/bin/gatecrash"
HEALTH_URL="http://127.0.0.1:8080/healthz"
SETTLE=20

usage() {
  cat <<'EOF'
Usage: sudo ./update.sh <new-binary>
       sudo ./update.sh --rollback

  Installs the binary into the inactive slot, points the symlink at it, restarts the
  box, and checks it answers. If it does not, the previous slot is restored before
  this script returns.

  --rollback   go back to the other slot immediately, no questions
EOF
}

if [[ $EUID -ne 0 ]]; then
  echo "update.sh: run this with sudo" >&2
  exit 1
fi

install -d -m 0755 "$PREFIX"

current_slot() {
  # Which slot the symlink points at. Missing means a fresh install, which counts as
  # slot b so the first update lands in a.
  local target
  target="$(readlink -f "$LINK" 2>/dev/null || true)"
  case "$target" in
    "$PREFIX/a/gatecrash") echo a ;;
    "$PREFIX/b/gatecrash") echo b ;;
    *) echo b ;;
  esac
}

other() { [[ "$1" == a ]] && echo b || echo a; }

point_at() {
  local slot="$1"
  # Symlink swapped by rename, which is atomic. `ln -sf` on an existing path unlinks
  # first, and a box that restarts in that window has no binary at all.
  ln -sfn "$PREFIX/$slot/gatecrash" "$LINK.new"
  mv -T "$LINK.new" "$LINK"
}

healthy() {
  local deadline=$((SECONDS + SETTLE))
  while (( SECONDS < deadline )); do
    if curl -fsS --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
      # Answering is necessary and not sufficient: systemd's own view matters too,
      # because a box that is restarting in a loop will answer between restarts.
      if systemctl is-active --quiet gatecrash; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

if [[ "${1:-}" == "--rollback" ]]; then
  target="$(other "$(current_slot)")"
  if [[ ! -x "$PREFIX/$target/gatecrash" ]]; then
    echo "update.sh: slot $target is empty, so there is nothing to roll back to" >&2
    exit 1
  fi
  echo "rolling back to slot $target"
  point_at "$target"
  systemctl restart gatecrash
  healthy && echo "slot $target is answering" || { echo "update.sh: the rollback is not answering either" >&2; exit 1; }
  exit 0
fi

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

new="$1"
if [[ ! -f "$new" ]]; then
  echo "update.sh: $new does not exist" >&2
  exit 1
fi

active="$(current_slot)"
target="$(other "$active")"

echo "active slot is $active; installing into $target"

install -d -m 0755 "$PREFIX/$target"
install -m 0755 "$new" "$PREFIX/$target/gatecrash.incoming"

# Check it runs at all before it becomes the thing the gates depend on. A binary
# built for the wrong architecture, or truncated by a bad copy, fails here rather
# than after the symlink has moved.
if ! "$PREFIX/$target/gatecrash.incoming" version >/dev/null; then
  rm -f "$PREFIX/$target/gatecrash.incoming"
  echo "update.sh: the new binary will not run on this machine; nothing was changed" >&2
  exit 1
fi

mv -T "$PREFIX/$target/gatecrash.incoming" "$PREFIX/$target/gatecrash"

echo "pointing at $target and restarting"
point_at "$target"

if ! systemctl restart gatecrash; then
  echo "update.sh: restart failed; reverting to $active" >&2
  point_at "$active"
  systemctl restart gatecrash || true
  exit 1
fi

if healthy; then
  echo
  echo "  slot $target is live and answering."
  echo "  slot $active is still on disk. Go back with: sudo ./update.sh --rollback"
  echo
  exit 0
fi

echo "update.sh: the new binary is not answering after ${SETTLE}s; reverting to $active" >&2
point_at "$active"
systemctl restart gatecrash

if healthy; then
  echo "update.sh: reverted to $active, which is answering. The gates kept working." >&2
else
  # Both slots are down. Say so plainly rather than exiting quietly, because at this
  # point somebody has to go and look at the box.
  echo "update.sh: BOTH SLOTS ARE DOWN. Check: journalctl -u gatecrash -n 50" >&2
fi
exit 1
