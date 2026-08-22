#!/usr/bin/env bash
#
# harden.sh — make the root filesystem read-only.
#
# The threat is not an attacker. It is an SD card.
#
# Cheap cards acknowledge writes they have not committed, and a power cut in that
# window corrupts whatever was in flight. If the only thing in flight is the box's own
# database, SQLite's write-ahead log recovers it — that is what synchronous=FULL and
# the WAL are for. If the operating system was also mid-write, the card comes back
# with a corrupt filesystem and the box does not boot at all, at which point no amount
# of database durability helps anybody.
#
# So: nothing writes to the root filesystem. Logs go to a tmpfs in RAM, the few
# directories that insist on being writable are bind-mounted to RAM, and the data
# directory is the only thing on real storage that is ever written. A power cut then
# has exactly one thing it can damage, and that one thing is designed to survive it.
#
# This is reversible. `sudo ./harden.sh --off` puts it back.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "harden.sh: run this with sudo" >&2
  exit 1
fi

DATA_DIR="/var/lib/gatecrash"
MARKER="/etc/gatecrash/hardened"

if [[ "${1:-}" == "--off" ]]; then
  echo "making the root filesystem writable again"
  sed -i 's|^\(\S\+\s\+/\s\+\S\+\s\+\)ro,|\1defaults,|' /etc/fstab
  rm -f /etc/systemd/system/gatecrash-tmpfs.mount "$MARKER"
  systemctl daemon-reload
  echo "reboot to apply"
  exit 0
fi

echo
echo "  This makes / read-only. After the reboot, apt and any edit under /etc will"
echo "  fail until you run: sudo ./harden.sh --off"
echo
read -r -p "  Continue? [y/N] " answer
[[ "$answer" == "y" || "$answer" == "Y" ]] || { echo "  nothing changed"; exit 0; }

echo "moving the writable directories into RAM"

# Logs, spool and temporary files. All of them are things the box does not need to
# survive a reboot, and all of them are things that write constantly — which is what
# wears a card out and what is in flight when the power goes.
#
# The journal is told to stay in RAM explicitly. Without this, systemd notices
# /var/log is a tmpfs and cheerfully keeps writing there, which works and loses the
# log on every reboot without saying so.
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/gatecrash.conf <<'EOF'
# In RAM, capped, and rate-limited.
#
# A box under a DNS flood can generate log lines faster than anything can consume
# them, and an unbounded journal in a tmpfs is a way to fill RAM until the kernel
# starts killing processes — beginning, on a Pi, with the largest one.
[Journal]
Storage=volatile
RuntimeMaxUse=32M
RateLimitIntervalSec=30s
RateLimitBurst=2000
ForwardToSyslog=no
EOF

# fstab entries for the paths that must be writable and must not be on the card.
#
# Appended once and guarded by a marker, because running this twice would otherwise
# stack duplicate mounts and the second boot would fail in a way that is genuinely
# hard to read from a serial console.
if [[ ! -f "$MARKER" ]]; then
  cat >>/etc/fstab <<'EOF'

# gatecrash: writable paths in RAM, so a power cut can only damage the data directory
tmpfs /tmp     tmpfs nosuid,nodev,size=64M  0 0
tmpfs /var/tmp tmpfs nosuid,nodev,size=32M  0 0
tmpfs /var/log tmpfs nosuid,nodev,size=32M  0 0
EOF
fi

echo "keeping the data directory writable"

# The one exception. The data directory holds the database, the WAL, the CA, the
# enrollment secret and the admin token, and all of it has to survive a reboot.
#
# A bind mount with its own options rather than a separate partition: a separate
# partition is better and requires repartitioning a card somebody is holding at a
# venue, which is not a thing to ask of an operator an hour before doors.
cat >/etc/systemd/system/gatecrash-tmpfs.mount <<EOF
[Unit]
Description=Gatecrash data directory, writable on a read-only root
Before=gatecrash.service

[Mount]
What=$DATA_DIR
Where=$DATA_DIR
Type=none
Options=bind,rw,nosuid,nodev

[Install]
WantedBy=multi-user.target
EOF

echo "making / read-only"

# The root entry in fstab, rewritten to mount ro. Matched on the mount point rather
# than the device, because the device is a PARTUUID on Raspberry Pi OS and hard-coding
# one would break on any other card.
if ! grep -qE '^\S+\s+/\s+\S+\s+ro,' /etc/fstab; then
  sed -i -E 's|^(\S+\s+/\s+\S+\s+)(defaults|rw)([,[:space:]])|\1ro\3|' /etc/fstab
fi

# The kernel command line too. fstab alone remounts ro after the initramfs has already
# mounted rw, which leaves a window early in boot where a power cut still corrupts.
if [[ -f /boot/firmware/cmdline.txt ]] && ! grep -q ' ro ' /boot/firmware/cmdline.txt; then
  sed -i 's|rootwait|rootwait ro|' /boot/firmware/cmdline.txt
fi

touch "$MARKER"
systemctl daemon-reload
systemctl enable gatecrash-tmpfs.mount >/dev/null 2>&1 || true

cat <<'EOF'

  Done. Reboot to apply.

  After the reboot the only writable storage on the box is /var/lib/gatecrash. A
  power cut can damage the database and nothing else, and the database is built to
  survive one — the simulator pulls the plug hundreds of times a run and asserts
  that no acknowledged scan is ever lost.

  To change anything under /etc afterwards:

    sudo mount -o remount,rw /
    ...
    sudo mount -o remount,ro /

  Or turn this off entirely with: sudo ./harden.sh --off

EOF
