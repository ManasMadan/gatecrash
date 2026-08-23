#!/usr/bin/env bash
#
# build.sh — bake a flashable Raspberry Pi image with the box already on it.
#
# The reason this exists rather than "SSH in and run install.sh": an organizer running
# their third event does not want to configure a Pi again, and somebody handing a box
# to a venue wants the card to be the deliverable. Flash it, put a manifest on the
# boot partition, plug it in. No keyboard, no monitor, no SSH.
#
# It works by modifying an official Raspberry Pi OS Lite image rather than building a
# root filesystem from scratch. pi-gen and Buildroot both produce a more defensible
# artefact and both take an hour and a Debian host; this takes two minutes on a laptop
# and produces something an operator can flash with the Raspberry Pi Imager. The
# tradeoff is stated rather than hidden: the base image is trusted as shipped, and its
# checksum is verified before anything is written into it.
#
# Requires Linux, or a Linux VM. Loop devices and ext4 do not exist on macOS, and a
# script that pretended otherwise would fail halfway through with a mounted image and
# no cleanup.

set -euo pipefail

BASE_URL="https://downloads.raspberrypi.com/raspios_lite_arm64_latest"
WORK="${WORK:-$PWD/.image-work}"
OUT="${OUT:-$PWD/gatecrash.img}"
BINARY=""
MANIFEST=""
MODE="router"
SSID="GATECRASH"
HOSTNAME="gate"

usage() {
  cat <<'EOF'
Usage: sudo ./build.sh --binary PATH [options]

  --binary PATH      the linux/arm64 gatecrash binary (required)
  --manifest PATH    a manifest to bake in, so the box boots straight into an event
  --ap               configure AP mode in the image
  --ssid NAME        AP mode SSID                       (default GATECRASH)
  --hostname NAME    the box's hostname and mDNS name   (default gate)
  --out PATH         where to write the image           (default ./gatecrash.img)
  --base PATH        use this base image instead of downloading one

The manifest carries the event master key. An image with one baked in is a
credential: it can mint a rotating code for every ticket at that event. Treat the
card the way you would treat the key, and prefer copying the manifest onto the boot
partition after flashing.
EOF
}

BASE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    --ap) MODE="ap"; shift ;;
    --ssid) SSID="$2"; shift 2 ;;
    --hostname) HOSTNAME="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --base) BASE="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "build.sh: unknown option $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "build.sh: this needs Linux (loop devices, ext4). Run it in a VM or a container with --privileged." >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "build.sh: run this with sudo — it mounts a loop device" >&2
  exit 1
fi
if [[ -z "$BINARY" || ! -f "$BINARY" ]]; then
  echo "build.sh: --binary is required and must exist" >&2
  exit 1
fi
if ! file "$BINARY" | grep -q 'aarch64\|ARM aarch64'; then
  # Caught here rather than on the Pi, where the symptom is "cannot execute binary
  # file" on a machine with no screen attached.
  echo "build.sh: $BINARY is not an arm64 binary. Build it with scripts/build.sh." >&2
  exit 1
fi

mkdir -p "$WORK"

# Cleanup that runs whatever happens. A failure between mount and umount leaves a
# loop device attached and an image half-written, and the next run then fails for a
# completely unrelated-looking reason.
BOOT_MOUNT="$WORK/boot"
ROOT_MOUNT="$WORK/root"
LOOP=""
cleanup() {
  set +e
  [[ -n "$LOOP" ]] && {
    umount "$BOOT_MOUNT" 2>/dev/null
    umount "$ROOT_MOUNT" 2>/dev/null
    losetup -d "$LOOP" 2>/dev/null
  }
}
trap cleanup EXIT

if [[ -z "$BASE" ]]; then
  echo "==> fetching Raspberry Pi OS Lite (arm64)"
  BASE="$WORK/base.img.xz"
  [[ -f "$BASE" ]] || curl -fL --progress-bar -o "$BASE" "$BASE_URL"

  echo "==> verifying it"
  # The published checksum, fetched separately. Not a signature and not pretending to
  # be one: it catches a truncated download and a mirror serving something stale,
  # which are the realistic failures. A tampered mirror serving a matching checksum
  # is not covered, and that is worth knowing rather than glossing over.
  if curl -fsSL "${BASE_URL}.sha256" -o "$BASE.sha256" 2>/dev/null; then
    ( cd "$WORK" && sha256sum -c --status "$(basename "$BASE").sha256" ) \
      || { echo "build.sh: the base image does not match its published checksum" >&2; exit 1; }
  else
    echo "    (no checksum published at that URL; continuing unverified)"
  fi
fi

echo "==> unpacking"
rm -f "$OUT"
if [[ "$BASE" == *.xz ]]; then
  xz -dc "$BASE" >"$OUT"
else
  cp "$BASE" "$OUT"
fi

# Room for the binary, the web assets and a manifest. The stock image has a few
# hundred megabytes free, which is enough — but growing it by a little is cheap
# insurance against a future build being larger, and an image that runs out of space
# mid-copy fails in a way that is hard to attribute.
echo "==> growing the image by 256MB"
truncate -s +256M "$OUT"

LOOP="$(losetup --find --show --partscan "$OUT")"
echo "==> attached at $LOOP"

# Grow the root partition into the space just added. sfdisk rewrites the partition
# table in place; the filesystem itself is resized after.
echo ", +" | sfdisk --no-reread -N 2 "$LOOP" >/dev/null 2>&1 || true
partprobe "$LOOP" 2>/dev/null || true
e2fsck -fy "${LOOP}p2" >/dev/null 2>&1 || true
resize2fs "${LOOP}p2" >/dev/null

mkdir -p "$BOOT_MOUNT" "$ROOT_MOUNT"
mount "${LOOP}p1" "$BOOT_MOUNT"
mount "${LOOP}p2" "$ROOT_MOUNT"

echo "==> installing the box"

install -D -m 0755 "$BINARY" "$ROOT_MOUNT/usr/local/bin/gatecrash"
install -D -m 0644 "$(dirname "$0")/../systemd/gatecrash.service" \
  "$ROOT_MOUNT/etc/systemd/system/gatecrash.service"

# Enabled by symlink rather than by running systemctl, because there is no running
# systemd inside a mounted image to run it against.
install -d "$ROOT_MOUNT/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/gatecrash.service \
  "$ROOT_MOUNT/etc/systemd/system/multi-user.target.wants/gatecrash.service"

# The account, written straight into the files. useradd needs a running system.
grep -q '^gatecrash:' "$ROOT_MOUNT/etc/passwd" || \
  echo 'gatecrash:x:900:900:gatecrash:/nonexistent:/usr/sbin/nologin' >>"$ROOT_MOUNT/etc/passwd"
grep -q '^gatecrash:' "$ROOT_MOUNT/etc/group" || \
  echo 'gatecrash:x:900:' >>"$ROOT_MOUNT/etc/group"
grep -q '^gatecrash:' "$ROOT_MOUNT/etc/shadow" || \
  echo 'gatecrash:!:19000:0:99999:7:::' >>"$ROOT_MOUNT/etc/shadow"

install -d -m 0700 "$ROOT_MOUNT/var/lib/gatecrash"
chown 900:900 "$ROOT_MOUNT/var/lib/gatecrash"
install -d -m 0755 "$ROOT_MOUNT/etc/gatecrash"

echo "==> writing the configuration"

if [[ "$MODE" == "ap" ]]; then
  cat >"$ROOT_MOUNT/etc/gatecrash/config.json" <<EOF
{
  "mode": "ap",
  "data_dir": "/var/lib/gatecrash",
  "listen": ":8443",
  "listen_plain": ":8080",
  "hostname": "$HOSTNAME",
  "mdns": true,
  "beacon": true,
  "subnet": "10.11.0.0/24",
  "box_ip": "10.11.0.1",
  "ssid": "$SSID",
  "iface": "wlan0",
  "dns_port": 53,
  "synchronous": "FULL",
  "seal_every": "5m",
  "log_level": "info",
  "log_json": true
}
EOF
else
  cat >"$ROOT_MOUNT/etc/gatecrash/config.json" <<EOF
{
  "mode": "router",
  "data_dir": "/var/lib/gatecrash",
  "listen": ":8443",
  "listen_plain": ":8080",
  "hostname": "$HOSTNAME",
  "mdns": true,
  "beacon": true,
  "synchronous": "FULL",
  "seal_every": "5m",
  "log_level": "info",
  "log_json": true
}
EOF
fi

echo "$HOSTNAME" >"$ROOT_MOUNT/etc/hostname"
sed -i "s/raspberrypi/$HOSTNAME/g" "$ROOT_MOUNT/etc/hosts"

# Low ports without root.
cat >"$ROOT_MOUNT/etc/sysctl.d/60-gatecrash.conf" <<'EOF'
net.ipv4.ip_unprivileged_port_start=80
EOF

if [[ -n "$MANIFEST" ]]; then
  echo "==> baking in the manifest"
  install -m 0600 "$MANIFEST" "$ROOT_MOUNT/var/lib/gatecrash/manifest.json"
  chown 900:900 "$ROOT_MOUNT/var/lib/gatecrash/manifest.json"
fi

# A first-boot hook that copies a manifest off the boot partition.
#
# This is the path that makes the image reusable: the boot partition is the FAT one
# that any laptop can mount, so handing somebody a card and telling them to drop
# manifest.json onto it is a workflow that needs no Linux and no SSH.
install -D -m 0755 /dev/stdin "$ROOT_MOUNT/usr/local/sbin/gatecrash-firstboot" <<'EOF'
#!/bin/sh
# Copy a manifest from the boot partition, once, then get out of the way.
set -eu
for candidate in /boot/firmware/manifest.json /boot/manifest.json; do
  [ -f "$candidate" ] || continue
  install -o gatecrash -g gatecrash -m 0600 "$candidate" /var/lib/gatecrash/manifest.json
  # Removed after copying, so the event master key does not sit on a partition any
  # laptop can read.
  rm -f "$candidate"
  break
done
EOF

install -D -m 0644 /dev/stdin "$ROOT_MOUNT/etc/systemd/system/gatecrash-firstboot.service" <<'EOF'
[Unit]
Description=Copy a manifest from the boot partition
Before=gatecrash.service
ConditionPathExists=|/boot/firmware/manifest.json
ConditionPathExists=|/boot/manifest.json

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gatecrash-firstboot
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF
ln -sf /etc/systemd/system/gatecrash-firstboot.service \
  "$ROOT_MOUNT/etc/systemd/system/multi-user.target.wants/gatecrash-firstboot.service"

# SSH on, because a box with no screen and no SSH is a brick. The default password is
# not enabled: Raspberry Pi OS requires a user to be configured, and leaving one with
# a known password on an image is worse than requiring the Imager's user setup.
touch "$BOOT_MOUNT/ssh"

sync
umount "$BOOT_MOUNT" "$ROOT_MOUNT"
losetup -d "$LOOP"
LOOP=""

echo "==> compressing"
xz -T0 -f -k "$OUT"

cat <<EOF

  Wrote $OUT and $OUT.xz

  Flash it with the Raspberry Pi Imager, and set a username and password in its
  advanced options — this image deliberately ships without a default login.

  To run an event: drop manifest.json onto the boot partition of the flashed card,
  eject it, and power the box on. The manifest is moved into place on first boot and
  removed from the boot partition, so the event master key does not stay somewhere
  any laptop can read.

EOF
