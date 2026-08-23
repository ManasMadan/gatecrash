#!/usr/bin/env bash
#
# install.sh — turn a fresh Raspberry Pi OS Lite install into a gatecrash box.
#
# Run it on the Pi, over SSH, once. It is idempotent: running it again upgrades the
# binary and leaves the data, the keys and the certificate authority alone. That
# matters more than it sounds — the alternative is an upgrade that logs every
# enrolled scanner out on the morning of an event.
#
# What it does not do is touch the network configuration unless asked. A box in
# router mode joins the venue's Wi-Fi like any other device and this script has no
# business rewriting that; AP mode is opt-in with --ap, because turning a machine
# into an access point that intercepts DNS is not something to do by default.

set -euo pipefail

MODE="router"
SSID="GATECRASH"
COUNTRY="IN"
CHANNEL="6"
IFACE="wlan0"
BINARY=""
PREFIX="/usr/local/bin"
CONFIG_DIR="/etc/gatecrash"
DATA_DIR="/var/lib/gatecrash"

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [options]

  --ap                 configure the box as its own access point (hostapd + DHCP + DNS)
  --ssid NAME          the Wi-Fi name to advertise in AP mode  (default GATECRASH)
  --country CC         regulatory domain, required in AP mode  (default IN)
  --channel N          2.4GHz channel                          (default 6)
  --iface NAME         wireless interface                       (default wlan0)
  --binary PATH        install this binary instead of building from source
  --help               this

Examples:
  sudo ./install.sh --binary ./gatecrash-linux-arm64
  sudo ./install.sh --ap --ssid "SUNDOWN-GATES" --country IN --binary ./gatecrash
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ap) MODE="ap"; shift ;;
    --ssid) SSID="$2"; shift 2 ;;
    --country) COUNTRY="$2"; shift 2 ;;
    --channel) CHANNEL="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "install.sh: unknown option $1" >&2; usage; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "install.sh: run this with sudo" >&2
  exit 1
fi

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say "checking the machine"

# A 64-bit kernel is required, not preferred: the binary is built for linux/arm64 and
# Raspberry Pi OS still ships a 32-bit userland by default on some images. Finding
# this out here beats finding it out from "cannot execute binary file".
arch="$(uname -m)"
case "$arch" in
  aarch64|arm64) ;;
  *) echo "install.sh: this box is $arch; gatecrash ships linux/arm64. Use the 64-bit Raspberry Pi OS." >&2; exit 1 ;;
esac

# The data directory lives on the SD card, and cheap SD cards are the single most
# common cause of a lost event. Warn rather than refuse: an SSD over USB is better and
# a card is what most people will have.
root_device="$(findmnt -no SOURCE / || true)"
if [[ "$root_device" == /dev/mmcblk* ]]; then
  cat <<'EOF'

  This box boots from an SD card.

  SD cards lie about having completed a write, which is why the box runs SQLite with
  synchronous=FULL and ships its WAL to a second device. It works. But a card that
  has been in a Pi for two years will eventually fail during a show, and the failure
  looks like a gate that has stopped answering.

  If you have a USB SSD, use it. If you do not, take a spare card with the same
  image on it and keep a copy of the manifest on a phone.

EOF
fi

say "creating the service account"

# A system account with no shell and no home. The box never needs to log in, and an
# account that can is an account somebody can get a shell on.
if ! id -u gatecrash >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin gatecrash
fi

install -d -o gatecrash -g gatecrash -m 0700 "$DATA_DIR"
install -d -o root -g root -m 0755 "$CONFIG_DIR"

say "installing the binary"

if [[ -n "$BINARY" ]]; then
  install -o root -g root -m 0755 "$BINARY" "$PREFIX/gatecrash"
elif command -v go >/dev/null 2>&1; then
  # Built on the box. Slow on a Pi and perfectly workable, and it means an operator
  # with a source checkout and no cross-compiler is not stuck.
  ( cd "$here/.." && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$PREFIX/gatecrash" ./cmd/gatecrash )
  chown root:root "$PREFIX/gatecrash"
  chmod 0755 "$PREFIX/gatecrash"
else
  echo "install.sh: no --binary given and no Go toolchain here. Cross-compile with scripts/build.sh and pass --binary." >&2
  exit 1
fi

"$PREFIX/gatecrash" version

say "writing the configuration"

# Written once and then left alone. An install that rewrites the config on every run
# is an install that silently reverts whatever the operator changed at the venue.
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
  if [[ "$MODE" == "ap" ]]; then
    cat >"$CONFIG_DIR/config.json" <<EOF
{
  "mode": "ap",
  "data_dir": "$DATA_DIR",
  "listen": ":8443",
  "listen_plain": ":8080",
  "hostname": "gate",
  "mdns": true,
  "beacon": true,
  "subnet": "10.11.0.0/24",
  "box_ip": "10.11.0.1",
  "ssid": "$SSID",
  "iface": "$IFACE",
  "dns_port": 53,
  "synchronous": "FULL",
  "seal_every": "5m",
  "log_level": "info",
  "log_json": true
}
EOF
  else
    cat >"$CONFIG_DIR/config.json" <<EOF
{
  "mode": "router",
  "data_dir": "$DATA_DIR",
  "listen": ":8443",
  "listen_plain": ":8080",
  "hostname": "gate",
  "mdns": true,
  "beacon": true,
  "synchronous": "FULL",
  "seal_every": "5m",
  "log_level": "info",
  "log_json": true
}
EOF
  fi
  chmod 0644 "$CONFIG_DIR/config.json"
else
  echo "  $CONFIG_DIR/config.json exists; leaving it alone"
fi

# The secrets file the unit reads. Empty by default, and 0600 root — the admin token
# is minted by the box on first boot and kept in the data directory, so this only
# exists for a manifest passphrase or a pinned token.
if [[ ! -f "$CONFIG_DIR/secrets.env" ]]; then
  cat >"$CONFIG_DIR/secrets.env" <<'EOF'
# Read by the systemd unit. 0600, root-owned, never in a repository.
#
# GATECRASH_MANIFEST_PASSPHRASE=...
# GATECRASH_ADMIN_TOKEN=...        (omit to let the box mint and persist one)
EOF
  chmod 0600 "$CONFIG_DIR/secrets.env"
fi

say "installing the service"

install -o root -g root -m 0644 "$here/systemd/gatecrash.service" /etc/systemd/system/gatecrash.service

# Ports 80 and 443 without root. The unit grants CAP_NET_BIND_SERVICE, and this makes
# the low ports reachable at all — on a Pi the default is that unprivileged processes
# cannot bind below 1024 even with the capability unless the sysctl allows it.
cat >/etc/sysctl.d/60-gatecrash.conf <<'EOF'
# The box binds 80 and 443 as an unprivileged user.
net.ipv4.ip_unprivileged_port_start=80
EOF
sysctl --system >/dev/null

if [[ "$MODE" == "ap" ]]; then
  say "configuring the access point"

  apt-get update -qq
  apt-get install -y -qq hostapd

  sed -e "s|@IFACE@|$IFACE|g" \
      -e "s|@SSID@|$SSID|g" \
      -e "s|@COUNTRY@|$COUNTRY|g" \
      -e "s|@CHANNEL@|$CHANNEL|g" \
      "$here/ap/hostapd.conf" >/etc/hostapd/hostapd.conf
  chmod 0644 /etc/hostapd/hostapd.conf

  if [[ ! -f /etc/hostapd/wpa_psk ]]; then
    # A generated passphrase rather than a default one. A default Wi-Fi password on a
    # published image is the same as no password, and this one is printed once here
    # and then only readable by root.
    passphrase="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 16)"
    printf '00:00:00:00:00:00 %s\n' "$passphrase" >/etc/hostapd/wpa_psk
    chmod 0600 /etc/hostapd/wpa_psk
    printf '\n  Wi-Fi: %s\n  key:   %s\n\n  Write this down. It is only readable by root from now on.\n\n' "$SSID" "$passphrase"
  fi

  # The box runs its own DHCP and DNS, so anything else that wants those ports has to
  # go. dhcpcd is what fights it on Raspberry Pi OS.
  systemctl disable --now dnsmasq 2>/dev/null || true
  systemctl mask systemd-resolved 2>/dev/null || true

  # A static address on the wireless interface, because the box is the router.
  cat >/etc/systemd/network/10-gatecrash-ap.network <<EOF
[Match]
Name=$IFACE

[Network]
Address=10.11.0.1/24
DHCPServer=no
IPv6AcceptRA=no
EOF

  systemctl unmask hostapd
  systemctl enable hostapd
  cat <<'EOF'

  The access point is configured but not started, and that is deliberate: bringing
  up hostapd drops the SSH session you are almost certainly using right now.

  Start it when you are ready, from the console or over Ethernet:

    sudo systemctl start hostapd
    sudo systemctl start gatecrash

EOF
fi

say "enabling the box"

systemctl daemon-reload
systemctl enable gatecrash

cat <<EOF

  Installed.

  Next, put a manifest where the box can read it:

    sudo install -o gatecrash -g gatecrash -m 0600 manifest.json $DATA_DIR/manifest.json
    sudo systemctl start gatecrash
    sudo journalctl -u gatecrash -f

  The boot log prints the dashboard URL with its token, the certificate fingerprint
  to pin, and the addresses the scanners should use.

  The token survives a reboot. It lives in $DATA_DIR/admin-token, 0600 — so a power
  cut mid-event does not sign the control room out.

EOF
