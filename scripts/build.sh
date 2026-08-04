#!/usr/bin/env bash
# Cross-compile the box binary. Called by `pnpm go:build`.
#
# Everything about this script exists to keep one promise from the README: the
# artifact is a single static file you scp onto a Raspberry Pi. CGO_ENABLED=0 is
# not an optimisation, it is the requirement — SQLite is linked in as pure Go
# (modernc.org/sqlite) precisely so that this stays true and so that a Pi
# without a toolchain, and a CI runner without a cross-compiler, both produce
# byte-identical binaries.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${GATECRASH_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${GATECRASH_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
# Reproducible by default: the commit's own timestamp, not "now".
DATE="${GATECRASH_DATE:-$(git log -1 --format=%cI 2>/dev/null || echo unknown)}"

LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X github.com/ManasMadan/gatecrash/internal/version.Version=$VERSION"
LDFLAGS="$LDFLAGS -X github.com/ManasMadan/gatecrash/internal/version.Commit=$COMMIT"
LDFLAGS="$LDFLAGS -X github.com/ManasMadan/gatecrash/internal/version.Date=$DATE"

# The Pi is the only target that matters for the box; the rest are for
# developers and for the load rig.
TARGETS="${GATECRASH_TARGETS:-linux/arm64 linux/amd64 linux/arm darwin/arm64 darwin/amd64}"

mkdir -p bin

for target in $TARGETS; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  out="bin/gatecrash-$goos-$goarch"

  echo "==> $out"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM=7 \
    go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/gatecrash

  size=$(wc -c <"$out" | tr -d ' ')
  printf '    %s bytes (%.1f MiB)\n' "$size" "$(echo "$size" | awk '{print $1/1048576}')"
done

# The side binaries are developer tools; they only ever run on a laptop or a CI
# runner, so they are built for the host and nothing else.
for tool in gatecrash-sim gatecrash-keys gatecrash-presale gatecrash-load; do
  echo "==> bin/$tool"
  CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "bin/$tool" "./cmd/$tool"
done

echo
echo "Built $(ls bin | wc -l | tr -d ' ') artifacts into bin/"
