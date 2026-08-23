#!/usr/bin/env bash
#
# verify.sh — compile the Kotlin protocol port and check it against the Go reference.
#
# This needs `kotlinc` and a JVM. It does **not** need the Android SDK, Gradle, a device
# or an emulator, and that is the point: the protocol layer is deliberately free of
# Android imports, so the part that has to agree byte for byte with the box can be
# verified on any machine and in CI.
#
# What it does not cover is the radio. `mesh/Ble.kt` needs a device, and no amount of
# unit testing substitutes for two phones in a room.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v kotlinc >/dev/null 2>&1; then
  echo "verify.sh: kotlinc is not installed." >&2
  echo "  macOS:  brew install kotlin" >&2
  echo "  linux:  sdk install kotlin  (https://sdkman.io)" >&2
  exit 1
fi

OUT=".build/conformance.jar"
mkdir -p .build

echo "==> compiling the protocol port"
# Only the pure-Kotlin protocol files. Anything importing android.* is excluded, because
# this runs on a JVM with no Android on the classpath.
kotlinc \
  app/src/main/java/dev/manasmadan/backstage/mesh/Frame.kt \
  app/src/main/java/dev/manasmadan/backstage/mesh/Router.kt \
  app/src/test/java/dev/manasmadan/backstage/mesh/ConformanceTest.kt \
  -include-runtime -d "$OUT" \
  -Werror

echo "==> running it against the Go fixtures"
java -jar "$OUT"
