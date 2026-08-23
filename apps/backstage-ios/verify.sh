#!/usr/bin/env bash
#
# verify.sh — build the Swift protocol port and check it against the Go reference.
#
# Needs a Swift toolchain. It does **not** need Xcode, a simulator or a device, which is
# the point: the protocol layer imports nothing from CoreBluetooth or UIKit, so the part
# that has to agree byte for byte with the box can be verified on any Mac and in CI.
#
# What it does not cover is the radio. `BackstageBLE` needs a device, and no amount of
# unit testing substitutes for two phones in a room.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v swift >/dev/null 2>&1; then
  echo "verify.sh: no swift toolchain found." >&2
  echo "  macOS: xcode-select --install" >&2
  echo "  linux: https://swift.org/download" >&2
  exit 1
fi

swift --version

# swift-testing rather than XCTest, because XCTest ships inside Xcode and this has to run
# on a machine with only the command-line tools.
#
# On such a machine the Testing framework is present but outside the default search
# paths, and its interop dylib is in a *different* directory again — so both have to be
# named at compile time, at link time and at run time. Without this the failure is
# `no such module 'Testing'`, and then, confusingly, a successful build that cannot
# dlopen its own test bundle.
FRAMEWORKS=""
LIBRARIES=""
if [[ "$(uname -s)" == "Darwin" ]] && ! xcode-select -p 2>/dev/null | grep -q "Xcode.app"; then
  TOOLS="$(xcode-select -p)"
  FRAMEWORKS="$TOOLS/Library/Developer/Frameworks"
  LIBRARIES="$TOOLS/Library/Developer/usr/lib"

  if [[ ! -d "$FRAMEWORKS/Testing.framework" ]]; then
    echo "verify.sh: no Testing.framework under $FRAMEWORKS." >&2
    echo "  Install Xcode, or a newer command-line tools package." >&2
    exit 1
  fi
fi

echo
echo "==> building and testing the protocol port"

if [[ -n "$FRAMEWORKS" ]]; then
  DYLD_FRAMEWORK_PATH="$FRAMEWORKS" DYLD_LIBRARY_PATH="$LIBRARIES" \
    swift test \
    -Xswiftc -F -Xswiftc "$FRAMEWORKS" \
    -Xlinker -F -Xlinker "$FRAMEWORKS" \
    -Xlinker -rpath -Xlinker "$FRAMEWORKS" \
    -Xlinker -rpath -Xlinker "$LIBRARIES"
else
  # A machine with full Xcode, or Linux, finds its own test framework.
  swift test
fi

echo
echo "the Swift port agrees with the Go reference"
