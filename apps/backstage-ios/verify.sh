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
# Probe for the framework rather than inferring it from whether Xcode is installed.
#
# The first version branched on `xcode-select -p | grep Xcode.app`, which is wrong on a CI runner
# where the path is `/Applications/Xcode_26.6.app/...` — the underscore means the grep misses, the
# script takes the command-line-tools branch, and it then fails looking for a framework in a
# directory Xcode does not use. Asking the filesystem where the framework actually is has no such
# failure mode.
FRAMEWORKS=""
LIBRARIES=""
if [[ "$(uname -s)" == "Darwin" ]]; then
  TOOLS="$(xcode-select -p)"
  if [[ -d "$TOOLS/Library/Developer/Frameworks/Testing.framework" ]]; then
    # A command-line-tools install keeps swift-testing outside the default search paths, and its
    # interop dylib in a different directory again — so both have to be named at compile time, at
    # link time and at run time.
    FRAMEWORKS="$TOOLS/Library/Developer/Frameworks"
    LIBRARIES="$TOOLS/Library/Developer/usr/lib"
  fi
  # Otherwise a full Xcode, or a toolchain that bundles swift-testing, finds it unaided.
fi

echo
echo "==> building every target, including the radio and the app"

# `swift test` alone would not touch these: BackstageBLE and BackstageApp have no tests,
# because what they do needs two phones in a room. Building them still catches the failure
# that matters most often — the protocol changed and the code using it no longer compiles.
# CoreBluetooth and SwiftUI both exist on macOS, which is what makes this possible without
# Xcode.
swift build

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
