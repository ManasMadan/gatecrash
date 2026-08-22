# Backstage for iOS

The crew radio that needs no radios. Bluetooth mesh chat for a venue where the phone
signal has gone — which at a festival is most of the evening.

This is the iOS half. The Android half is in `../backstage-android`, and the two speak the
same wire format as the box, specified in `../../proto/backstage.md`.

## What is here

| Target            | What it is                                                    | Verified by            |
| ----------------- | ------------------------------------------------------------- | ---------------------- |
| `BackstageMesh`   | Frame codec, cuckoo dedup filter, relay rule. No system deps. | `swift test`, 55 tests |
| `BackstageCrypto` | ChaCha20-Poly1305, X25519, HKDF via CryptoKit; Argon2id here  | `swift test`           |
| `BackstageBLE`    | The CoreBluetooth transport                                   | `swift build`          |
| `BackstageApp`    | The SwiftUI app                                               | `swift build`          |
| `bench`           | How long one Argon2id derivation takes on real hardware        | run it                 |

`./verify.sh` does all of it and is what CI runs.

## Why Argon2id is implemented by hand

CryptoKit has no Argon2, and the channel keys have to match the box's byte for byte or two
phones that typed the same passphrase end up silently in different rooms. So it is
implemented here against the RFC 9106 vectors. It is slow on purpose: ~87 ms in a release
build on an M-series Mac, a few hundred on a phone. Derive once when somebody joins a
channel and keep the result — per message it makes the app unusable.

## Running it on a phone: what you have to do

**Everything below needs Xcode, and that is the one thing this repository cannot do for
you.** `swift build` type-checks every view and every line of the transport, and
`swift test` proves the protocol agrees with Go — but an installable `.ipa` needs the iOS
SDK, a provisioning profile and a signing identity, none of which exist in a
command-line-tools install or on a CI runner.

Concretely:

1. **Install Xcode** from the App Store (needs an Apple ID; it is ~10 GB).
2. **Make an app target.** `File ▸ New ▸ Project ▸ iOS ▸ App`, then add this package as a
   local Swift package dependency and depend on `BackstageBLE` and `BackstageMesh`. Delete
   the generated `ContentView` and point the app at `BackstageScreen`. The
   `BackstageApp` target here exists so the views are compiled and type-checked on every
   CI run; an Xcode app target is what turns them into something installable.
3. **Add the Info.plist keys.** Without these the app is killed the moment it touches
   Bluetooth, with a crash log that does not obviously say why:

   ```
   NSBluetoothAlwaysUsageDescription
     Backstage uses Bluetooth to pass messages between phones when there is no signal.

   UIBackgroundModes
     bluetooth-central
     bluetooth-peripheral
   ```

   The two background modes are both needed. Without `bluetooth-peripheral` a backgrounded
   phone stops advertising and becomes invisible to the mesh — it still receives, and
   relays nothing, which is the failure that looks like the app working.

4. **Sign it.** A free Apple ID gives 7-day builds, enough to test with. Handing the app to
   stewards at a real event needs a paid account and TestFlight.

5. **Point the wallet at it.** Put the TestFlight link in the venue config so the QR
   ticket screen offers it; see `../../docs/guide/apps.md`.

## What is not verified here

The radio. `BackstageBLE` compiles and is type-checked, and its logic is the same logic the
Go simulator drives at five thousand nodes — but whether two iPhones actually see each
other across a field is not something any test on a Mac can answer. That needs two phones,
and it is the one part of this system that has not been run on hardware.

Being specific about it: the frame format, the dedup filter, the relay probability, the
carry rule and the Argon2id derivation are all verified against the Go reference. The
scanning, advertising, connecting and writing are not.
