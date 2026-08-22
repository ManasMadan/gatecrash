# The phone apps

Backstage is the mesh chat app. It is optional — nothing about a ticket depends on it —
and it exists for the part of an evening when the phone signal has gone and the crew still
need to talk to each other.

There are two, one per platform, and they speak the same wire format as the box:

- `apps/backstage-android` — Kotlin, Jetpack Compose, BLE advertising and GATT
- `apps/backstage-ios` — Swift, SwiftUI, Core Bluetooth

## Offering it to attendees

The install links live in the **signed manifest**, not in box configuration:

```json
{
  "event": {
    "name": "Sundown 2026",
    "backstage": {
      "android": "https://example.org/backstage.apk",
      "ios": "https://testflight.apple.com/join/xxxxxxxx",
      "note": "Optional. Lets you message people nearby when there is no signal."
    }
  }
}
```

That placement is the point. This is a link inviting attendees to install software, and the
people following it are standing in a queue trusting the event. A field an operator could
edit on the night is a field anybody with shell access could point at their own APK. In the
manifest it cannot change without the organizer's key.

Leave it out and the app is never mentioned. The wallet renders nothing rather than a dead
button, and it only ever shows the link for the phone being held — offering an APK to an
iPhone is how a page teaches people to ignore it.

## Building the Android app

Needs a JDK 17 and the Android SDK. Nothing else:

```sh
cd apps/backstage-android
./gradlew assembleDebug
# app/build/outputs/apk/debug/app-debug.apk
```

CI does this on every push and keeps the APK as an artifact, so there is always a build to
hand somebody at a venue without cutting a release.

## Building the iOS app

This is the one part of the repository that needs a tool it cannot install for you: **Xcode**,
for the iOS SDK and a signing identity. `swift build` type-checks every view and the whole
Core Bluetooth layer on any Mac — Core Bluetooth and SwiftUI both exist on macOS — but an
installable `.ipa` does not come out of that.

`apps/backstage-ios/README.md` has the steps, including the two `Info.plist` keys without
which the app is killed the moment it touches Bluetooth.

## What is verified, and what is not

Worth being exact about, because "the app builds" and "the app works" are different claims.

Verified against the Go reference, on every CI run:

- the frame codec, byte for byte, from fixtures the Go implementation generates
- the cuckoo dedup filter, including its hash vectors
- the relay probability and the density rule
- the carry (store-and-forward) rule
- Argon2id channel-key derivation, against RFC 9106 and against the box
- the frames the UI builds — a wire constant is a thing to assert, not to remember

Not verified by anything except reading it:

- scanning, advertising, connecting and writing over a real radio

Two phones in a room is the test that matters and it has not been run. The failures will be
there rather than in the protocol: Android's peripheral role is the least-travelled path in
every vendor's Bluetooth stack, and iOS rewrites an advertisement out from under an app when
it backgrounds. That is why the protocol lives in one place, is ported rather than
reinvented, and is checked three ways — so that when the radio misbehaves, the radio is the
only suspect.
