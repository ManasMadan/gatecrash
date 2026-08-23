# Backstage wire protocol, version 1

This is the specification the Go, Kotlin and Swift implementations all follow. It
exists because the same protocol is written three times, and three implementations
that _almost_ agree is worse than one — a disagreement here does not look like a bug
report, it looks like a message that never arrived.

Every number below is checked by a test in this repository. Where a value is quoted, it
was produced by running the code rather than by reasoning about it.

The reference implementation is `internal/mesh`, `internal/meshcrypto`,
`internal/noise` and `internal/cuckoo`. Where this document and that code disagree, the
code is right and this document is a bug.

---

## 1. What the protocol is for

Twenty thousand phones in a field is a dead cellular network and a dead Wi-Fi network.
Backstage carries short messages between phones over Bluetooth Low Energy with no
infrastructure at all, and the venue boxes join in as super-nodes that bridge clusters
over the LAN.

Four kinds of traffic:

| Kind            | Value | Encrypted with                                  | Relayed                |
| --------------- | ----- | ----------------------------------------------- | ---------------------- |
| Channel message | `1`   | ChaCha20-Poly1305, Argon2id-derived channel key | Yes, probabilistically |
| Direct message  | `2`   | ChaCha20-Poly1305, X25519 session key           | Yes, probabilistically |
| Announcement    | `3`   | Not encrypted. Ed25519-signed                   | Yes, unconditionally   |
| Friend beacon   | `4`   | Not encrypted. Rotating token                   | **Never**              |

A beacon is never relayed, and that is not an oversight: the feature works by hearing a
token _directly_, so a relayed one means walking towards somebody three hops away.

---

## 2. The frame

Fixed 18-byte header, then the body. Little-endian nowhere — every multi-byte field in
the header is a byte array rather than an integer, so there is no endianness to get
wrong.

```
offset  size  field
     0     1  version          always 1
     1     1  kind             1 channel, 2 direct, 3 announcement, 4 beacon
     2     1  flags            bit 0 priority, bit 1 fragment, bit 2 box-origin
     3     1  ttl              hops remaining, 0..6
     4     8  message id       random, identifies the message not the frame
    12     4  channel id       zero unless kind == 1
    16     1  fragment index   0 unless the fragment flag is set
    17     1  fragment total   0 unless the fragment flag is set
    18     n  body             ciphertext, or signed plaintext for an announcement
```

**Maximum frame: 200 bytes**, so the body is at most 182.

Not 255, which is what a BLE extended advertisement can carry. The number that matters
is what a five-year-old Android phone and an iPhone will both reliably transmit in one
advertisement without falling back to a connection, and in the field that is closer to 200.

**Maximum TTL: 6.** BLE indoors is 10 to 30 metres, so six hops is a couple of hundred
metres of crowd. It also bounds how many frames one message can generate.

### Validation, on every received frame

Reject, without relaying:

- `version != 1`
- `ttl > 6`
- `kind` not in `{1, 2, 3, 4}`
- length `< 18` or `> 200`
- the fragment flag set with `fragment_total < 2` or `fragment_index >= fragment_total`
- the fragment flag clear with either fragment field non-zero

That last pair matters more than it looks. A fragment index at or past the total would
index off the end of a reassembly buffer, and everything here arrives from strangers.

---

## 3. Additional authenticated data

The AEAD's additional data is **the 18-byte header with the TTL byte set to zero.**

This is the single most important line in the specification.

Every relay decrements the TTL. A TTL inside the authenticated data would mean the
frame failed to authenticate at the first hop — the message would travel exactly one
hop and the protocol would not work at all.

What that costs: anybody can rewrite a TTL in flight. Raising it is bounded by the limit
every receiver enforces independently; lowering it is indistinguishable from not
relaying, which any node can do by staying silent. Neither is worth defending against.

Everything else _is_ covered, so a frame cannot be re-labelled into another channel,
promoted to priority, or re-stitched into a different message without breaking its tag.

---

## 4. Fragmentation

A body over 182 bytes is split. **Every fragment carries the same message id.**

That is deliberate: it means the whole message propagates as one thing, and the dedup
filter treats it as one thing. Giving each fragment its own id would flood sixteen
independent messages whose reassembly depended on all sixteen taking the same path.

The consequence is that the dedup key is not the message id alone:

```
dedup_key = message_id                      when the fragment flag is clear
dedup_key = message_id || fragment_index    when it is set
```

Without the index, fragment two looks like a duplicate of fragment one and the message
never arrives.

**Maximum 16 fragments**, so just under 3 KB. The bound exists because a reassembly
buffer is memory a stranger can make this phone allocate: without it, one crafted frame
claiming 255 fragments makes every phone in range hold a buffer for a message that will
never come.

Reassembly:

- hold at most 32 partial messages; on overflow drop the oldest, not the newest
- drop a partial message after 30 seconds
- reject a fragment whose total disagrees with the one in progress
- reject a fragment already received
- the reassembled frame is the first fragment's header with the fragment flag and both
  fragment fields cleared

A fragmented message is sealed **once, as a whole, before splitting**, against the
unfragmented header. So the AAD a receiver rebuilds after reassembly is the
unfragmented one, not the per-fragment one.

---

## 5. Dedup

A cuckoo filter of message ids, two generations, rotated every 10 minutes. A node keeps
ids for between one and two windows.

- 4 slots per bucket, bucket count a power of two
- **16-bit fingerprints**, not 8. A false positive means a message this phone has never
  seen is treated as already seen and never relayed — at 8 bits that is about 3% of
  messages, which in a protocol whose delivery guarantee is "many paths, best effort" is
  a 3% tax on every hop
- fingerprint 0 is the empty-slot marker, so a fingerprint that hashes to 0 becomes 1
- 8192 ids per generation is 32 KiB; two generations is 64 KiB

### Hashing, exactly

```
h        = splitmix64(fnv1a64(key))
fingerprint = h >> 48                (or 1 if that is 0)
bucket_1    = h & (buckets - 1)
bucket_2    = (bucket_1 ^ splitmix64(fingerprint)) & (buckets - 1)
```

```
fnv1a64(data):
    h = 0xcbf29ce484222325
    for each byte b:  h ^= b;  h *= 0x100000001b3
    return splitmix64(h)

splitmix64(x):
    x += 0x9e3779b97f4a7c15
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
    x = (x ^ (x >> 27)) * 0x94d049bb133111eb
    return x ^ (x >> 31)
```

All arithmetic is unsigned 64-bit with wrapping multiply. In Kotlin use `ULong`; in
Swift use `UInt64` with `&*`.

**The fingerprint must be mixed before the xor.** A bare `bucket ^ fingerprint` only
ever changes the low sixteen bits of the index, so in a filter with more than 65,536
buckets both homes land in the same neighbourhood and the load factor collapses.

Insert with eviction, at most 500 kicks, and the victim slot is derived rather than
random so two machines given the same inserts agree byte for byte:

```
slot = splitmix64(kick ^ fingerprint) % 4
```

It has to vary with the kick count. Always evicting slot zero is reproducible and
useless — the chain falls into a two-position cycle and the filter reports itself full
at 73% occupancy instead of 95%.

---

## 6. Relaying

On receiving a frame:

1. Count the sender towards the density estimate, **whatever else happens** — including
   frames that failed to decode. A collision is the strongest possible evidence that the
   band is busy, and throwing it away is exactly backwards.
2. If the dedup filter has seen the key, drop it. Do not deliver, do not relay.
3. Deliver it locally.
4. If `kind == 4`, stop. Beacons are never relayed.
5. If `ttl == 0`, stop.
6. If the priority flag is set, relay. Announcements cross a saturated field.
7. Otherwise relay with probability `min(1, k / neighbours)`, `k = 3`.
8. Before transmitting, wait a uniform random delay in `[0, 250ms]`.

**The jitter is not optional.** Without it every node that decided to relay transmits at
the same instant, and on a shared medium simultaneous transmissions are collisions
rather than deliveries.

**Density** is the number of distinct peers heard in the last 30 seconds. Shorter and
the estimate swings as people walk past; longer and it lags a crowd coming through a
gate, which is when it needs to be right. A node that has heard nobody relays
unconditionally — it is either alone or at the edge of the crowd, and the edge is where
a message needs carrying.

The peer identifier is whatever the platform gives you. Both platforms rotate theirs,
which is good for the people carrying the phones and fine here: only distinct counts
inside a 30-second window matter.

### Store and forward

A node keeps frames it relayed _or suppressed_ for 2 minutes, up to 64 of them, and
offers them to a peer it has not heard from in that window. This is what crosses a
thirty-metre gap between two groups who never hear each other — BLE mesh's worst
real-world failure.

**Offer them only when the neighbourhood is sparse** — fewer than `k` neighbours, the
same test the relay rule uses. In a dense crowd every node meets hundreds of peers, and
four frames each is hundreds of thousands of extra transmissions: the broadcast storm
the density rule exists to prevent, reintroduced through a side door. The simulator
found this the hard way.

Offer at most 4 frames per newly met peer, freshest first, spread out in time.

---

## 7. Channel encryption

```
salt = SHA256("gatecrash-mesh-channel-v1" || 0x00 || event_id || 0x00 || channel_name)
key  = Argon2id(passphrase, salt, t=1, m=65536 KiB, p=4, len=32)
id   = SHA256("gatecrash-mesh-channel-id-v1" || 0x00 || key)[0..4]
```

`channel_name` is lower-cased, trimmed, and stripped of a leading `#`. Two people
typing `#Gate-3` and `gate-3` and silently ending up in different rooms is the most
predictable failure this feature has.

**The salt is derived rather than random,** which is the opposite of what a password
database should do and the only thing that works here. A random salt would have to
travel in every 200-byte frame, and worse, two phones that both know the passphrase
could not derive the same key without first exchanging it — which is exactly the
coordination a protocol with no infrastructure cannot do. The Argon2id cost carries the
security instead.

**Argon2id parameters are interactive, not disk-encryption.** 64 MiB and one pass is
about 100ms on a mid-range phone and 12.6ms on an M-series laptop. Slower would mean
the feature does not get used; the memory cost is the part that cannot be bought on a
GPU, and it is what turns "backstage" from seconds of cracking into weeks.

Derive once when somebody joins a channel and keep the result. Deriving per message
makes the app unusable.

**The channel id is a hash of the key**, not of the name. Of the name would let anybody
listening enumerate an event's channels from a wordlist; of the passphrase would give an
attacker an oracle to test guesses against without paying the Argon2id cost.

Sealing: ChaCha20-Poly1305, 12-byte random nonce prepended to the ciphertext, AAD as
§3. Random rather than a counter, because a counter needs state that survives an app
restart and two phones in a channel cannot coordinate counters — and a repeated nonce
with the same key breaks the cipher completely.

---

## 8. Direct messages

Identities are **ephemeral per event**. No account, nothing to subpoena, and nothing
linking this festival to the next one. Two keys, not one — using a single key for both
signing and Diffie-Hellman weakens both, and the second key costs 32 bytes:

- Ed25519 for signing
- X25519 for agreement

```
shared     = X25519(my_agree_private, their_agree_public)
low, high  = the two agreement public keys, sorted lexicographically
transcript = low || high
key_l2h    = HKDF-SHA256(ikm=shared, salt=transcript, info="gatecrash-mesh-dm-v1 low-to-high", 32)
key_h2l    = HKDF-SHA256(ikm=shared, salt=transcript, info="gatecrash-mesh-dm-v1 high-to-low", 32)
```

The node whose public key sorts lower **sends** with `key_l2h` and **receives** with
`key_h2l`; the other does the reverse. Sorting is the only ordering both sides can agree
on without talking.

Two keys split by direction because with one shared key a frame this phone sent is
indistinguishable from one it received, so an attacker can replay somebody's own message
back at them and it authenticates.

Reject an all-zero shared secret. That means the peer sent a low-order point, which is
an attempt to force a known key rather than a transmission error.

The transcript binds both public keys into the derivation, which is what stops an
unknown key-share attack.

### Fingerprint

```
fingerprint = base32(SHA256("gatecrash-mesh-identity-v1" || 0x00 || verify_key || agree_key)[0..4])
              lower-cased, first 6 characters
```

Six characters, because a fingerprint nobody will read out loud protects nobody. The
threat here is a casual impersonator in the same field, not somebody grinding
collisions.

---

## 9. Announcements

Signed, not encrypted. "Gate 4 is now open" is not a secret; the property that matters
is that nobody else can say it. Encrypting it would mean distributing a key to twenty
thousand phones, which is the same as not having one.

```
message   = "gatecrash-mesh-announcement-v1" || 0x00 || event_id || 0x00 || body
signature = Ed25519(organizer_private, message)
frame body = signature (64 bytes) || body
```

Verified against the organizer key every phone already has from the manifest. The event
id is in the signed message so an announcement cannot be replayed at a different
event — and "everybody leave the building" is exactly the message somebody would want
to replay.

Announcements carry the priority flag and relay unconditionally.

**A known limitation:** the signature covers the whole body, so it can only be verified
after reassembly. A phone cannot tell whether a _fragment_ is genuine before relaying
it, which means somebody can flood priority-flagged junk. The mitigations are the hop
limit and the dedup filter — it propagates once and dies — and it is a real limitation
rather than a solved problem.

---

## 10. Friend beacons

```
token = SHA256("gatecrash-mesh-beacon-v1" || 0x00 || beacon_key || window_be64)[0..4]
```

`window` is unix seconds divided by the rotation period, big-endian. Accept a token from
`window - 1`, `window` and `window + 1`: two phones disagree about the time by a second
or two, and a friend finder that stops working on every window boundary is one nobody
trusts.

Four bytes, because this rides in a BLE advertisement where there are barely a couple of
dozen to spend.

**It rotates, and that is the whole privacy design.** A constant identifier broadcast in
a field is how early Bluetooth trackers became a stalking tool.

---

## 11. Noise XX, for pairwise sessions

`Noise_XX_25519_ChaChaPoly_SHA256`, revision 34. Full details in `internal/noise`; the
two things that break ports:

**The nonce is four zero bytes then the counter, little-endian.** Big-endian, or the
zeros at the wrong end, produces a handshake that completes and then cannot decrypt one
transport message.

**The two split keys are assigned by direction, not by order.** The initiator sends with
the first and receives with the second; the responder does the reverse.

Message sizes are fixed with an empty payload, and are the cheapest conformance check a
port can run:

| Message               | Bytes |
| --------------------- | ----- |
| 1 (`-> e`)            | 32    |
| 2 (`<- e, ee, s, es`) | 96    |
| 3 (`-> s, se`)        | 64    |

The prologue is the event id, so two phones at different events cannot complete a
handshake at all — a cleaner failure than completing one and finding out later.

### Conformance vectors

Static keys from private scalars `[1..32]` and `[100..131]`, ephemerals from `[2..33]`
and `[200..231]` (each byte `seed + index`), prologue `"gatecrash-conformance"`,
payloads `"one"`, `"two"`, `"three"`:

```
message 1        ab9f2628c325c141e9fb2430f106850f62930bc3f0b12df39a9b84a49c7c1d126f6e65
message 2        4d5bab89b0733d9d8dcecf04f321c90b761b7765a6bdb2bddbfad3e7abdf1f6666b61efbdc18b0f49b3610567f7a412f86062ee7e8b9d6ceb767cdaacc3ca83402a00dbfcf11b242b463e5099c3f2de5430991231c53977911c6a046519d1e9d13707b
message 3        a40a3f66bd7f98c5d4cf293fce376a69e233c379d16e6abad5a7c87cc99725f0fbed98e31da6f3516441d96e0fc6c7f294585e666d292c6b4b2c6b3db5ba80941ae517606c
handshake hash   fb5537512b27ac95fb84534005324479b6ce41bd81f3e445e7a4c5dad6f3a830
```

These were produced by this repository's implementation. They are **not** official Noise
vectors, and their job is to let a Kotlin or Swift port be checked against a fixture
rather than against a probability. Regenerate with:

```sh
go test ./internal/noise -run TranscriptIsReproducible -v
```

---

## 12. BLE transport

Deliberately not specified in detail, because the two platforms look nothing alike and
an abstraction over both would fit neither. What both do:

- advertise frames as manufacturer-specific or service data, one frame per
  advertisement
- scan continuously while the app is in the foreground
- fall back to a GATT connection for a frame that will not fit an advertisement

Service UUID: `6761-7465-6372-6173-682d-6d65-7368-7631` ("gatecrash-meshv1" in ASCII
hex), so a phone can filter for peers running this protocol.

### Honest physics

- BLE is 10–30 metres indoors, and what makes the range vary that much is what is
  between the two radios — which at a concert is bodies.
- **iOS restricts advertising aggressively when the screen is locked.** A phone in a
  pocket is a much worse node than a phone in a hand. Mitigations: foreground use
  patterns, box bridging, local notifications. It is reduced, not removed.
- Android is better and not unlimited: background scanning is throttled and some OEM
  power managers kill it entirely.
- Web Bluetooth has no peripheral mode and does not exist on iOS Safari, which is why
  chat is native-only while the ticket stays a web app.

---

## 13. Implementing this

Port the pure logic first: the frame codec, the dedup filter, the relay decision, the
fragmenter. All four are testable with no radio, and all four have conformance vectors.
Then the crypto against the vectors in §7–11. Then the radio, which is the only part
that needs a device.

The order matters because the radio is where debugging is slowest, and arriving there
with an already-verified protocol is the difference between one bug and an
indistinguishable pile of them.
