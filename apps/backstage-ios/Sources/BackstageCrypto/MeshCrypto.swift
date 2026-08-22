import BackstageMesh
import CryptoKit
import Foundation

/// The encryption behind Backstage, ported from `internal/meshcrypto`.
///
/// CryptoKit for everything it has — ChaCha20-Poly1305, X25519, Ed25519, HKDF, SHA-256 —
/// and the Argon2id in this module for the one thing it does not. Nothing here is
/// hand-rolled that did not have to be.
public enum MeshCrypto {

    // MARK: channels

    /// Argon2id parameters. These are not tunable: a phone that picks different ones
    /// derives a different key and is silently in a different room.
    static let argonIterations: UInt32 = 1
    static let argonMemoryKiB: UInt32 = 65536  // 64 MiB
    static let argonParallelism: UInt32 = 4
    static let argonKeyLength = 32

    static let saltPrefix = "gatecrash-mesh-channel-v1"

    public struct ChannelKey {
        let key: SymmetricKey
        /// A public, non-secret identifier carried in the clear in every frame, so a phone
        /// knows which of its keys to try without trying all of them.
        public let id: Data

        /// The raw key bytes. Exposed only for the conformance tests: everything else
        /// should go through seal and open.
        let rawKey: Data
    }

    /// Turns a passphrase into a channel key.
    ///
    /// Slow on purpose: 87 ms in release on an M-series Mac, and a few hundred on a phone.
    /// Do it once when somebody joins a channel and keep the result — per message it would
    /// make the app unusable, and that mistake is the reason this comment exists.
    public static func deriveChannelKey(
        eventID: String, channel: String, passphrase: String
    ) throws -> ChannelKey {
        let salt = channelSalt(eventID: eventID, channel: channel)

        let raw = try Argon2.id(
            passphrase: Data(passphrase.utf8),
            salt: salt,
            iterations: argonIterations,
            memoryKiB: argonMemoryKiB,
            parallelism: argonParallelism,
            length: argonKeyLength)

        // The id is a hash of the key, not of the name or the passphrase. Of the name
        // would let anybody listening enumerate an event's channels from a wordlist; of
        // the passphrase would give an attacker an oracle to test guesses against without
        // paying the Argon2id cost.
        var idInput = Data("gatecrash-mesh-channel-id-v1\u{0}".utf8)
        idInput.append(raw)
        let id = Data(SHA256.hash(data: idInput).prefix(4))

        return ChannelKey(key: SymmetricKey(data: raw), id: id, rawKey: raw)
    }

    /// The salt, derived rather than random.
    ///
    /// The opposite of what a password database should do, and the only thing that works
    /// with no infrastructure: a random salt would have to travel in every 200-byte frame,
    /// and two phones that both know the passphrase could not derive the same key without
    /// first exchanging it. The Argon2id cost carries the security instead.
    static func channelSalt(eventID: String, channel: String) -> Data {
        let input = "\(saltPrefix)\u{0}\(eventID)\u{0}\(normalize(channel))"
        return Data(SHA256.hash(data: Data(input.utf8)))
    }

    /// Makes "#Gate-3", "gate-3" and " GATE-3 " the same channel.
    ///
    /// Two people typing a name slightly differently and silently ending up in different
    /// rooms is the most predictable failure this feature has.
    static func normalize(_ name: String) -> String {
        var trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("#") { trimmed.removeFirst() }
        return trimmed.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// Encrypts a message for a channel.
    ///
    /// The nonce is random and travels with the ciphertext. Random rather than a counter,
    /// because a counter needs state that survives an app restart and two phones in a
    /// channel have no way to coordinate counters — and a repeated nonce with the same key
    /// breaks ChaCha20-Poly1305 completely.
    public static func seal(
        _ plaintext: Data, channel: ChannelKey, additionalData: Data
    ) throws -> Data {
        let box = try ChaChaPoly.seal(
            plaintext, using: channel.key, authenticating: additionalData)
        // nonce || ciphertext || tag, which is what the Go side writes.
        return Data(box.nonce) + box.ciphertext + box.tag
    }

    /// Decrypts a channel message.
    ///
    /// Failure is the normal case rather than an error worth surfacing: every phone in
    /// range hears every frame, and most of them are for channels it is not in.
    public static func open(
        _ sealed: Data, channel: ChannelKey, additionalData: Data
    ) throws -> Data {
        let box = try ChaChaPoly.SealedBox(combined: sealed)
        return try ChaChaPoly.open(box, using: channel.key, authenticating: additionalData)
    }

    // MARK: identities and direct messages

    /// One phone's ephemeral identity for one event.
    ///
    /// Ephemeral is the whole point: no account, no handle that survives the night, and
    /// nothing that links two festivals. The signing key and the agreement key are
    /// separate because using one key for both signing and Diffie-Hellman weakens both,
    /// and the second key costs 32 bytes.
    public struct Identity {
        public let signing: Curve25519.Signing.PrivateKey
        public let agreement: Curve25519.KeyAgreement.PrivateKey

        public init() {
            signing = Curve25519.Signing.PrivateKey()
            agreement = Curve25519.KeyAgreement.PrivateKey()
        }

        public var publicIdentity: PublicIdentity {
            PublicIdentity(
                verify: signing.publicKey.rawRepresentation,
                agree: agreement.publicKey.rawRepresentation)
        }
    }

    public struct PublicIdentity: Equatable {
        public let verify: Data
        public let agree: Data

        public init(verify: Data, agree: Data) {
            self.verify = verify
            self.agree = agree
        }

        /// The short, human-comparable form, read out loud to confirm you are talking to
        /// the person in front of you rather than to somebody relaying.
        ///
        /// Six characters, because a fingerprint nobody will read out loud protects
        /// nobody. The threat is a casual impersonator in the same field, not somebody
        /// grinding collisions.
        public var fingerprint: String {
            var input = Data("gatecrash-mesh-identity-v1\u{0}".utf8)
            input.append(verify)
            input.append(agree)
            let digest = Data(SHA256.hash(data: input).prefix(4))
            return String(base32(digest).lowercased().prefix(6))
        }
    }

    /// A pair of keys for talking to one peer, split by direction.
    ///
    /// Two keys rather than one: with a single shared key a frame this phone sent is
    /// indistinguishable from one it received, so an attacker can replay somebody's own
    /// message back at them and it authenticates.
    public struct Session {
        let send: SymmetricKey
        let receive: SymmetricKey
    }

    public enum CryptoError: Swift.Error {
        case degeneratePublicKey
    }

    /// Derives the session for talking to a peer.
    ///
    /// The direction each phone calls "send" is decided by comparing the two public keys,
    /// which is the only ordering both sides can agree on without talking.
    public static func session(_ identity: Identity, peer: PublicIdentity) throws -> Session {
        let peerKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer.agree)
        let shared = try identity.agreement.sharedSecretFromKeyAgreement(with: peerKey)

        let mine = identity.agreement.publicKey.rawRepresentation
        let weAreLow = mine.lexicographicallyPrecedes(peer.agree)

        // The transcript binds both public keys into the derivation, which is what stops
        // an unknown key-share attack — somebody convincing two people they are talking to
        // them rather than to each other.
        let transcript = weAreLow ? mine + peer.agree : peer.agree + mine

        let lowToHigh = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: transcript,
            sharedInfo: Data("gatecrash-mesh-dm-v1 low-to-high".utf8),
            outputByteCount: 32)
        let highToLow = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: transcript,
            sharedInfo: Data("gatecrash-mesh-dm-v1 high-to-low".utf8),
            outputByteCount: 32)

        return weAreLow
            ? Session(send: lowToHigh, receive: highToLow)
            : Session(send: highToLow, receive: lowToHigh)
    }

    public static func seal(
        _ plaintext: Data, session: Session, additionalData: Data
    ) throws -> Data {
        let box = try ChaChaPoly.seal(
            plaintext, using: session.send, authenticating: additionalData)
        return Data(box.nonce) + box.ciphertext + box.tag
    }

    public static func open(
        _ sealed: Data, session: Session, additionalData: Data
    ) throws -> Data {
        let box = try ChaChaPoly.SealedBox(combined: sealed)
        return try ChaChaPoly.open(box, using: session.receive, authenticating: additionalData)
    }

    // MARK: announcements

    /// Verifies an organizer announcement against the key every phone already has from the
    /// manifest.
    ///
    /// Signed and not encrypted: "Gate 4 is now open" is not a secret, and the property
    /// that matters is that nobody else can say it. The event id is inside the signed
    /// message so an announcement cannot be replayed at a different event — and "everybody
    /// leave the building" is exactly the message somebody would want to replay.
    public static func verifyAnnouncement(
        organizerKey: Data, eventID: String, body: Data, signature: Data
    ) -> Bool {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: organizerKey) else {
            return false
        }
        var message = Data("gatecrash-mesh-announcement-v1\u{0}".utf8)
        message.append(Data(eventID.utf8))
        message.append(0)
        message.append(body)
        return key.isValidSignature(signature, for: message)
    }

    // MARK: friend beacons

    /// The rotating token a phone advertises for one friend.
    ///
    /// It rotates so that somebody who is not the friend cannot follow a person around a
    /// festival by tracking a constant identifier — the privacy failure that made early
    /// Bluetooth trackers a stalking tool.
    public static func beaconToken(key: Data, window: UInt64) -> Data {
        var input = Data("gatecrash-mesh-beacon-v1\u{0}".utf8)
        input.append(key)
        // Big-endian, matching the Go side.
        for shift in stride(from: 56, through: 0, by: -8) {
            input.append(UInt8(truncatingIfNeeded: window >> UInt64(shift)))
        }
        return Data(SHA256.hash(data: input).prefix(4))
    }

    /// Whether a token belongs to this friend, allowing one window either side.
    ///
    /// The tolerance is for the same reason the rotating ticket code has one: two phones
    /// disagree about the time by a second or two, and a friend finder that stops working
    /// on every window boundary is one nobody trusts.
    public static func matchesBeacon(key: Data, token: Data, window: UInt64) -> Bool {
        for candidate in [window, window &- 1, window &+ 1] {
            // Constant-time, because a timing signal here would let somebody test whether
            // a token belongs to a particular friend key.
            let expected = beaconToken(key: key, window: candidate)
            if expected.count == token.count {
                var difference: UInt8 = 0
                for (a, b) in zip(expected, token) { difference |= a ^ b }
                if difference == 0 { return true }
            }
        }
        return false
    }
}

/// RFC 4648 base32, no padding. Matches Go's `base32.StdEncoding.WithPadding(NoPadding)`.
func base32(_ data: Data) -> String {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var out = ""
    var buffer = 0
    var bits = 0

    for byte in data {
        buffer = (buffer << 8) | Int(byte)
        bits += 8
        while bits >= 5 {
            out.append(alphabet[(buffer >> (bits - 5)) & 31])
            bits -= 5
        }
    }
    if bits > 0 {
        out.append(alphabet[(buffer << (5 - bits)) & 31])
    }
    return out
}
