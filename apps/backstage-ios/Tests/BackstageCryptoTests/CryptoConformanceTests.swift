import Foundation
import Testing

@testable import BackstageCrypto

/// The Swift crypto, checked against the Go box.
///
/// The values here came from:
///
///     go test ./internal/meshcrypto -run ChannelKeyVectorsForThePorts -v
///
/// The one that matters is the channel key. A channel is only a channel if everybody in
/// it lands on the same key, so if the Argon2id in this module disagrees with the box's
/// by a single byte, two people who typed the same passphrase are silently in different
/// rooms and neither of them can tell.

private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

@Suite("BLAKE2b, RFC 7693")
struct Blake2bTests {

    /// The published vectors. BLAKE2b is here only because Argon2 needs it, so getting it
    /// right is the first of two places a wrong channel key could come from.
    @Test("the empty input, 64 bytes")
    func emptyInput() {
        #expect(
            hex(Blake2b.hash(Data(), digestLength: 64))
                == "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                    + "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
    }

    @Test("abc, 64 bytes")
    func abc() {
        #expect(
            hex(Blake2b.hash(Data("abc".utf8), digestLength: 64))
                == "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                    + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
    }

    /// Argon2 asks for several different digest lengths, and a truncation bug would only
    /// show up at some of them.
    @Test("shorter digests")
    func shorterDigests() {
        #expect(hex(Blake2b.hash(Data("abc".utf8), digestLength: 32))
            == "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")
        #expect(hex(Blake2b.hash(Data(), digestLength: 1)) == "2e")
    }
}

@Suite("Argon2id, RFC 9106")
struct Argon2Tests {

    /// The exact parameters Backstage uses, against the Go implementation's output.
    ///
    /// If this passes and the channel key below fails, the salt derivation is at fault
    /// rather than the KDF — which is why both are checked separately.
    @Test("agrees with Go at the parameters Backstage uses")
    func agreesWithGo() throws {
        let out = try Argon2.id(
            passphrase: Data("password".utf8),
            salt: Data("somesalt00000000".utf8),
            iterations: 1, memoryKiB: 65536, parallelism: 4, length: 32)

        #expect(hex(out) == "510109b0442e930b2a8e9f3bbb0bb23d3a097af1f532f3749787ee6985163daa")
    }

    /// The earliest steps, so a mismatch says which layer is wrong rather than only that
    /// the answer is.
    ///
    /// From a Go program that reimplements just these steps over
    /// `golang.org/x/crypto/blake2b`.
    @Test("H' and H0 agree with Go before any memory is filled")
    func earlyStepsAgree() {
        // H', the variable-length hash, at a length that takes the short branch.
        #expect(
            hex(argon2Hash(Data("abc".utf8), outputLength: 32))
                == "6cfcbf5d43e547674bfbc009070570bcb84e272d359c1e9277e416d74cbbe1c6")

        // H0 for password/somesalt, t=1 m=8 p=1 len=32, Argon2id.
        let h0 = Argon2.initialHashForTesting(
            passphrase: Data("password".utf8), salt: Data("somesalt".utf8),
            iterations: 1, memoryKiB: 8, parallelism: 1, length: 32, variant: .id)
        #expect(
            hex(h0)
                == "d2f87cec38bce64773d72e03748f5db07249c78831b7e0dedd6a03eb44e66e27"
                    + "d3f0a44151e96a23d5d0eb5e4f91942246d16a0458157e8ad4931a7225774a61")

        // And the first two blocks of lane 0, which come straight from H0. If these are
        // right and the tag is wrong, the bug is in the compression function or the
        // addressing rather than in the setup.
        var first = h0
        first.append(littleEndian32(0))
        first.append(littleEndian32(0))
        let block0 = argon2Hash(first, outputLength: 1024)
        #expect(hex(block0.prefix(32))
            == "8d9e53a8532f86e93869125e3509f221d049f12fdfce5fe27bc24ce843515751")
        #expect(hex(block0.suffix(32))
            == "e7f2420a2ccacfa920735c5e88f6becf8c69cb1a9ee8c4fc9d771bbf81a30ab8")

        var second = h0
        second.append(littleEndian32(1))
        second.append(littleEndian32(0))
        let block1 = argon2Hash(second, outputLength: 1024)
        #expect(hex(block1.prefix(32))
            == "e7a1e4ad3604812b3815480e9c79ce0ad298b2a807248bb4de487ea2ae1c6968")
    }

    /// One compression, against the Go reference.
    ///
    /// If H0 matches and this does not, the bug is in the permutation or the mixing
    /// function — which is fifty lines rather than three hundred.
    @Test("one compression agrees with Go")
    func oneCompressionAgrees() {
        let h0 = Argon2.initialHashForTesting(
            passphrase: Data("password".utf8), salt: Data("somesalt".utf8),
            iterations: 1, memoryKiB: 8, parallelism: 1, length: 32, variant: .id)

        var in0 = h0
        in0.append(littleEndian32(0))
        in0.append(littleEndian32(0))
        let b0 = Argon2.wordsForTesting(argon2Hash(in0, outputLength: 1024))

        var in1 = h0
        in1.append(littleEndian32(1))
        in1.append(littleEndian32(0))
        let b1 = Argon2.wordsForTesting(argon2Hash(in1, outputLength: 1024))

        let out = Argon2.bytesForTesting(Argon2.compressForTesting(b0, b1))
        #expect(hex(out.prefix(32))
            == "74ca09eb894c045df276eb80bb42648ef2d3bed9d5d8279c95c3ca957f74ef82")
        #expect(hex(out.suffix(32))
            == "60d61c11ce65fcf5583fb73ce41f54f46203041f9f7d9c350efb421a642e2357")
    }

    /// The address block for pass 0, slice 1, lane 0, counter 1 — the data-independent
    /// addressing path, which is the one place Argon2id differs from Argon2d.
    @Test("the address block agrees with Go")
    func addressBlockAgrees() {
        let zero = [UInt64](repeating: 0, count: 128)
        var input = zero
        input[0] = 0  // pass
        input[1] = 0  // lane
        input[2] = 1  // slice
        input[3] = 8  // total blocks
        input[4] = 1  // passes
        input[5] = 2  // variant: id
        input[6] = 1  // counter

        let first = Argon2.compressForTesting(zero, input)
        let address = Argon2.compressForTesting(zero, first)

        #expect(String(format: "%016lx", address[0]) == "0f71e00bd5d76577")
        #expect(String(format: "%016lx", address[1]) == "c6894b6c4c5c25e7")
    }

    /// Block by block, for the smallest case, against a full Go reimplementation that
    /// was itself checked against golang.org/x/crypto.
    @Test("the filled memory agrees with Go, block by block")
    func filledMemoryAgrees() throws {
        _ = try Argon2.id(
            passphrase: Data("password".utf8), salt: Data("somesalt".utf8),
            iterations: 1, memoryKiB: 8, parallelism: 1, length: 32)

        let memory = Argon2.lastMemoryForTesting
        #expect(memory.count == 8)
        #expect(String(format: "%016lx", memory[2][0]) == "5d044c89eb09ca74", "block 2")
        #expect(String(format: "%016lx", memory[3][0]) == "cfe28e48b23ef5d4", "block 3")
        #expect(String(format: "%016lx", memory[7][0]) == "b124d5b8e02cf434", "block 7")
    }

    /// The bisection ladder. Each row isolates one more piece of the algorithm, so a
    /// mismatch says roughly where to look rather than only that the answer is wrong.
    ///
    ///   m=8  p=1 t=1 — one lane, two blocks per segment, data-independent addressing only
    ///   m=32 p=1 t=1 — one lane, several blocks, both addressing modes
    ///   m=32 p=1 t=2 — the second pass, which XORs rather than overwrites
    ///   m=32 p=4 t=1 — four lanes, so cross-lane references
    ///
    /// All from `golang.org/x/crypto/argon2`.
    @Test("agrees with Go at every step of the ladder")
    func bisectionLadder() throws {
        let password = Data("password".utf8)
        let salt = Data("somesalt".utf8)

        #expect(
            hex(try Argon2.id(passphrase: password, salt: salt, iterations: 1, memoryKiB: 8, parallelism: 1))
                == "f137f8e186a403a679ccd0606e5ab5dcdafe43c1640855ac8c6e33e9bd63eeb3",
            "m=8 p=1 t=1")

        #expect(
            hex(try Argon2.id(passphrase: password, salt: salt, iterations: 1, memoryKiB: 32, parallelism: 1))
                == "301a8fbb4c595c521e6752c989a952d47e1ecd063d89eebcf6887288675b54c8",
            "m=32 p=1 t=1")

        #expect(
            hex(try Argon2.id(passphrase: password, salt: salt, iterations: 2, memoryKiB: 32, parallelism: 1))
                == "31111cc053ba0a799c0884148fd7ec9dc3631f3e8cf476cca9521d4ccc5136e8",
            "m=32 p=1 t=2 — the second pass xors rather than overwrites")

        #expect(
            hex(try Argon2.id(passphrase: password, salt: salt, iterations: 1, memoryKiB: 32, parallelism: 4))
                == "299d5e50f0022a4eef2d510ade9b1743bd1f568feefc042c3dff926a271e7fb2",
            "m=32 p=4 t=1 — cross-lane references")
    }

    @Test("rejects parameters that would weaken it")
    func rejectsBadParameters() {
        #expect(throws: (any Error).self) {
            try Argon2.id(passphrase: Data(), salt: Data("short".utf8))
        }
        #expect(throws: (any Error).self) {
            try Argon2.id(passphrase: Data(), salt: Data("longenoughsalt".utf8), iterations: 0)
        }
        #expect(throws: (any Error).self) {
            try Argon2.id(
                passphrase: Data(), salt: Data("longenoughsalt".utf8),
                memoryKiB: 4, parallelism: 4)
        }
    }
}

@Suite("Channels")
struct ChannelTests {

    /// The check this whole module exists for.
    @Test("the channel key and id match the box, byte for byte")
    func matchesTheBox() throws {
        let key = try MeshCrypto.deriveChannelKey(
            eventID: "SUNDOWN", channel: "lost-and-found", passphrase: "orange lanyard")

        #expect(
            hex(MeshCrypto.channelSalt(eventID: "SUNDOWN", channel: "lost-and-found"))
                == "e9e0c1740cf3d8a56b66a81218eca5e816523a7b68dccf2d52a553ae5dbce67f")
        #expect(hex(key.rawKey)
            == "a692bd249b1a448f7d0b313f03bf897c8d1633ec32540641b2956687346c9caf")
        #expect(hex(key.id) == "0968f3d2")
    }

    @Test("a second channel matches too")
    func secondChannelMatches() throws {
        let key = try MeshCrypto.deriveChannelKey(
            eventID: "SUNDOWN", channel: "gate-3", passphrase: "shared secret")
        #expect(hex(key.rawKey)
            == "13519c388aaef1d1a9c07ffd8e5e01b2418c5d39a370200e66c7fa15b52be50c")
        #expect(hex(key.id) == "eb0b21a4")
    }

    /// A frame captured at one festival must not open a channel at the next one, even with
    /// the same channel name and passphrase.
    @Test("a channel is scoped to its event")
    func scopedToItsEvent() throws {
        let key = try MeshCrypto.deriveChannelKey(
            eventID: "EVENT-TWO", channel: "afterparty", passphrase: "same passphrase")
        #expect(hex(key.rawKey)
            == "3abc6a7f5ad54dde8a911bbc81574758bae04f902b4060e6d888ff8423de3d8d")
        #expect(hex(key.id) == "26ddd4ca")
    }

    /// Two people typing "#Gate-3" and "gate-3" and silently ending up in different rooms
    /// is the most predictable failure this feature has.
    @Test("channel names are forgiving")
    func namesAreForgiving() throws {
        let canonical = try MeshCrypto.deriveChannelKey(
            eventID: "SUNDOWN", channel: "gate-3", passphrase: "shared secret")

        for written in ["#gate-3", "  #Gate-3 ", "GATE-3", " gate-3"] {
            let key = try MeshCrypto.deriveChannelKey(
                eventID: "SUNDOWN", channel: written, passphrase: "shared secret")
            #expect(key.id == canonical.id, "\(written) derived a different channel")
        }
    }

    @Test("seals and opens, and the additional data is authenticated")
    func sealAndOpen() throws {
        let key = try MeshCrypto.deriveChannelKey(
            eventID: "SUNDOWN", channel: "general", passphrase: "pass")

        let sealed = try MeshCrypto.seal(
            Data("blue shirt kid at the mixer desk".utf8),
            channel: key, additionalData: Data("header-as-sent".utf8))

        let opened = try MeshCrypto.open(
            sealed, channel: key, additionalData: Data("header-as-sent".utf8))
        #expect(String(decoding: opened, as: UTF8.self) == "blue shirt kid at the mixer desk")

        // A tampered header must not open, which is what stops a frame being re-labelled
        // into another channel or promoted to priority in flight.
        #expect(throws: (any Error).self) {
            try MeshCrypto.open(
                sealed, channel: key, additionalData: Data("header-tampered".utf8))
        }
    }
}

@Suite("Direct messages")
struct DirectMessageTests {

    @Test("two phones that have never met a server can talk")
    func roundTrip() throws {
        let alice = MeshCrypto.Identity()
        let bob = MeshCrypto.Identity()

        let fromAlice = try MeshCrypto.session(alice, peer: bob.publicIdentity)
        let fromBob = try MeshCrypto.session(bob, peer: alice.publicIdentity)

        let sealed = try MeshCrypto.seal(
            Data("by the sound desk".utf8), session: fromAlice, additionalData: Data())
        let opened = try MeshCrypto.open(sealed, session: fromBob, additionalData: Data())
        #expect(String(decoding: opened, as: UTF8.self) == "by the sound desk")

        let back = try MeshCrypto.seal(
            Data("on my way".utf8), session: fromBob, additionalData: Data())
        let returned = try MeshCrypto.open(back, session: fromAlice, additionalData: Data())
        #expect(String(decoding: returned, as: UTF8.self) == "on my way")
    }

    /// With one shared key, an attacker can replay somebody's own message back at them and
    /// it authenticates.
    @Test("the directions are separate keys")
    func directionsAreSeparate() throws {
        let alice = MeshCrypto.Identity()
        let bob = MeshCrypto.Identity()
        let fromAlice = try MeshCrypto.session(alice, peer: bob.publicIdentity)

        let sealed = try MeshCrypto.seal(
            Data("reflect me".utf8), session: fromAlice, additionalData: Data())

        #expect(throws: (any Error).self) {
            try MeshCrypto.open(sealed, session: fromAlice, additionalData: Data())
        }
    }

    @Test("a third party cannot read a direct message")
    func thirdPartyCannotRead() throws {
        let alice = MeshCrypto.Identity()
        let bob = MeshCrypto.Identity()
        let eve = MeshCrypto.Identity()

        let session = try MeshCrypto.session(alice, peer: bob.publicIdentity)
        let sealed = try MeshCrypto.seal(
            Data("private".utf8), session: session, additionalData: Data())

        let eavesdrop = try MeshCrypto.session(eve, peer: bob.publicIdentity)
        #expect(throws: (any Error).self) {
            try MeshCrypto.open(sealed, session: eavesdrop, additionalData: Data())
        }
    }

    /// A fingerprint nobody will read out loud protects nobody.
    @Test("fingerprints are six lower-case characters")
    func fingerprints() {
        let identity = MeshCrypto.Identity()
        let fingerprint = identity.publicIdentity.fingerprint

        #expect(fingerprint.count == 6)
        #expect(fingerprint == fingerprint.lowercased())
        #expect(MeshCrypto.Identity().publicIdentity.fingerprint != fingerprint)
    }

    /// There is no account, so two identities minted moments apart must share nothing.
    @Test("identities are ephemeral and unlinkable")
    func ephemeral() {
        let first = MeshCrypto.Identity().publicIdentity
        let second = MeshCrypto.Identity().publicIdentity
        #expect(first.verify != second.verify)
        #expect(first.agree != second.agree)
    }
}

@Suite("Friend beacons")
struct BeaconTests {

    /// A constant identifier broadcast in a field is how early Bluetooth trackers became a
    /// stalking tool.
    @Test("tokens rotate, and a friend still recognises them")
    func tokensRotate() {
        let key = Data((0..<32).map { UInt8($0) })
        let window: UInt64 = 1_600_000_000 / 300

        let current = MeshCrypto.beaconToken(key: key, window: window)
        #expect(current != MeshCrypto.beaconToken(key: key, window: window + 1))
        #expect(current.count == 4)

        #expect(MeshCrypto.matchesBeacon(key: key, token: current, window: window))
        #expect(MeshCrypto.matchesBeacon(key: key, token: current, window: window + 1))
        #expect(MeshCrypto.matchesBeacon(key: key, token: current, window: window + 5) == false)

        let stranger = Data((0..<32).map { UInt8(255 - $0) })
        #expect(MeshCrypto.matchesBeacon(key: stranger, token: current, window: window) == false)
    }

    /// From `go test ./internal/meshcrypto`, so the two sides agree about the window
    /// encoding — big-endian, which is the easiest thing here to get backwards.
    @Test("the tokens match the box")
    func matchTheBox() {
        let key = Data((0..<32).map { UInt8($0) })
        #expect(hex(MeshCrypto.beaconToken(key: key, window: 0)) == "4224eca6")
        #expect(hex(MeshCrypto.beaconToken(key: key, window: 1)) == "69111813")
        #expect(hex(MeshCrypto.beaconToken(key: key, window: 1_000_000)) == "a575990f")
    }
}

@Suite("Base32")
struct Base32Tests {

    /// Matches Go's base32.StdEncoding with no padding, which is what the box uses for
    /// every identifier a human ever reads.
    @Test("matches Go's unpadded standard encoding")
    func matchesGo() {
        #expect(base32(Data([0x09, 0x68, 0xf3, 0xd2])) == "BFUPHUQ")
        #expect(base32(Data()) == "")
        #expect(base32(Data([0x00])) == "AA")
    }
}
