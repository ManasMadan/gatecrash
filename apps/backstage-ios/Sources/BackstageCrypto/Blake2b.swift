import Foundation

/// BLAKE2b, RFC 7693.
///
/// Here because Argon2id needs it and CryptoKit does not have it. Nothing else in this
/// app uses BLAKE2b — the signatures are Ed25519 and the AEAD is ChaCha20-Poly1305, both
/// from CryptoKit — so this exists purely as Argon2's compression function.
///
/// The alternative was a C dependency. libsodium would give both BLAKE2b and Argon2id and
/// is well tested, and it would also mean a binary blob in the app bundle, a build step
/// that differs between the simulator and a device, and an App Store review conversation
/// about a bundled crypto library. Four hundred lines of Swift with published test
/// vectors is the smaller risk.
///
/// Verified against the RFC 7693 test vectors and, more importantly, by the channel key
/// it produces matching the one the Go box derives for the same passphrase.
struct Blake2b {

    /// The IV, which is the first 64 bits of the fractional parts of the square roots of
    /// the first eight primes — the same constants as SHA-512.
    private static let iv: [UInt64] = [
        0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
    ]

    /// The message permutation schedule, ten rounds of it. BLAKE2b does twelve rounds and
    /// the last two reuse the first two, which the round loop below relies on.
    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    private var h: [UInt64]
    private var buffer = [UInt8](repeating: 0, count: 128)
    private var bufferLength = 0
    private var counter: UInt64 = 0
    private let digestLength: Int

    /// - Parameters:
    ///   - digestLength: 1 to 64 bytes. Argon2 asks for several different lengths.
    ///   - key: the optional MAC key. Argon2 does not use it; it is here because leaving
    ///     it out would make this a different function from the one the vectors test.
    init(digestLength: Int, key: Data = Data()) {
        precondition(digestLength >= 1 && digestLength <= 64)
        precondition(key.count <= 64)

        self.digestLength = digestLength
        h = Blake2b.iv
        // The parameter block, folded into the first state word: digest length, key
        // length, fanout 1, depth 1.
        h[0] ^= UInt64(digestLength) | (UInt64(key.count) << 8) | (1 << 16) | (1 << 24)

        if !key.isEmpty {
            // A keyed hash starts with the key in a full, zero-padded block.
            var block = [UInt8](repeating: 0, count: 128)
            block.replaceSubrange(0..<key.count, with: key)
            update(Data(block))
        }
    }

    mutating func update(_ data: Data) {
        for byte in data {
            if bufferLength == 128 {
                counter &+= 128
                compress(last: false)
                bufferLength = 0
            }
            buffer[bufferLength] = byte
            bufferLength += 1
        }
    }

    mutating func finalize() -> Data {
        counter &+= UInt64(bufferLength)
        // The final block is zero-padded, and the padding must not be counted.
        for i in bufferLength..<128 { buffer[i] = 0 }
        compress(last: true)

        var out = Data(capacity: digestLength)
        for word in h {
            for shift in stride(from: 0, to: 64, by: 8) {
                if out.count == digestLength { return out }
                out.append(UInt8(truncatingIfNeeded: word >> UInt64(shift)))
            }
        }
        return out
    }

    static func hash(_ data: Data, digestLength: Int, key: Data = Data()) -> Data {
        var state = Blake2b(digestLength: digestLength, key: key)
        state.update(data)
        return state.finalize()
    }

    private mutating func compress(last: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            var word: UInt64 = 0
            for j in 0..<8 { word |= UInt64(buffer[i * 8 + j]) << UInt64(j * 8) }
            m[i] = word
        }

        var v = h + Blake2b.iv
        v[12] ^= counter
        // The high half of the 128-bit counter. This implementation never hashes 2^64
        // bytes, so v[13] stays zero — stated rather than silently omitted.
        if last { v[14] = ~v[14] }

        for round in 0..<12 {
            let s = Blake2b.sigma[round % 10]
            mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
    }

    /// The G function. `&+` throughout: every addition here is meant to wrap, and Swift's
    /// checked `+` would trap rather than hash.
    private func mix(
        _ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64
    ) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = rotr(v[d] ^ v[a], 32)
        v[c] = v[c] &+ v[d]
        v[b] = rotr(v[b] ^ v[c], 24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = rotr(v[d] ^ v[a], 16)
        v[c] = v[c] &+ v[d]
        v[b] = rotr(v[b] ^ v[c], 63)
    }

    private func rotr(_ value: UInt64, _ bits: UInt64) -> UInt64 {
        (value >> bits) | (value << (64 - bits))
    }
}

/// Argon2's variable-length hash, H'.
///
/// For outputs up to 64 bytes this is just BLAKE2b with the length prepended. Beyond
/// that it is a chain of 64-byte hashes where each takes the previous as input and only
/// the first 32 bytes of each are kept — which looks arbitrary and is exactly what
/// RFC 9106 specifies.
func argon2Hash(_ input: Data, outputLength: Int) -> Data {
    var prefixed = Data(capacity: 4 + input.count)
    prefixed.append(littleEndian32(UInt32(outputLength)))
    prefixed.append(input)

    if outputLength <= 64 {
        return Blake2b.hash(prefixed, digestLength: outputLength)
    }

    var out = Data()
    var block = Blake2b.hash(prefixed, digestLength: 64)
    out.append(block.prefix(32))

    var remaining = outputLength - 32
    while remaining > 64 {
        block = Blake2b.hash(block, digestLength: 64)
        out.append(block.prefix(32))
        remaining -= 32
    }

    out.append(Blake2b.hash(block, digestLength: remaining))
    return out
}

func littleEndian32(_ value: UInt32) -> Data {
    Data([
        UInt8(truncatingIfNeeded: value),
        UInt8(truncatingIfNeeded: value >> 8),
        UInt8(truncatingIfNeeded: value >> 16),
        UInt8(truncatingIfNeeded: value >> 24),
    ])
}
