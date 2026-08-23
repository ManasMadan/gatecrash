import Foundation

/// Argon2id, RFC 9106.
///
/// Needed because Backstage channel keys are derived from a passphrase with Argon2id, and
/// they have to match the ones the Go box derives byte for byte — a channel is only a
/// channel if everybody in it lands on the same key. CryptoKit has no Argon2, and the
/// spec is not negotiable, so it is implemented here.
///
/// Written for clarity over speed, and measured rather than assumed: **86.7 ms** per
/// derivation in a release build on an M-series Mac (`swift run -c release bench`), against
/// 12.6 ms for Go's assembly-optimised implementation. A mid-range phone will be several
/// times slower again, so budget a few hundred milliseconds.
///
/// That is acceptable because it runs once when somebody joins a channel, not per message
/// — and the memory cost is what carries the security anyway. 64 MiB per guess is what
/// turns a passphrase somebody says out loud at a campsite from seconds of cracking into
/// weeks, and unlike time it cannot be bought on a GPU.
///
/// A debug build takes about 4 seconds. Anything calling this from a UI thread should show
/// a spinner and mean it.
///
/// Parallelism is accepted as a parameter and the lanes are computed in sequence. The
/// output is identical either way — that is the point of the specification — and a
/// concurrent version would be faster for the attacker as much as for us.
public enum Argon2 {

    /// The variant. Only `id` is used here; the others exist because the version number is
    /// in the hash's own input and getting it wrong silently changes every output.
    public enum Variant: UInt32 {
        case d = 0
        case i = 1
        case id = 2
    }

    public enum Error: Swift.Error {
        case badParameters(String)
    }

    static let version: UInt32 = 0x13  // 1.3
    static let blockSize = 1024
    static let syncPoints = 4

    /// Derives a key.
    ///
    /// - Parameters:
    ///   - passphrase: the secret.
    ///   - salt: at least 8 bytes. Backstage derives it from the event and channel name
    ///     rather than randomising it — see §7 of proto/backstage.md for why that is the
    ///     opposite of what a password database should do and the only thing that works
    ///     with no infrastructure.
    ///   - iterations: `t`. One, for Backstage.
    ///   - memoryKiB: `m`. 65536, so 64 MiB.
    ///   - parallelism: `p`. Four.
    ///   - length: output bytes. 32, a ChaCha20-Poly1305 key.
    public static func id(
        passphrase: Data,
        salt: Data,
        iterations: UInt32 = 1,
        memoryKiB: UInt32 = 65536,
        parallelism: UInt32 = 4,
        length: Int = 32
    ) throws -> Data {
        try derive(
            variant: .id, passphrase: passphrase, salt: salt,
            iterations: iterations, memoryKiB: memoryKiB,
            parallelism: parallelism, length: length)
    }

    /// The initial hash, exposed so a port can be bisected one layer at a time.
    ///
    /// If this matches the reference and the final tag does not, the bug is in the
    /// compression function or the addressing rather than in the setup — which is a much
    /// smaller place to look.
    static func initialHashForTesting(
        passphrase: Data, salt: Data,
        iterations: UInt32, memoryKiB: UInt32, parallelism: UInt32,
        length: Int, variant: Variant
    ) -> Data {
        var input = Data()
        input.append(littleEndian32(parallelism))
        input.append(littleEndian32(UInt32(length)))
        input.append(littleEndian32(memoryKiB))
        input.append(littleEndian32(iterations))
        input.append(littleEndian32(version))
        input.append(littleEndian32(variant.rawValue))
        input.append(littleEndian32(UInt32(passphrase.count)))
        input.append(passphrase)
        input.append(littleEndian32(UInt32(salt.count)))
        input.append(salt)
        input.append(littleEndian32(0))
        input.append(littleEndian32(0))
        return Blake2b.hash(input, digestLength: 64)
    }

    /// The compression function, exposed for bisection. See initialHashForTesting.
    static func compressForTesting(_ x: [UInt64], _ y: [UInt64]) -> [UInt64] {
        var out = [UInt64](repeating: 0, count: blockSize / 8)
        compress(&out, x, y, xor: false)
        return out
    }

    static func wordsForTesting(_ data: Data) -> [UInt64] { words(from: data) }
    static func bytesForTesting(_ w: [UInt64]) -> Data { bytes(from: w) }

    static func derive(
        variant: Variant,
        passphrase: Data,
        salt: Data,
        iterations: UInt32,
        memoryKiB: UInt32,
        parallelism: UInt32,
        length: Int,
        secret: Data = Data(),
        associated: Data = Data()
    ) throws -> Data {
        guard parallelism >= 1 else { throw Error.badParameters("parallelism must be at least 1") }
        guard iterations >= 1 else { throw Error.badParameters("iterations must be at least 1") }
        guard salt.count >= 8 else { throw Error.badParameters("the salt must be at least 8 bytes") }
        guard length >= 4 else { throw Error.badParameters("the output must be at least 4 bytes") }
        guard memoryKiB >= 8 * parallelism else {
            throw Error.badParameters("memory must be at least 8 KiB per lane")
        }

        // The memory is rounded down to a multiple of 4*p blocks, which is what makes the
        // four sync points divide evenly into every lane.
        let blockCount = (memoryKiB / (UInt32(syncPoints) * parallelism))
            * (UInt32(syncPoints) * parallelism)
        let laneLength = Int(blockCount / parallelism)
        let segmentLength = laneLength / syncPoints

        // H0: everything that identifies this derivation, hashed together. Every parameter
        // is in here, which is why a mismatched memory cost produces a completely
        // different key rather than a slightly weaker one.
        var h0Input = Data()
        h0Input.append(littleEndian32(parallelism))
        h0Input.append(littleEndian32(UInt32(length)))
        h0Input.append(littleEndian32(memoryKiB))
        h0Input.append(littleEndian32(iterations))
        h0Input.append(littleEndian32(version))
        h0Input.append(littleEndian32(variant.rawValue))
        h0Input.append(littleEndian32(UInt32(passphrase.count)))
        h0Input.append(passphrase)
        h0Input.append(littleEndian32(UInt32(salt.count)))
        h0Input.append(salt)
        h0Input.append(littleEndian32(UInt32(secret.count)))
        h0Input.append(secret)
        h0Input.append(littleEndian32(UInt32(associated.count)))
        h0Input.append(associated)

        let h0 = Blake2b.hash(h0Input, digestLength: 64)

        // The memory: `blockCount` blocks of 1 KiB, as UInt64 words because that is the
        // width the compression function operates on.
        var memory = [[UInt64]](
            repeating: [UInt64](repeating: 0, count: blockSize / 8),
            count: Int(blockCount))

        // The first two blocks of every lane come straight from H0.
        for lane in 0..<Int(parallelism) {
            for index in 0..<2 {
                var input = h0
                input.append(littleEndian32(UInt32(index)))
                input.append(littleEndian32(UInt32(lane)))
                let block = argon2Hash(input, outputLength: blockSize)
                memory[lane * laneLength + index] = words(from: block)
            }
        }

        for pass in 0..<Int(iterations) {
            for slice in 0..<syncPoints {
                for lane in 0..<Int(parallelism) {
                    fill(
                        memory: &memory,
                        pass: pass, lane: lane, slice: slice,
                        laneLength: laneLength, segmentLength: segmentLength,
                        lanes: Int(parallelism), passes: Int(iterations),
                        variant: variant)
                }
            }
        }

        // The final block is the XOR of the last block of every lane.
        var final = memory[laneLength - 1]
        for lane in 1..<Int(parallelism) {
            let last = memory[lane * laneLength + laneLength - 1]
            for i in final.indices { final[i] ^= last[i] }
        }

        lastMemoryForTesting = memory
        return argon2Hash(bytes(from: final), outputLength: length)
    }

    /// The last derivation's memory, kept only so the conformance tests can compare block
    /// by block against the Go reference. Not thread-safe and not for production use;
    /// nothing outside the tests reads it.
    nonisolated(unsafe) static var lastMemoryForTesting: [[UInt64]] = []

    private static func fill(
        memory: inout [[UInt64]],
        pass: Int, lane: Int, slice: Int,
        laneLength: Int, segmentLength: Int,
        lanes: Int, passes: Int,
        variant: Variant
    ) {
        // The first pass's first slice already has two blocks, so it starts at index 2.
        var index = (pass == 0 && slice == 0) ? 2 : 0

        // Argon2id uses data-independent addressing for the first half of the first pass
        // and data-dependent addressing after that. That hybrid is the entire reason the
        // variant exists: independent addressing resists side-channel attacks, dependent
        // addressing resists time-memory tradeoffs, and Argon2id gets some of both.
        let dataIndependent =
            variant == .i || (variant == .id && pass == 0 && slice < syncPoints / 2)

        var addressBlock = [UInt64](repeating: 0, count: blockSize / 8)
        var inputBlock = [UInt64](repeating: 0, count: blockSize / 8)

        if dataIndependent {
            inputBlock[0] = UInt64(pass)
            inputBlock[1] = UInt64(lane)
            inputBlock[2] = UInt64(slice)
            inputBlock[3] = UInt64(memory.count)
            inputBlock[4] = UInt64(passes)
            inputBlock[5] = UInt64(variant.rawValue)
        }

        // The index the segment starts at, kept because the first segment of the first
        // pass starts at 2 rather than 0.
        //
        // That off-by-two is why the address block below is generated on
        // `index == startingIndex` as well as on every 128th position. Checking only
        // `index % 128 == 0` means the very first segment never generates one at all, so
        // every reference is taken from an all-zero block — which produces a hash that
        // looks perfectly random and matches nothing.
        let startingIndex = index

        while index < segmentLength {
            let current = lane * laneLength + slice * segmentLength + index
            let previous =
                current % laneLength == 0
                ? current + laneLength - 1
                : current - 1

            // The pseudo-random value that picks the reference block.
            var rand: UInt64
            if dataIndependent {
                if index % 128 == 0 || index == startingIndex {
                    inputBlock[6] &+= 1
                    // address = G(zero, G(zero, input)), which is how the addresses are
                    // generated without ever touching memory that depends on the
                    // passphrase — the property that makes Argon2i side-channel resistant.
                    let zero = [UInt64](repeating: 0, count: blockSize / 8)
                    var first = zero
                    compress(&first, zero, inputBlock, xor: false)
                    var second = zero
                    compress(&second, zero, first, xor: false)
                    addressBlock = second
                }
                rand = addressBlock[index % 128]
            } else {
                rand = memory[previous][0]
            }

            let refLane: Int =
                (pass == 0 && slice == 0) ? lane : Int(UInt32(truncatingIfNeeded: rand >> 32) % UInt32(lanes))

            let refIndex = referenceIndex(
                rand: UInt32(truncatingIfNeeded: rand),
                sameLane: refLane == lane,
                pass: pass, slice: slice, index: index,
                laneLength: laneLength, segmentLength: segmentLength)

            let reference = refLane * laneLength + refIndex

            // Computed into a local and then assigned, rather than
            // `compress(&memory[current], memory[previous], ...)`.
            //
            // That form passes inout access to `memory` while also reading two other
            // elements of it in the same call, which is overlapping access. Swift either
            // traps on it or silently copies, and which one you get depends on the
            // optimiser — the version here has one meaning.
            var next = compressed(memory[previous], memory[reference])

            // After the first pass the new block is XORed into the old one rather than
            // replacing it. Getting this backwards produces a plausible-looking hash that
            // matches nothing.
            if pass > 0 {
                let existing = memory[current]
                for i in next.indices { next[i] ^= existing[i] }
            }
            memory[current] = next

            index += 1
        }
    }

    /// Picks which earlier block to mix in, per RFC 9106 §3.4.1.1.
    ///
    /// The quadratic-looking arithmetic is deliberate and specified: it biases the
    /// selection towards recent blocks, which is what forces an attacker who wants to
    /// trade memory for time to recompute most of what they discarded.
    private static func referenceIndex(
        rand: UInt32, sameLane: Bool,
        pass: Int, slice: Int, index: Int,
        laneLength: Int, segmentLength: Int
    ) -> Int {
        var referenceAreaSize: Int
        if pass == 0 {
            if slice == 0 {
                referenceAreaSize = index - 1
            } else if sameLane {
                referenceAreaSize = slice * segmentLength + index - 1
            } else {
                referenceAreaSize = slice * segmentLength - (index == 0 ? 1 : 0)
            }
        } else {
            if sameLane {
                referenceAreaSize = laneLength - segmentLength + index - 1
            } else {
                referenceAreaSize = laneLength - segmentLength - (index == 0 ? 1 : 0)
            }
        }
        if referenceAreaSize < 1 { referenceAreaSize = 1 }

        // Parenthesised deliberately. Swift gives `>>` *higher* precedence than `*`, so
        // `a * a >> 32` parses as `a * (a >> 32)` — while in Go, C and the RFC's pseudocode
        // the shift and the multiply are the same precedence and it means `(a * a) >> 32`.
        //
        // Without the brackets this produced a hash that looked perfectly random, matched
        // nothing, and agreed with the reference for the first two slices — because the
        // data-independent addressing path does not reach this line.
        var relative = (UInt64(rand) &* UInt64(rand)) >> 32
        relative = UInt64(referenceAreaSize) - 1 - ((UInt64(referenceAreaSize) &* relative) >> 32)

        let start: Int =
            (pass != 0 && slice != syncPoints - 1) ? (slice + 1) * segmentLength : 0

        return (start + Int(relative)) % laneLength
    }

    /// The compression function, as a value. See the call site for why this shape.
    private static func compressed(_ x: [UInt64], _ y: [UInt64]) -> [UInt64] {
        var out = [UInt64](repeating: 0, count: blockSize / 8)
        compress(&out, x, y, xor: false)
        return out
    }

    /// The compression function G: BLAKE2b's round function applied to rows then columns
    /// of a 1 KiB block viewed as an 8x8 grid of 16-byte cells.
    private static func compress(
        _ out: inout [UInt64], _ x: [UInt64], _ y: [UInt64], xor: Bool
    ) {
        var r = [UInt64](repeating: 0, count: 128)
        for i in 0..<128 { r[i] = x[i] ^ y[i] }
        var z = r

        // Rows.
        for i in 0..<8 {
            let base = i * 16
            permute(&z, base, base + 1, base + 2, base + 3, base + 4, base + 5, base + 6, base + 7,
                    base + 8, base + 9, base + 10, base + 11, base + 12, base + 13, base + 14, base + 15)
        }
        // Columns.
        for i in 0..<8 {
            let o = i * 2
            permute(&z, o, o + 1, o + 16, o + 17, o + 32, o + 33, o + 48, o + 49,
                    o + 64, o + 65, o + 80, o + 81, o + 96, o + 97, o + 112, o + 113)
        }

        for i in 0..<128 {
            let value = z[i] ^ r[i]
            out[i] = xor ? out[i] ^ value : value
        }
    }

    /// One application of BLAKE2b's permutation to sixteen words.
    // swiftlint:disable:next function_parameter_count
    private static func permute(
        _ v: inout [UInt64],
        _ i0: Int, _ i1: Int, _ i2: Int, _ i3: Int, _ i4: Int, _ i5: Int, _ i6: Int, _ i7: Int,
        _ i8: Int, _ i9: Int, _ i10: Int, _ i11: Int, _ i12: Int, _ i13: Int, _ i14: Int, _ i15: Int
    ) {
        blamka(&v, i0, i4, i8, i12)
        blamka(&v, i1, i5, i9, i13)
        blamka(&v, i2, i6, i10, i14)
        blamka(&v, i3, i7, i11, i15)
        blamka(&v, i0, i5, i10, i15)
        blamka(&v, i1, i6, i11, i12)
        blamka(&v, i2, i7, i8, i13)
        blamka(&v, i3, i4, i9, i14)
    }

    /// Argon2's G, which is BLAKE2b's mixing function with the additions replaced by the
    /// "BlaMka" step: `a + b + 2*a_low*b_low`. The extra multiplication is what makes the
    /// function expensive on hardware that is cheap at addition, which is most of what
    /// makes Argon2 GPU-resistant.
    private static func blamka(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        v[a] = mul(v[a], v[b])
        v[d] = rotr(v[d] ^ v[a], 32)
        v[c] = mul(v[c], v[d])
        v[b] = rotr(v[b] ^ v[c], 24)
        v[a] = mul(v[a], v[b])
        v[d] = rotr(v[d] ^ v[a], 16)
        v[c] = mul(v[c], v[d])
        v[b] = rotr(v[b] ^ v[c], 63)
    }

    private static func mul(_ x: UInt64, _ y: UInt64) -> UInt64 {
        let low = UInt64(UInt32(truncatingIfNeeded: x)) &* UInt64(UInt32(truncatingIfNeeded: y))
        return x &+ y &+ (low &<< 1)
    }

    private static func rotr(_ value: UInt64, _ bits: UInt64) -> UInt64 {
        (value >> bits) | (value << (64 - bits))
    }

    private static func words(from data: Data) -> [UInt64] {
        let bytes = [UInt8](data)
        var out = [UInt64](repeating: 0, count: bytes.count / 8)
        for i in out.indices {
            var word: UInt64 = 0
            for j in 0..<8 { word |= UInt64(bytes[i * 8 + j]) << UInt64(j * 8) }
            out[i] = word
        }
        return out
    }

    private static func bytes(from words: [UInt64]) -> Data {
        var out = Data(capacity: words.count * 8)
        for word in words {
            for shift in stride(from: 0, to: 64, by: 8) {
                out.append(UInt8(truncatingIfNeeded: word >> UInt64(shift)))
            }
        }
        return out
    }
}
