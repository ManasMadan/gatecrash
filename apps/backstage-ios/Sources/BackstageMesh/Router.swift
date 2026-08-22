import Foundation

/// The dedup filter and the relay decision.
///
/// A port of `internal/cuckoo` and `internal/mesh/router.go`. The hashing has to agree
/// with the Go side byte for byte — see §5 of `proto/backstage.md` — which is why every
/// constant is spelled out rather than taken from a library.
///
/// Not thread-safe. One radio, one queue, one router.

private let slotsPerBucket = 4
private let maxKicks = 500

/// SplitMix64's finaliser: a bijection that spreads every input bit across the word.
///
/// `&+` and `&*` throughout. Swift traps on overflow by default, and every one of these
/// operations is *supposed* to wrap — using the checked operators would give a crash
/// rather than a hash.
@inlinable
public func splitmix(_ value: UInt64) -> UInt64 {
    var x = value &+ 0x9e37_79b9_7f4a_7c15
    x = (x ^ (x >> 30)) &* 0xbf58_476d_1ce4_e5b9
    x = (x ^ (x >> 27)) &* 0x94d0_49bb_1331_11eb
    return x ^ (x >> 31)
}

/// FNV-1a, 64-bit, finished with a mixing step.
///
/// Written out rather than taken from a library for the same reason the Go side avoids
/// `hash/maphash`: anything with a per-process seed would give two phones different
/// fingerprints for the same message, and the filters would be incomparable.
@inlinable
public func fnv1a(_ data: Data) -> UInt64 {
    var hash: UInt64 = 14_695_981_039_346_656_037
    for byte in data {
        hash ^= UInt64(byte)
        hash = hash &* 1_099_511_628_211
    }
    // FNV-1a's low bits are weak, and the low bits are the bucket index.
    return splitmix(hash)
}

/// A cuckoo filter over 16-bit fingerprints.
///
/// A cuckoo filter rather than a bloom filter because entries have to expire, and bloom
/// filters cannot forget: a filter that fills up and starts refusing to remember new
/// messages is worse than no filter.
///
/// 16-bit fingerprints rather than the more common 8: a false positive here means a
/// message this phone has never seen is treated as already seen and never relayed. At
/// eight bits that is about 3% of messages, which in a protocol whose delivery guarantee
/// is "many paths, best effort" is a 3% tax on every hop.
public final class CuckooFilter {
    private var buckets: [[UInt16]]
    private let mask: UInt64
    public private(set) var count: Int = 0

    public init(capacity: Int) {
        var bucketCount = 1
        while bucketCount * slotsPerBucket < capacity { bucketCount <<= 1 }
        buckets = Array(repeating: Array(repeating: 0, count: slotsPerBucket), count: bucketCount)
        mask = UInt64(bucketCount - 1)
    }

    public var capacity: Int { buckets.count * slotsPerBucket }
    public var bytes: Int { buckets.count * slotsPerBucket * 2 }

    public func reset() {
        for index in buckets.indices {
            for slot in buckets[index].indices { buckets[index][slot] = 0 }
        }
        count = 0
    }

    public func contains(_ key: Data) -> Bool {
        let (fingerprint, first, second) = locate(key)
        return containsAt(first, fingerprint) || containsAt(second, fingerprint)
    }

    /// Returns false when the filter is full and the key could not be stored.
    @discardableResult
    public func insert(_ key: Data) -> Bool {
        var (fingerprint, first, second) = locate(key)

        if insertInto(first, fingerprint) || insertInto(second, fingerprint) {
            count += 1
            return true
        }

        // Both homes are full, so start evicting. The victim slot is derived rather than
        // random so two machines given the same inserts agree byte for byte — but it has
        // to vary with the kick count. Always evicting slot zero is reproducible and
        // useless: the chain falls into a two-position cycle and the filter reports itself
        // full at 73% occupancy rather than 95%.
        var index = second
        for kick in 0..<maxKicks {
            let slot = Int(splitmix(UInt64(kick) ^ UInt64(fingerprint)) % 4)
            let victim = buckets[Int(index)][slot]
            buckets[Int(index)][slot] = fingerprint
            fingerprint = victim

            index = alternate(index, fingerprint)
            if insertInto(index, fingerprint) {
                count += 1
                return true
            }
        }

        // The chain ran out and the fingerprint in hand is stored nowhere, so the filter
        // has lost one entry. Reported rather than hidden.
        count -= 1
        return false
    }

    private func insertInto(_ index: UInt64, _ fingerprint: UInt16) -> Bool {
        for slot in buckets[Int(index)].indices where buckets[Int(index)][slot] == 0 {
            buckets[Int(index)][slot] = fingerprint
            return true
        }
        return false
    }

    private func containsAt(_ index: UInt64, _ fingerprint: UInt16) -> Bool {
        buckets[Int(index)].contains(fingerprint)
    }

    private func locate(_ key: Data) -> (UInt16, UInt64, UInt64) {
        let hash = fnv1a(key)

        // The fingerprint comes from the high bits and the bucket index from the low ones,
        // so the two are uncorrelated. Zero is the empty-slot marker, so a fingerprint
        // that hashes to zero is nudged to one.
        var fingerprint = UInt16(truncatingIfNeeded: hash >> 48)
        if fingerprint == 0 { fingerprint = 1 }

        let first = hash & mask
        return (fingerprint, first, alternate(first, fingerprint))
    }

    /// The partial-key cuckoo trick: a fingerprint's second home is derived from its first
    /// and from the fingerprint itself, so a displaced entry can be re-homed without
    /// knowing the key it came from.
    ///
    /// The fingerprint is mixed before the xor. A bare `index ^ fingerprint` only ever
    /// changes the low sixteen bits, so with more than 65,536 buckets both homes land in
    /// the same neighbourhood and the load factor collapses.
    private func alternate(_ index: UInt64, _ fingerprint: UInt16) -> UInt64 {
        (index ^ splitmix(UInt64(fingerprint))) & mask
    }
}

/// A set of message ids that forgets anything older than its window.
///
/// Two generations rather than a timestamp per entry: on rotation the older one is
/// dropped wholesale, which is one reset rather than a scan.
public final class SeenSet {
    private var current: CuckooFilter
    private var previous: CuckooFilter
    private let windowMillis: Int64
    private var rotateAt: Int64
    private let now: () -> Int64

    public init(
        capacity: Int = 8192,
        windowMillis: Int64 = 10 * 60 * 1000,
        now: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }
    ) {
        current = CuckooFilter(capacity: capacity)
        previous = CuckooFilter(capacity: capacity)
        self.windowMillis = windowMillis
        self.now = now
        rotateAt = now() + windowMillis
    }

    public var bytes: Int { current.bytes + previous.bytes }
    public var count: Int { current.count + previous.count }
    public var loadFactor: Double {
        current.capacity == 0 ? 0 : Double(current.count) / Double(current.capacity)
    }

    /// Reports whether an id has been seen inside the window, and records it if not.
    public func seen(_ id: Data) -> Bool {
        maybeRotate()
        if current.contains(id) || previous.contains(id) { return true }
        // Deliberately ignoring a full filter: rotation is what recovers from one, and
        // risking a duplicate relay is a far better failure than refusing the message.
        current.insert(id)
        return false
    }

    /// Forgets everything, immediately.
    ///
    /// The panic wipe. Somebody triple-tapping in a crowd wants no trace of what their
    /// phone has heard, and the ids of messages they received are a trace.
    public func wipe() {
        current.reset()
        previous.reset()
        rotateAt = now() + windowMillis
    }

    private func maybeRotate() {
        let at = now()
        guard at >= rotateAt else { return }

        // A phone that was asleep for an hour comes back with several windows elapsed.
        // Both generations are stale, so both go.
        if at - rotateAt >= windowMillis {
            current.reset()
            previous.reset()
        } else {
            swap(&current, &previous)
            current.reset()
        }
        rotateAt = at + windowMillis
    }
}

public struct Decision: Equatable, Sendable {
    /// Try to decrypt this and show it.
    public var deliver: Bool = false
    /// Rebroadcast it, after `afterMillis`.
    public var relay: Bool = false
    public var hopped: Frame?
    public var afterMillis: Int64 = 0
    /// For the debug screen. Not for control flow.
    public var why: String = ""
}

public struct RouterStats: Sendable {
    public var heard = 0
    public var duplicate = 0
    public var delivered = 0
    public var relayed = 0
    public var suppressed = 0
    public var expired = 0
    public var malformed = 0
}

/// Decides what to do with every frame the radio hears.
///
/// Holds no keys and decrypts nothing. That separation is deliberate: this is the part
/// that has to be right under load, and mixing decryption in would make it impossible to
/// test the flooding behaviour without standing up a key for every peer.
public final class Router {
    /// The relay constant: the target number of nodes in any neighbourhood that
    /// rebroadcast a given message.
    ///
    /// Three, from `gatecrash-sim crowd -sweep`. At 500 phones in a hall that is 98.8%
    /// delivery; at 5,000 it is 99.4%, with airtime growing far slower than the crowd.
    private let k: Double
    private let ttl: UInt8
    private let neighborWindowMillis: Int64
    private let carryForMillis: Int64
    private let carryLimit: Int
    private let maxJitterMillis: Int64
    private let now: () -> Int64
    private let random: () -> Double

    private let seen: SeenSet
    private var neighbors: [String: Int64] = [:]
    private var carried: [(frame: Frame, at: Int64, seq: UInt64)] = []
    private var nextSeq: UInt64 = 0

    public private(set) var stats = RouterStats()

    public init(
        k: Double = 3,
        ttl: UInt8 = maxTTL,
        neighborWindowMillis: Int64 = 30_000,
        carryForMillis: Int64 = 2 * 60 * 1000,
        carryLimit: Int = 64,
        maxJitterMillis: Int64 = 250,
        now: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) },
        random: @escaping () -> Double = { Double.random(in: 0..<1) }
    ) {
        self.k = k
        self.ttl = ttl
        self.neighborWindowMillis = neighborWindowMillis
        self.carryForMillis = carryForMillis
        self.carryLimit = carryLimit
        self.maxJitterMillis = maxJitterMillis
        self.now = now
        self.random = random
        seen = SeenSet(now: now)
    }

    /// The current density estimate: distinct peers heard in the window.
    ///
    /// It undercounts a silent crowd — a hundred phones listening and not transmitting
    /// look like an empty field — and that failure is in the safe direction, because
    /// undercounting raises the relay probability.
    public func neighborCount() -> Int {
        sweepNeighbors()
        return neighbors.count
    }

    /// The chance this node rebroadcasts an ordinary frame right now.
    ///
    /// In a field of five people it is 1; in a pit of five hundred it is about 0.006, and
    /// the message still crosses the pit because there are five hundred phones each
    /// rolling that die.
    public func relayProbability() -> Double {
        let count = neighborCount()
        // A node that has heard nobody is either alone or at the edge of the crowd, and
        // the edge is exactly where a message needs carrying.
        guard count > 0 else { return 1 }
        return min(1, k / Double(count))
    }

    /// Records that a frame was heard from a peer.
    ///
    /// Called for every frame, including duplicates and frames that failed to decode. A
    /// collision is the strongest available evidence that the band is busy, so throwing it
    /// away would be exactly backwards — the Go simulator found that leaving it out made
    /// the density estimate stay at zero and the rule never engage.
    public func observe(_ peer: String) {
        guard !peer.isEmpty else { return }
        neighbors[peer] = now()
        sweepNeighbors()
    }

    public func handle(_ frame: Frame, from peer: String) -> Decision {
        stats.heard += 1
        observe(peer)

        if frame.version != protocolVersion {
            stats.malformed += 1
            return Decision(why: "unknown protocol version")
        }

        // Dedup before anything expensive. In a crowd a phone hears the same message from
        // a dozen neighbours, and every one of those is a decryption it should not pay for.
        if seen.seen(frame.dedupKey) {
            stats.duplicate += 1
            return Decision(why: "already seen")
        }

        stats.delivered += 1

        if !frame.kind.isRelayable {
            return Decision(deliver: true, why: "delivered; beacons are never relayed")
        }

        guard let hopped = frame.hop() else {
            stats.expired += 1
            return Decision(deliver: true, why: "delivered; hop limit reached")
        }

        // Organizer announcements ignore the density rule.
        if frame.isPriority {
            stats.relayed += 1
            carry(hopped)
            return Decision(
                deliver: true, relay: true, hopped: hopped,
                afterMillis: jitter(), why: "delivered and relayed at priority")
        }

        if random() < relayProbability() {
            stats.relayed += 1
            carry(hopped)
            return Decision(
                deliver: true, relay: true, hopped: hopped,
                afterMillis: jitter(), why: "delivered and relayed")
        }

        // Not relaying, but still worth carrying: walking into a cluster that has not
        // heard this delivers it there.
        stats.suppressed += 1
        carry(hopped)
        return Decision(deliver: true, why: "delivered; relay suppressed by density")
    }

    /// Prepares a frame this node is sending for the first time.
    public func originate(_ frame: Frame) -> Frame {
        var out = frame
        out.version = protocolVersion
        if out.ttl == 0 || out.ttl > ttl { out.ttl = ttl }
        // Recorded as seen straight away, so a copy that comes back from a neighbour is a
        // duplicate rather than a new message shown to its own sender.
        _ = seen.seen(out.dedupKey)
        carry(out)
        return out
    }

    /// Whether to push the store-and-forward buffer at a peer just met.
    ///
    /// Only in a sparse neighbourhood, and that restriction is load-bearing. Carrying
    /// exists to cross a gap between two clusters who never hear each other; in a dense
    /// crowd flooding already reaches everybody and the buffer adds nothing. The Go
    /// simulator measured the cost of ignoring that: with 500 phones in a hall, offering
    /// four frames to every peer met produced hundreds of thousands of extra
    /// transmissions — the storm the density rule exists to prevent, through a side door.
    public func shouldOfferCarry() -> Bool { Double(neighborCount()) < k }

    /// Frames worth offering to a peer that has just come into range, freshest first.
    public func carriedFrames() -> [Frame] {
        expireCarried()
        // Sorted by time and then by insertion order. Without the tiebreaker, frames added
        // within the same millisecond come back oldest-first — the opposite of what a peer
        // who may only be in range for two seconds needs.
        return carried
            .sorted { $0.at != $1.at ? $0.at > $1.at : $0.seq > $1.seq }
            .map(\.frame)
    }

    /// Forgets everything: seen ids, carried frames, and the density estimate.
    public func wipe() {
        seen.wipe()
        carried.removeAll()
        neighbors.removeAll()
    }

    private func jitter() -> Int64 { Int64(random() * Double(maxJitterMillis)) }

    private func carry(_ frame: Frame) {
        expireCarried()
        nextSeq += 1
        let at = now()

        // Replace an existing copy rather than holding two: the only thing that differs is
        // a TTL the receiver re-checks anyway.
        if let existing = carried.firstIndex(where: { $0.frame.id == frame.id }) {
            carried[existing] = (frame, at, nextSeq)
            return
        }

        carried.append((frame, at, nextSeq))
        while carried.count > carryLimit { carried.removeFirst() }
    }

    private func expireCarried() {
        let cutoff = now() - carryForMillis
        carried.removeAll { $0.at <= cutoff }
    }

    /// Drops peers not heard inside the window.
    ///
    /// On every observation rather than on a timer: the map is bounded by how many phones
    /// are in radio range, and a timer on a phone is a wakeup, which is battery.
    private func sweepNeighbors() {
        let cutoff = now() - neighborWindowMillis
        neighbors = neighbors.filter { $0.value >= cutoff }
    }
}
