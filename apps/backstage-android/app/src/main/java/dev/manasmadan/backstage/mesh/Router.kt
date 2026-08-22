package dev.manasmadan.backstage.mesh

import kotlin.math.min
import kotlin.random.Random

/**
 * The dedup filter and the relay decision.
 *
 * A port of `internal/cuckoo` and `internal/mesh/router.go`. The hashing has to agree
 * with the Go side byte for byte — see §5 of proto/backstage.md — which is why every
 * constant is spelled out rather than taken from a library.
 *
 * Not thread-safe. One radio, one coroutine, one router.
 */

// ---------------------------------------------------------------------------
// The dedup filter
// ---------------------------------------------------------------------------

private const val SLOTS_PER_BUCKET = 4
private const val MAX_KICKS = 500

/**
 * A cuckoo filter over 16-bit fingerprints.
 *
 * A cuckoo filter rather than a bloom filter because entries have to expire, and bloom
 * filters cannot forget. A filter that fills up and starts refusing to remember new
 * messages is worse than no filter at all.
 *
 * 16-bit fingerprints rather than the more common 8: a false positive here means a
 * message this phone has never seen is treated as already seen and never relayed. At
 * eight bits that happens to about 3% of messages, which in a protocol whose delivery
 * guarantee is "many paths, best effort" is a 3% tax on every hop.
 */
class CuckooFilter(capacity: Int) {
    private val buckets: Array<ShortArray>
    private val mask: ULong
    var size: Int = 0
        private set

    init {
        var count = 1
        while (count * SLOTS_PER_BUCKET < capacity) count = count shl 1
        buckets = Array(count) { ShortArray(SLOTS_PER_BUCKET) }
        mask = (count - 1).toULong()
    }

    val capacity: Int get() = buckets.size * SLOTS_PER_BUCKET
    val bytes: Int get() = buckets.size * SLOTS_PER_BUCKET * 2

    fun reset() {
        for (bucket in buckets) bucket.fill(0)
        size = 0
    }

    fun contains(key: ByteArray): Boolean {
        val (fingerprint, first, second) = locate(key)
        return containsAt(first, fingerprint) || containsAt(second, fingerprint)
    }

    /** Returns false when the filter is full and the key could not be stored. */
    fun insert(key: ByteArray): Boolean {
        var (fingerprint, first, second) = locate(key)

        if (insertInto(first, fingerprint) || insertInto(second, fingerprint)) {
            size++
            return true
        }

        // Both homes are full, so start evicting. The victim slot is derived rather than
        // random so two machines given the same inserts agree byte for byte — but it has
        // to vary with the kick count. Always evicting slot zero is reproducible and
        // useless: the chain falls into a two-position cycle and the filter reports
        // itself full at 73% occupancy rather than 95%.
        var index = second
        for (kick in 0 until MAX_KICKS) {
            val slot = (splitmix(kick.toULong() xor fingerprint.toULong()) % 4uL).toInt()
            val victim = buckets[index.toInt()][slot]
            buckets[index.toInt()][slot] = fingerprint
            fingerprint = victim

            index = alternate(index, fingerprint)
            if (insertInto(index, fingerprint)) {
                size++
                return true
            }
        }

        // The chain ran out and the fingerprint in hand is stored nowhere, so the filter
        // has lost one entry. Reported rather than hidden.
        size--
        return false
    }

    private fun insertInto(index: ULong, fingerprint: Short): Boolean {
        val bucket = buckets[index.toInt()]
        for (slot in bucket.indices) {
            if (bucket[slot] == 0.toShort()) {
                bucket[slot] = fingerprint
                return true
            }
        }
        return false
    }

    private fun containsAt(index: ULong, fingerprint: Short): Boolean =
        buckets[index.toInt()].any { it == fingerprint }

    private fun locate(key: ByteArray): Triple<Short, ULong, ULong> {
        val hash = fnv1a(key)

        // The fingerprint comes from the high bits and the bucket index from the low
        // ones, so the two are uncorrelated. Zero is the empty-slot marker, so a
        // fingerprint that hashes to zero is nudged to one.
        var fingerprint = (hash shr 48).toShort()
        if (fingerprint == 0.toShort()) fingerprint = 1

        val first = hash and mask
        return Triple(fingerprint, first, alternate(first, fingerprint))
    }

    /**
     * The partial-key cuckoo trick: a fingerprint's second home is derived from its
     * first and from the fingerprint itself, so a displaced entry can be re-homed
     * without knowing the key it came from.
     *
     * The fingerprint is mixed before the xor. A bare `index xor fingerprint` only ever
     * changes the low sixteen bits, so with more than 65,536 buckets both homes land in
     * the same neighbourhood and the load factor collapses.
     */
    private fun alternate(index: ULong, fingerprint: Short): ULong =
        (index xor splitmix(fingerprint.toULong() and 0xffffuL)) and mask
}

/**
 * FNV-1a, 64-bit, finished with a mixing step.
 *
 * Written out rather than taken from a library for the same reason the Go side does not
 * use `hash/maphash`: anything with a per-process seed would give two phones different
 * fingerprints for the same message, and the filters would be incomparable.
 */
internal fun fnv1a(data: ByteArray): ULong {
    var hash = 14695981039346656037uL
    for (byte in data) {
        hash = hash xor (byte.toULong() and 0xffuL)
        hash *= 1099511628211uL
    }
    // FNV-1a's low bits are weak and the low bits are the bucket index.
    return splitmix(hash)
}

/** SplitMix64's finaliser: a bijection that spreads every input bit across the word. */
internal fun splitmix(value: ULong): ULong {
    var x = value + 0x9e3779b97f4a7c15uL
    x = (x xor (x shr 30)) * 0xbf58476d1ce4e5b9uL
    x = (x xor (x shr 27)) * 0x94d049bb133111ebuL
    return x xor (x shr 31)
}

/**
 * A set of message ids that forgets anything older than its window.
 *
 * Two generations rather than a timestamp per entry: on rotation the older one is
 * dropped wholesale, which is one clear rather than a scan.
 */
class SeenSet(
    capacity: Int = 8192,
    private val windowMillis: Long = 10 * 60 * 1000,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private var current = CuckooFilter(capacity)
    private var previous = CuckooFilter(capacity)
    private var rotateAt = now() + windowMillis

    val bytes: Int get() = current.bytes + previous.bytes
    val size: Int get() = current.size + previous.size
    val loadFactor: Double
        get() = if (current.capacity == 0) 0.0 else current.size.toDouble() / current.capacity

    /** Reports whether an id has been seen inside the window, and records it if not. */
    fun seen(id: ByteArray): Boolean {
        maybeRotate()
        if (current.contains(id) || previous.contains(id)) return true
        // Deliberately ignoring a full filter: rotation is what recovers from one, and
        // risking a duplicate relay is a far better failure than refusing the message.
        current.insert(id)
        return false
    }

    /**
     * Forgets everything, immediately.
     *
     * The panic wipe. Somebody triple-tapping in a crowd wants no trace of what their
     * phone has heard, and the ids of messages they received are a trace.
     */
    fun wipe() {
        current.reset()
        previous.reset()
        rotateAt = now() + windowMillis
    }

    private fun maybeRotate() {
        val at = now()
        if (at < rotateAt) return

        // A phone that was asleep for an hour comes back with several windows elapsed.
        // Both generations are stale, so both go.
        if (at - rotateAt >= windowMillis) {
            current.reset()
            previous.reset()
        } else {
            val stale = previous
            previous = current
            current = stale
            current.reset()
        }
        rotateAt = at + windowMillis
    }
}

// ---------------------------------------------------------------------------
// The relay decision
// ---------------------------------------------------------------------------

data class Decision(
    /** Try to decrypt this and show it. */
    val deliver: Boolean = false,
    /** Rebroadcast it, after [afterMillis]. */
    val relay: Boolean = false,
    val hopped: Frame? = null,
    val afterMillis: Long = 0,
    /** For the debug screen. Not for control flow. */
    val why: String = "",
)

data class RouterStats(
    var heard: Int = 0,
    var duplicate: Int = 0,
    var delivered: Int = 0,
    var relayed: Int = 0,
    var suppressed: Int = 0,
    var expired: Int = 0,
    var malformed: Int = 0,
)

/**
 * Decides what to do with every frame the radio hears.
 *
 * Holds no keys and decrypts nothing. That separation is deliberate: this is the part
 * that has to be right under load, and mixing decryption in would make it impossible to
 * test the flooding behaviour without standing up a key for every peer.
 */
class Router(
    /**
     * The relay constant: the target number of nodes in any neighbourhood that
     * rebroadcast a given message.
     *
     * Three, from `gatecrash-sim crowd -sweep`. At 500 phones in a hall that is 98.8%
     * delivery; at 5,000 it is 99.4%, with airtime growing far slower than the crowd.
     */
    private val k: Double = 3.0,
    private val ttl: Int = MAX_TTL,
    private val neighborWindowMillis: Long = 30_000,
    private val carryForMillis: Long = 2 * 60 * 1000,
    private val carryLimit: Int = 64,
    private val maxJitterMillis: Long = 250,
    private val now: () -> Long = System::currentTimeMillis,
    private val random: () -> Double = { Random.nextDouble() },
) {
    private val seen = SeenSet(now = now)
    private val neighbors = LinkedHashMap<String, Long>()
    private val carried = ArrayList<Pair<Frame, Long>>()

    val stats = RouterStats()

    /**
     * The current density estimate: distinct peers heard in the window.
     *
     * It undercounts a silent crowd — a hundred phones listening and not transmitting
     * look like an empty field — and that failure is in the safe direction, because
     * undercounting raises the relay probability.
     */
    fun neighborCount(): Int {
        sweepNeighbors()
        return neighbors.size
    }

    /**
     * The chance this node rebroadcasts an ordinary frame right now.
     *
     * In a field of five people it is 1; in a pit of five hundred it is about 0.006, and
     * the message still crosses the pit because there are five hundred phones each
     * rolling that die.
     */
    fun relayProbability(): Double {
        val count = neighborCount()
        // A node that has heard nobody is either alone or at the edge of the crowd, and
        // the edge is exactly where a message needs carrying.
        if (count <= 0) return 1.0
        return min(1.0, k / count)
    }

    /**
     * Records that a frame was heard from a peer.
     *
     * Called for every frame, including duplicates and frames that failed to decode. A
     * collision is the strongest available evidence that the band is busy, so throwing
     * it away would be exactly backwards — the Go simulator found that leaving it out
     * made the density estimate stay at zero and the rule never engage.
     */
    fun observe(peer: String) {
        if (peer.isEmpty()) return
        neighbors[peer] = now()
        sweepNeighbors()
    }

    fun handle(frame: Frame, from: String): Decision {
        stats.heard++
        observe(from)

        if (frame.version != VERSION) {
            stats.malformed++
            return Decision(why = "unknown protocol version")
        }

        // Dedup before anything expensive. In a crowd a phone hears the same message from
        // a dozen neighbours, and every one of those is a decryption it should not pay
        // for.
        if (seen.seen(frame.dedupKey)) {
            stats.duplicate++
            return Decision(why = "already seen")
        }

        stats.delivered++

        if (!frame.kind.relayable) {
            return Decision(deliver = true, why = "delivered; ${frame.kind} frames are never relayed")
        }

        val hopped = frame.hop()
        if (hopped == null) {
            stats.expired++
            return Decision(deliver = true, why = "delivered; hop limit reached")
        }

        // Organizer announcements ignore the density rule.
        if (frame.isPriority) {
            stats.relayed++
            carry(hopped)
            return Decision(true, true, hopped, jitter(), "delivered and relayed at priority")
        }

        if (random() < relayProbability()) {
            stats.relayed++
            carry(hopped)
            return Decision(true, true, hopped, jitter(), "delivered and relayed")
        }

        // Not relaying, but still worth carrying: walking into a cluster that has not
        // heard this delivers it there.
        stats.suppressed++
        carry(hopped)
        return Decision(deliver = true, why = "delivered; relay suppressed by density")
    }

    /** Prepares a frame this node is sending for the first time. */
    fun originate(frame: Frame): Frame {
        val out = frame.copy(
            version = VERSION,
            ttl = if (frame.ttl == 0 || frame.ttl > ttl) ttl else frame.ttl,
        )
        // Recorded as seen straight away, so a copy that comes back from a neighbour is a
        // duplicate rather than a new message shown to its own sender.
        seen.seen(out.dedupKey)
        carry(out)
        return out
    }

    /**
     * Whether to push the store-and-forward buffer at a peer just met.
     *
     * Only in a sparse neighbourhood, and that restriction is load-bearing. Carrying
     * exists to cross a gap between two clusters who never hear each other; in a dense
     * crowd flooding already reaches everybody and the buffer adds nothing. The Go
     * simulator measured the cost of ignoring that: with 500 phones in a hall, offering
     * four frames to every peer met produced hundreds of thousands of extra
     * transmissions — the storm the density rule exists to prevent, through a side door.
     */
    fun shouldOfferCarry(): Boolean = neighborCount() < k

    /** Frames worth offering to a peer that has just come into range, freshest first. */
    fun carriedFrames(): List<Frame> {
        expireCarried()
        return carried.sortedByDescending { it.second }.map { it.first }
    }

    /** Forgets everything: seen ids, carried frames, and the density estimate. */
    fun wipe() {
        seen.wipe()
        carried.clear()
        neighbors.clear()
    }

    private fun jitter(): Long = (random() * maxJitterMillis).toLong()

    private fun carry(frame: Frame) {
        expireCarried()
        val at = now()

        // Replace an existing copy rather than holding two: the only thing that differs
        // is a TTL the receiver re-checks anyway.
        val existing = carried.indexOfFirst { it.first.id.contentEquals(frame.id) }
        if (existing >= 0) {
            carried[existing] = frame to at
            return
        }

        carried.add(frame to at)
        while (carried.size > carryLimit) carried.removeAt(0)
    }

    private fun expireCarried() {
        val cutoff = now() - carryForMillis
        carried.removeAll { it.second <= cutoff }
    }

    /**
     * Drops peers not heard inside the window.
     *
     * On every observation rather than on a timer: the map is bounded by how many phones
     * are in radio range, and a timer on a phone is a wakeup, which is battery.
     */
    private fun sweepNeighbors() {
        val cutoff = now() - neighborWindowMillis
        neighbors.entries.removeAll { it.value < cutoff }
    }
}
