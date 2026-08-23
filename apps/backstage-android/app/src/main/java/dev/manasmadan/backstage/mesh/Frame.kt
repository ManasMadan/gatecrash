package dev.manasmadan.backstage.mesh

/**
 * The Backstage frame, byte for byte.
 *
 * This is a port of `internal/mesh/frame.go`, and it is a port rather than a
 * reimplementation on purpose: the specification in `proto/backstage.md` is the
 * contract, and where this file and the Go one disagree, one of them is a message that
 * never arrives.
 *
 * Nothing here touches Bluetooth. That separation is what lets the whole protocol be
 * tested on a laptop with no device attached, which matters because the radio is where
 * debugging is slowest and arriving there with an already-verified protocol is the
 * difference between one bug and an indistinguishable pile of them.
 */

/** Protocol version, in every frame's first byte. */
const val VERSION: Byte = 1

/** The fixed header. */
const val HEADER_SIZE = 18

/**
 * The largest frame the protocol will produce.
 *
 * Not 255, which is what a BLE extended advertisement can carry. The number that
 * matters is what a five-year-old Android phone and an iPhone will both reliably
 * transmit in one advertisement without falling back to a connection, and in the field
 * that is closer to 200.
 */
const val MAX_FRAME = 200

/** How much payload fits in one frame. */
const val MAX_BODY = MAX_FRAME - HEADER_SIZE

/**
 * The hop limit.
 *
 * BLE indoors is 10 to 30 metres, so six hops is a couple of hundred metres of crowd,
 * which covers a hall or a field. It also bounds how many frames one message can
 * generate.
 */
const val MAX_TTL: Int = 6

/** A body over this many bytes is split; at most 16 pieces, so just under 3 KB. */
const val MAX_FRAGMENTS = 16

enum class Kind(val value: Byte) {
    CHANNEL(1),
    DIRECT(2),
    ANNOUNCEMENT(3),

    /**
     * A friend-finder token, and the one kind that is never relayed. The feature works
     * by hearing a token directly; a relayed one means walking towards somebody three
     * hops away.
     */
    BEACON(4);

    val relayable: Boolean get() = this != BEACON

    companion object {
        fun from(value: Byte): Kind? = entries.firstOrNull { it.value == value }
    }
}

object Flags {
    /**
     * Relays unconditionally, ignoring the density rule.
     *
     * Only for organizer announcements. "Lost child at the mixer desk" has to cross a
     * saturated field, and that is also why the bit is not available to attendee
     * traffic: a priority flag anybody could set is a broadcast storm anybody could
     * start.
     */
    const val PRIORITY: Int = 1 shl 0

    /** One piece of a fragmented message. */
    const val FRAGMENT: Int = 1 shl 1

    /** Entered the mesh from a venue box rather than a phone. */
    const val BOX_ORIGIN: Int = 1 shl 2
}

/** Why a frame was rejected. Each of these is normal in a crowd, not exceptional. */
sealed class FrameError(message: String) : Exception(message) {
    data object TooShort : FrameError("shorter than a header")
    data object TooLong : FrameError("larger than the maximum frame")
    data object BadVersion : FrameError("unsupported protocol version")
    data object BadTtl : FrameError("ttl above the hop limit")
    data object BadKind : FrameError("unknown frame kind")
    data object BadFragment : FrameError("inconsistent fragment numbering")
}

data class Frame(
    val version: Byte = VERSION,
    val kind: Kind,
    val flags: Int = 0,
    val ttl: Int = MAX_TTL,
    val id: ByteArray,
    val channel: ByteArray = ByteArray(4),
    val fragmentIndex: Int = 0,
    val fragmentTotal: Int = 0,
    val body: ByteArray = ByteArray(0),
) {
    init {
        require(id.size == 8) { "a message id is 8 bytes, got ${id.size}" }
        require(channel.size == 4) { "a channel id is 4 bytes, got ${channel.size}" }
    }

    val isFragment: Boolean get() = flags and Flags.FRAGMENT != 0
    val isPriority: Boolean get() = flags and Flags.PRIORITY != 0
    val size: Int get() = HEADER_SIZE + body.size

    /**
     * The dedup key.
     *
     * Not the message id alone for a fragment: every fragment of a message shares the
     * id, so a filter keyed on it would see fragment two as a duplicate of fragment one
     * and the message would never arrive.
     */
    val dedupKey: ByteArray
        get() = if (!isFragment) id else id + fragmentIndex.toByte()

    fun encode(): ByteArray {
        if (body.size > MAX_BODY) throw FrameError.TooLong
        if (ttl > MAX_TTL || ttl < 0) throw FrameError.BadTtl

        val out = ByteArray(HEADER_SIZE + body.size)
        out[0] = version
        out[1] = kind.value
        out[2] = flags.toByte()
        out[3] = ttl.toByte()
        id.copyInto(out, 4)
        channel.copyInto(out, 12)
        out[16] = fragmentIndex.toByte()
        out[17] = fragmentTotal.toByte()
        body.copyInto(out, HEADER_SIZE)
        return out
    }

    /**
     * The additional authenticated data: the header with the TTL zeroed.
     *
     * This is the most important method in the file. Every relay decrements the TTL, so
     * a TTL inside the authenticated data would mean the frame failed to authenticate at
     * the first hop — the message would travel exactly one hop and the protocol would
     * not work at all.
     *
     * Everything else is covered, so a frame cannot be re-labelled into another channel,
     * promoted to priority, or re-stitched into a different message without breaking its
     * tag. See §3 of proto/backstage.md for what that costs.
     */
    fun aad(): ByteArray {
        val out = ByteArray(HEADER_SIZE)
        out[0] = version
        out[1] = kind.value
        out[2] = flags.toByte()
        out[3] = 0 // deliberately not the ttl
        id.copyInto(out, 4)
        channel.copyInto(out, 12)
        out[16] = fragmentIndex.toByte()
        out[17] = fragmentTotal.toByte()
        return out
    }

    /**
     * A copy with the TTL decremented, or null at the limit.
     *
     * A copy rather than a mutation because the caller may still hold the original for
     * its own store-and-forward buffer, and a shared frame whose TTL changes underneath
     * it is a bug that only shows up under load.
     */
    fun hop(): Frame? = if (ttl == 0) null else copy(ttl = ttl - 1)

    /** The token in a beacon frame, or null if this is not one. */
    fun beaconToken(): ByteArray? =
        if (kind == Kind.BEACON && body.size == 4) body.copyOf() else null

    // Data classes compare arrays by reference, which for a type whose whole purpose is
    // its bytes would be a quietly wrong equals. Spelled out instead.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Frame) return false
        return version == other.version &&
            kind == other.kind &&
            flags == other.flags &&
            ttl == other.ttl &&
            id.contentEquals(other.id) &&
            channel.contentEquals(other.channel) &&
            fragmentIndex == other.fragmentIndex &&
            fragmentTotal == other.fragmentTotal &&
            body.contentEquals(other.body)
    }

    override fun hashCode(): Int {
        var result = version.toInt()
        result = 31 * result + kind.hashCode()
        result = 31 * result + flags
        result = 31 * result + ttl
        result = 31 * result + id.contentHashCode()
        result = 31 * result + channel.contentHashCode()
        result = 31 * result + fragmentIndex
        result = 31 * result + fragmentTotal
        result = 31 * result + body.contentHashCode()
        return result
    }

    companion object {
        /**
         * Parses a frame off the radio.
         *
         * Every field is validated here rather than at the point of use, because this is
         * the boundary between "bytes some stranger transmitted" and the rest of the app,
         * and a mesh is the one place where every peer is untrusted by construction.
         */
        fun decode(raw: ByteArray): Frame {
            if (raw.size < HEADER_SIZE) throw FrameError.TooShort
            if (raw.size > MAX_FRAME) throw FrameError.TooLong
            if (raw[0] != VERSION) throw FrameError.BadVersion

            val kind = Kind.from(raw[1]) ?: throw FrameError.BadKind
            val flags = raw[2].toInt() and 0xff
            val ttl = raw[3].toInt() and 0xff
            if (ttl > MAX_TTL) throw FrameError.BadTtl

            val fragmentIndex = raw[16].toInt() and 0xff
            val fragmentTotal = raw[17].toInt() and 0xff

            // A fragment index at or past the total would index off the end of a
            // reassembly buffer, and a total of one is not a fragmentation.
            if (flags and Flags.FRAGMENT != 0) {
                if (fragmentTotal < 2 || fragmentIndex >= fragmentTotal) throw FrameError.BadFragment
            } else if (fragmentIndex != 0 || fragmentTotal != 0) {
                throw FrameError.BadFragment
            }

            return Frame(
                version = raw[0],
                kind = kind,
                flags = flags,
                ttl = ttl,
                id = raw.copyOfRange(4, 12),
                channel = raw.copyOfRange(12, 16),
                fragmentIndex = fragmentIndex,
                fragmentTotal = fragmentTotal,
                body = raw.copyOfRange(HEADER_SIZE, raw.size),
            )
        }

        /**
         * Splits a message into frames.
         *
         * Every fragment carries the same message id, which is what makes the whole
         * message propagate as one thing and be deduplicated as one thing. Giving each
         * fragment its own id would flood sixteen independent messages whose reassembly
         * depended on all sixteen taking the same path.
         */
        fun fragment(template: Frame, body: ByteArray): List<Frame> {
            if (body.size <= MAX_BODY) {
                return listOf(
                    template.copy(
                        version = VERSION,
                        body = body.copyOf(),
                        flags = template.flags and Flags.FRAGMENT.inv(),
                        fragmentIndex = 0,
                        fragmentTotal = 0,
                    ),
                )
            }

            val total = (body.size + MAX_BODY - 1) / MAX_BODY
            require(total <= MAX_FRAGMENTS) {
                "a message needs $total fragments and the protocol allows $MAX_FRAGMENTS"
            }

            return (0 until total).map { index ->
                val start = index * MAX_BODY
                val end = minOf(start + MAX_BODY, body.size)
                template.copy(
                    version = VERSION,
                    flags = template.flags or Flags.FRAGMENT,
                    fragmentIndex = index,
                    fragmentTotal = total,
                    body = body.copyOfRange(start, end),
                )
            }
        }
    }
}

/**
 * Gathers fragments back into messages.
 *
 * Bounded in both directions, because everything here arrives from strangers and an
 * unbounded reassembly buffer on a phone in a crowd is a way for one person to exhaust
 * everybody else's memory.
 */
class Reassembler(
    private val timeoutMillis: Long = 30_000,
    private val limit: Int = 32,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private class Partial(
        val total: Int,
        val pieces: Array<ByteArray?>,
        val template: Frame,
        val started: Long,
    ) {
        var received: Int = 0
    }

    // LinkedHashMap in insertion order, so dropping the oldest is the first entry.
    private val partial = LinkedHashMap<String, Partial>()

    val pending: Int get() { expire(); return partial.size }

    /**
     * Takes one frame and returns the complete message once the last piece arrives.
     *
     * An unfragmented frame completes immediately, which keeps callers from having to
     * branch on whether a message was fragmented at all.
     */
    fun accept(frame: Frame): Frame? {
        expire()
        if (!frame.isFragment) return frame

        if (frame.fragmentTotal < 2 || frame.fragmentTotal > MAX_FRAGMENTS) throw FrameError.BadFragment
        if (frame.fragmentIndex >= frame.fragmentTotal) throw FrameError.BadFragment

        val key = frame.id.joinToString("") { "%02x".format(it) }
        var entry = partial[key]
        if (entry == null) {
            if (partial.size >= limit) {
                // Drop the oldest, not the newest: a buffer full of messages that never
                // completed should not stop one that might.
                partial.remove(partial.keys.first())
            }
            entry = Partial(frame.fragmentTotal, arrayOfNulls(frame.fragmentTotal), frame, now())
            partial[key] = entry
        }

        // A fragment claiming a different total for the same id is either a bug or an
        // attempt to corrupt a reassembly in progress. Either way the safe answer is to
        // reject the piece rather than resize the buffer.
        if (entry.total != frame.fragmentTotal) throw FrameError.BadFragment
        if (entry.pieces[frame.fragmentIndex] != null) return null

        entry.pieces[frame.fragmentIndex] = frame.body.copyOf()
        entry.received++
        if (entry.received < entry.total) return null

        partial.remove(key)
        val body = ByteArray(entry.pieces.sumOf { it?.size ?: 0 })
        var offset = 0
        for (piece in entry.pieces) {
            piece?.copyInto(body, offset)
            offset += piece?.size ?: 0
        }

        return entry.template.copy(
            flags = entry.template.flags and Flags.FRAGMENT.inv(),
            fragmentIndex = 0,
            fragmentTotal = 0,
            body = body,
        )
    }

    /** Drops every partial message. Part of the panic wipe. */
    fun wipe() = partial.clear()

    private fun expire() {
        val cutoff = now() - timeoutMillis
        partial.entries.removeAll { it.value.started < cutoff }
    }
}
