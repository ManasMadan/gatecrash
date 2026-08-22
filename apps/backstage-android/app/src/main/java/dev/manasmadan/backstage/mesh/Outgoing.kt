package dev.manasmadan.backstage.mesh

/**
 * Builds the frames the UI sends.
 *
 * Separate from the UI, and with no Android imports, for one reason: it can then be
 * checked by `verify.sh` in CI alongside the rest of the protocol. The first version of
 * this logic lived inline in the activity and generated a 12-byte message id — the wire
 * format has an 8-byte id, so `Frame`'s own precondition would have thrown the first time
 * anybody pressed Send. It compiled perfectly. A runtime precondition on the app's
 * primary action is not something a build can catch, but a test can.
 */

/** The size of a message id on the wire. Not a tuning knob — see proto/backstage.md. */
const val ID_SIZE = 8

/**
 * A message to everybody in range.
 *
 * `urgent` sets the priority flag rather than choosing a different [Kind]. The wire format
 * has four kinds and adding a fifth would break both other implementations; the priority
 * flag already means exactly what an SOS needs — [Router] relays a priority frame
 * unconditionally instead of with probability k/n, so it crosses a saturated field while
 * ordinary chatter stays subject to the rule that prevents a broadcast storm.
 *
 * The body is truncated rather than rejected. 200 bytes is a protocol constant, and
 * silently dropping somebody's message because it was six characters too long is worse
 * than delivering the first 182 of it.
 */
fun chatFrame(body: String, urgent: Boolean, id: ByteArray): Frame {
    require(id.size == ID_SIZE) { "a message id is $ID_SIZE bytes, got ${id.size}" }
    val bytes = body.toByteArray()
    return Frame(
        kind = Kind.CHANNEL,
        flags = if (urgent) Flags.PRIORITY else 0,
        id = id,
        body = if (bytes.size > MAX_BODY) bytes.copyOf(MAX_BODY) else bytes,
    )
}
