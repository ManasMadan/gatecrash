import Foundation

/// The size of a message id on the wire. Not a tuning knob — see proto/backstage.md.
public let idSize = 8

/// Builds a message to everybody in range.
///
/// The mirror of `chatFrame` in the Kotlin port, and here for the same reason: it can be
/// tested without a radio. The Android version of this logic first lived inline in the
/// activity and generated a 12-byte id, which `Frame` rejects — it compiled, and would
/// have thrown the moment anybody pressed Send.
///
/// `urgent` sets the priority flag rather than choosing a different `Kind`. The wire
/// format has four kinds and adding a fifth would break the other two implementations;
/// the priority flag already means what an SOS needs — the router relays a priority frame
/// unconditionally instead of with probability k/n, so it crosses a saturated field while
/// ordinary chatter stays subject to the rule that prevents a broadcast storm.
///
/// The body is truncated rather than rejected. 200 bytes is a protocol constant, and
/// silently dropping a message for being six characters too long is worse than delivering
/// the first 182 of it.
public func chatFrame(body: String, urgent: Bool, id: Data) -> Frame {
    precondition(id.count == idSize, "a message id is \(idSize) bytes, got \(id.count)")
    let bytes = Data(body.utf8)
    return Frame(
        kind: .channel,
        flags: urgent ? .priority : [],
        id: id,
        body: bytes.count > maxBody ? bytes.prefix(maxBody) : bytes
    )
}
