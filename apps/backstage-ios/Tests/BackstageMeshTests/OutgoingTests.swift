import Foundation
import Testing

@testable import BackstageMesh

/// The frames the UI actually sends.
///
/// Here because the bug this catches is invisible to a compiler and fatal at runtime. The
/// Android version of this logic first built its message id as 12 bytes, and `Frame`
/// rejects anything but 8 — it compiled, installed, and would have thrown the moment
/// somebody pressed Send. A wire constant is the thing to assert rather than remember.
@Suite("the frames the UI sends")
struct OutgoingTests {

    private let id = Data([1, 2, 3, 4, 5, 6, 7, 8])

    @Test("a chat message is an unflagged channel frame")
    func chat() throws {
        let frame = chatFrame(body: "north gate is backing up", urgent: false, id: id)
        #expect(frame.kind == .channel)
        #expect(!frame.isPriority)
        #expect(try frame.encode().count == headerSize + 24)
    }

    @Test("an SOS is the same kind, carrying the priority flag")
    func sos() {
        let frame = chatFrame(body: "SOS", urgent: true, id: id)
        // Not a fifth Kind: the wire format has four, and adding one would break the Go
        // box and the Kotlin port at the same time.
        #expect(frame.kind == .channel)
        #expect(frame.isPriority)
    }

    @Test("the priority flag is what gets an SOS out of a saturated crowd")
    func priorityBeatsDensity() {
        // An ordinary frame relays with probability k/n. With 300 neighbours and a draw
        // of 0.99 that is a no; a priority frame ignores the rule entirely. This is the
        // property that makes an SOS worth having, so it is worth a test rather than a
        // comment.
        let router = Router(now: { 0 }, random: { 0.99 })
        for i in 0..<300 { router.observe("peer-\(i)") }

        let sos = chatFrame(body: "SOS", urgent: true, id: id)
        let chatter = chatFrame(body: "anyone seen the drummer", urgent: false, id: id)

        #expect(router.handle(sos, from: "peer-0").relay)
        #expect(!router.handle(chatter, from: "peer-1").relay)
    }

    @Test("an over-long body is truncated, not dropped")
    func truncates() throws {
        let frame = chatFrame(body: String(repeating: "x", count: maxBody + 40), urgent: false, id: id)
        #expect(frame.body.count == maxBody)
        #expect(try frame.encode().count == maxFrame)
    }
}
