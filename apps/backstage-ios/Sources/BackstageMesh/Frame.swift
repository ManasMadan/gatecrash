import Foundation

/// The Backstage frame, byte for byte.
///
/// A port of `internal/mesh/frame.go`, and a port rather than a reimplementation on
/// purpose: `proto/backstage.md` is the contract, and where this file and the Go one
/// disagree, one of them is a message that never arrives.
///
/// Nothing in this module imports CoreBluetooth. That separation is what lets the whole
/// protocol be tested with `swift test` on a Mac with no device attached, which matters
/// because the radio is where debugging is slowest — arriving there with an
/// already-verified protocol is the difference between one bug and an indistinguishable
/// pile of them.

/// Protocol version, in every frame's first byte.
///
/// Named `protocolVersion` rather than `version` because `Frame` has a `version`
/// property: inside a static method on `Frame` the bare name resolves to the instance
/// member and the compiler rejects it, which is a confusing error for a correct idea.
public let protocolVersion: UInt8 = 1

/// The fixed header.
public let headerSize = 18

/// The largest frame the protocol will produce.
///
/// Not 255, which is what a BLE extended advertisement can carry. The number that
/// matters is what a five-year-old Android phone and an iPhone will both reliably
/// transmit in one advertisement without falling back to a connection, and in the field
/// that is closer to 200.
public let maxFrame = 200

/// How much payload fits in one frame.
public let maxBody = maxFrame - headerSize

/// The hop limit. Six hops of 10–30m BLE is a couple of hundred metres of crowd.
public let maxTTL: UInt8 = 6

/// A body over `maxBody` is split; at most 16 pieces, so just under 3 KB.
public let maxFragments = 16

public enum Kind: UInt8, Sendable {
    case channel = 1
    case direct = 2
    case announcement = 3

    /// A friend-finder token, and the one kind that is never relayed. The feature works
    /// by hearing a token directly; a relayed one means walking towards somebody three
    /// hops away.
    case beacon = 4

    public var isRelayable: Bool { self != .beacon }
}

public struct Flags: OptionSet, Sendable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// Relays unconditionally, ignoring the density rule. Only for organizer
    /// announcements — a priority bit anybody could set is a broadcast storm anybody
    /// could start.
    public static let priority = Flags(rawValue: 1 << 0)

    /// One piece of a fragmented message.
    public static let fragment = Flags(rawValue: 1 << 1)

    /// Entered the mesh from a venue box rather than a phone.
    public static let boxOrigin = Flags(rawValue: 1 << 2)
}

/// Why a frame was rejected. Every one of these is normal in a crowd.
public enum FrameError: Error, Equatable, Sendable {
    case tooShort
    case tooLong
    case badVersion
    case badTTL
    case badKind
    case badFragment
    case tooManyFragments(needed: Int)
}

public struct Frame: Equatable, Sendable {
    public var version: UInt8
    public var kind: Kind
    public var flags: Flags
    public var ttl: UInt8
    /// Identifies the message, not the frame: every copy carries the same id, which is
    /// what makes dedup possible.
    public var id: Data
    /// Zero unless this is a channel frame. In the clear so a phone knows which of its
    /// keys to try instead of trying all of them.
    public var channel: Data
    public var fragmentIndex: UInt8
    public var fragmentTotal: UInt8
    public var body: Data

    public init(
        version: UInt8 = protocolVersion,
        kind: Kind,
        flags: Flags = [],
        ttl: UInt8 = maxTTL,
        id: Data,
        channel: Data = Data(repeating: 0, count: 4),
        fragmentIndex: UInt8 = 0,
        fragmentTotal: UInt8 = 0,
        body: Data = Data()
    ) {
        precondition(id.count == 8, "a message id is 8 bytes, got \(id.count)")
        precondition(channel.count == 4, "a channel id is 4 bytes, got \(channel.count)")
        self.version = version
        self.kind = kind
        self.flags = flags
        self.ttl = ttl
        self.id = id
        self.channel = channel
        self.fragmentIndex = fragmentIndex
        self.fragmentTotal = fragmentTotal
        self.body = body
    }

    public var isFragment: Bool { flags.contains(.fragment) }
    public var isPriority: Bool { flags.contains(.priority) }
    public var size: Int { headerSize + body.count }

    /// The dedup key.
    ///
    /// Not the message id alone for a fragment: every fragment shares the id, so a filter
    /// keyed on it would see fragment two as a duplicate of fragment one and the message
    /// would never arrive.
    public var dedupKey: Data {
        isFragment ? id + Data([fragmentIndex]) : id
    }

    public func encode() throws -> Data {
        if body.count > maxBody { throw FrameError.tooLong }
        if ttl > maxTTL { throw FrameError.badTTL }

        var out = Data(capacity: headerSize + body.count)
        out.append(version)
        out.append(kind.rawValue)
        out.append(flags.rawValue)
        out.append(ttl)
        out.append(id)
        out.append(channel)
        out.append(fragmentIndex)
        out.append(fragmentTotal)
        out.append(body)
        return out
    }

    /// The additional authenticated data: the header with the TTL zeroed.
    ///
    /// The most important function in the file. Every relay decrements the TTL, so a TTL
    /// inside the authenticated data would mean the frame failed to authenticate at the
    /// first hop — the message would travel exactly one hop and the protocol would not
    /// work at all.
    ///
    /// Everything else is covered, so a frame cannot be re-labelled into another channel,
    /// promoted to priority, or re-stitched into a different message without breaking its
    /// tag. §3 of proto/backstage.md states what that costs.
    public func aad() -> Data {
        var out = Data(capacity: headerSize)
        out.append(version)
        out.append(kind.rawValue)
        out.append(flags.rawValue)
        out.append(0)  // deliberately not the ttl
        out.append(id)
        out.append(channel)
        out.append(fragmentIndex)
        out.append(fragmentTotal)
        return out
    }

    /// A copy with the TTL decremented, or nil at the limit.
    ///
    /// A copy because the caller may still hold the original in its store-and-forward
    /// buffer, and a shared frame whose TTL changes underneath it is a bug that only
    /// shows up under load.
    public func hop() -> Frame? {
        guard ttl > 0 else { return nil }
        var out = self
        out.ttl = ttl - 1
        return out
    }

    /// The token in a beacon frame, or nil if this is not one.
    public func beaconToken() -> Data? {
        kind == .beacon && body.count == 4 ? body : nil
    }

    /// Parses a frame off the radio.
    ///
    /// Every field is validated here rather than at the point of use, because this is the
    /// boundary between "bytes some stranger transmitted" and the rest of the app, and a
    /// mesh is the one place where every peer is untrusted by construction.
    public static func decode(_ raw: Data) throws -> Frame {
        if raw.count < headerSize { throw FrameError.tooShort }
        if raw.count > maxFrame { throw FrameError.tooLong }

        // Data can be a slice with a non-zero start index, and indexing it by 0 then
        // traps. Re-based so the offsets below mean what they say.
        let bytes = [UInt8](raw)

        if bytes[0] != protocolVersion { throw FrameError.badVersion }
        guard let kind = Kind(rawValue: bytes[1]) else { throw FrameError.badKind }

        let flags = Flags(rawValue: bytes[2])
        let ttl = bytes[3]
        if ttl > maxTTL { throw FrameError.badTTL }

        let fragmentIndex = bytes[16]
        let fragmentTotal = bytes[17]

        // A fragment index at or past the total would index off the end of a reassembly
        // buffer, and a total of one is not a fragmentation.
        if flags.contains(.fragment) {
            if fragmentTotal < 2 || fragmentIndex >= fragmentTotal { throw FrameError.badFragment }
        } else if fragmentIndex != 0 || fragmentTotal != 0 {
            throw FrameError.badFragment
        }

        return Frame(
            version: bytes[0],
            kind: kind,
            flags: flags,
            ttl: ttl,
            id: Data(bytes[4..<12]),
            channel: Data(bytes[12..<16]),
            fragmentIndex: fragmentIndex,
            fragmentTotal: fragmentTotal,
            body: Data(bytes[headerSize...])
        )
    }

    /// Splits a message into frames.
    ///
    /// Every fragment carries the same message id, which is what makes the whole message
    /// propagate as one thing and be deduplicated as one thing. Giving each fragment its
    /// own id would flood sixteen independent messages whose reassembly depended on all
    /// sixteen taking the same path.
    public static func fragment(template: Frame, body: Data) throws -> [Frame] {
        if body.count <= maxBody {
            var out = template
            out.version = protocolVersion
            out.flags.remove(.fragment)
            out.fragmentIndex = 0
            out.fragmentTotal = 0
            out.body = body
            return [out]
        }

        let total = (body.count + maxBody - 1) / maxBody
        if total > maxFragments { throw FrameError.tooManyFragments(needed: total) }

        let bytes = [UInt8](body)
        return (0..<total).map { index in
            let start = index * maxBody
            let end = min(start + maxBody, bytes.count)
            var out = template
            out.version = protocolVersion
            out.flags.insert(.fragment)
            out.fragmentIndex = UInt8(index)
            out.fragmentTotal = UInt8(total)
            out.body = Data(bytes[start..<end])
            return out
        }
    }
}

/// Gathers fragments back into messages.
///
/// Bounded in both directions, because everything here arrives from strangers and an
/// unbounded reassembly buffer on a phone in a crowd is a way for one person to exhaust
/// everybody else's memory.
public final class Reassembler {
    private struct Partial {
        let total: Int
        var pieces: [Data?]
        let template: Frame
        let started: Int64
        var received: Int = 0
    }

    private var partial: [Data: Partial] = [:]
    /// Insertion order, so dropping the oldest is O(1) to find. A dictionary in Swift has
    /// no order at all, so it has to be tracked separately.
    private var order: [Data] = []

    private let timeoutMillis: Int64
    private let limit: Int
    private let now: () -> Int64

    public init(
        timeoutMillis: Int64 = 30_000,
        limit: Int = 32,
        now: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }
    ) {
        self.timeoutMillis = timeoutMillis
        self.limit = limit
        self.now = now
    }

    public var pending: Int {
        expire()
        return partial.count
    }

    /// Takes one frame and returns the complete message once the last piece arrives.
    ///
    /// An unfragmented frame completes immediately, which keeps callers from having to
    /// branch on whether a message was fragmented at all.
    public func accept(_ frame: Frame) throws -> Frame? {
        expire()
        if !frame.isFragment { return frame }

        if frame.fragmentTotal < 2 || Int(frame.fragmentTotal) > maxFragments {
            throw FrameError.badFragment
        }
        if frame.fragmentIndex >= frame.fragmentTotal { throw FrameError.badFragment }

        let key = frame.id
        if partial[key] == nil {
            if partial.count >= limit, let oldest = order.first {
                // Drop the oldest, not the newest: a buffer full of messages that never
                // completed should not stop one that might.
                partial.removeValue(forKey: oldest)
                order.removeFirst()
            }
            partial[key] = Partial(
                total: Int(frame.fragmentTotal),
                pieces: Array(repeating: nil, count: Int(frame.fragmentTotal)),
                template: frame,
                started: now()
            )
            order.append(key)
        }

        guard var entry = partial[key] else { return nil }

        // A fragment claiming a different total for the same id is either a bug or an
        // attempt to corrupt a reassembly in progress. Reject the piece rather than
        // resize the buffer.
        if entry.total != Int(frame.fragmentTotal) { throw FrameError.badFragment }
        if entry.pieces[Int(frame.fragmentIndex)] != nil { return nil }

        entry.pieces[Int(frame.fragmentIndex)] = frame.body
        entry.received += 1
        partial[key] = entry

        if entry.received < entry.total { return nil }

        partial.removeValue(forKey: key)
        order.removeAll { $0 == key }

        var body = Data()
        for piece in entry.pieces { body.append(piece ?? Data()) }

        var out = entry.template
        out.flags.remove(.fragment)
        out.fragmentIndex = 0
        out.fragmentTotal = 0
        out.body = body
        return out
    }

    /// Drops every partial message. Part of the panic wipe.
    public func wipe() {
        partial.removeAll()
        order.removeAll()
    }

    private func expire() {
        let cutoff = now() - timeoutMillis
        let stale = partial.filter { $0.value.started < cutoff }.map(\.key)
        for key in stale {
            partial.removeValue(forKey: key)
            order.removeAll { $0 == key }
        }
    }
}
