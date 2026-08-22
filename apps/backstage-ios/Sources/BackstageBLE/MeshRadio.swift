import BackstageMesh
import CoreBluetooth
import Foundation

/// The radio under the mesh, on Apple platforms.
///
/// The counterpart to `mesh/Ble.kt`, and deliberately the same shape: everything that can
/// be decided without a radio is decided in `Router`, which is checked byte for byte
/// against the Go reference. This file is only the parts CoreBluetooth insists on.
///
/// ## Why a central and a peripheral at once
///
/// Every phone runs both roles. There is no server and no phone with a special job, so a
/// node that can only scan is a node that cannot pass anything on. On iOS this costs more
/// than on Android: a backgrounded app keeps its peripheral advertising only for the
/// service UUIDs in its Info.plist, and iOS strips the local name and rewrites the
/// advertisement — which is why discovery relies on the service UUID alone and nothing
/// else is put in the packet.
///
/// ## Why writes and not notifications
///
/// A frame is one GATT write to ``frameCharacteristicUUID``. Notifications would need a
/// subscription per peer held open, and at festival density that is more connections than
/// iOS will give an app. `maxFrame` is 200 bytes so a frame fits a single write without
/// MTU negotiation.
///
/// ## Threading
///
/// CoreBluetooth calls back on `queue`; everything that touches `Router` is hopped to
/// `callbackQueue` (the main queue by default). `Router` is not thread-safe and does not
/// need to be, which is the same arrangement the Kotlin port uses.
public final class MeshRadio: NSObject {

    /// The service UUID phones look for.
    ///
    /// Fixed, and the same for every event. A per-event UUID would let anybody nearby
    /// work out which festival a phone is at from its advertisement — the tracking
    /// property the rotating beacon tokens exist to avoid. Which channel a frame belongs
    /// to is inside the encrypted frame, not in the advertisement.
    ///
    /// Matches `SERVICE_UUID` in the Kotlin port. If these two ever differ, Android and
    /// iOS simply never see each other, and nothing anywhere reports an error.
    public static let serviceUUID = CBUUID(string: "8F2A1B40-6C31-4A7E-9D55-0E1C7A5B3D21")

    /// The characteristic a frame is written to. Write-only: nothing is read back.
    public static let frameCharacteristicUUID =
        CBUUID(string: "8F2A1B41-6C31-4A7E-9D55-0E1C7A5B3D21")

    /// How long a peer counts as in range after it was last heard from.
    ///
    /// Matches the router's neighbour window, so "in range" means one thing everywhere.
    private static let peerWindow: TimeInterval = 30

    /// What the app is told about.
    public enum Event: Sendable {
        /// A frame arrived and the router says to deliver it.
        case arrived(frame: Frame, from: String)
        /// The number of peers in range changed.
        case neighbours(Int)
        /// Bluetooth became usable, or did not.
        case ready(Bool)
    }

    private let router: Router
    private let queue: DispatchQueue
    private let callbackQueue: DispatchQueue
    private let onEvent: @Sendable (Event) -> Void

    private var central: CBCentralManager!
    private var peripheral: CBPeripheralManager!

    /// Peers seen recently, whether or not there is a connection to them.
    ///
    /// Kept apart from `links` on purpose. Broadcasting to only the peers already
    /// connected means a frame this phone originates reaches nobody early on, when there
    /// are no connections yet — a phone would advertise, scan, see six neighbours and
    /// send nothing. Broadcast has to mean "everybody in range"; connecting is how.
    private var peers: [String: Date] = [:]

    /// Discovered peripherals, kept because CoreBluetooth will not reconnect to one that
    /// has been released.
    private var known: [String: CBPeripheral] = [:]

    /// Connections that have found the characteristic and can be written to.
    private var links: [String: CBCharacteristic] = [:]

    /// Frames waiting for a link to come up, keyed by peer identifier.
    private var pending: [String: [Data]] = [:]

    private var writable: CBMutableCharacteristic?
    private var advertising = false

    public init(
        router: Router,
        queue: DispatchQueue = DispatchQueue(label: "dev.manasmadan.backstage.ble"),
        callbackQueue: DispatchQueue = .main,
        onEvent: @escaping @Sendable (Event) -> Void
    ) {
        self.router = router
        self.queue = queue
        self.callbackQueue = callbackQueue
        self.onEvent = onEvent
        super.init()
    }

    /// Brings the radio up.
    ///
    /// Both managers are created here rather than in `init` so that nothing prompts the
    /// user for Bluetooth permission until the app actually wants it. On iOS the
    /// permission sheet appears on first use of a manager, and a sheet at launch, before
    /// anything has been explained, is a sheet that gets declined.
    public func start() {
        central = CBCentralManager(delegate: self, queue: queue)
        peripheral = CBPeripheralManager(delegate: self, queue: queue)
    }

    public func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            if self.advertising {
                self.peripheral?.stopAdvertising()
                self.advertising = false
            }
            self.central?.stopScan()
            for peer in self.known.values where peer.state == .connected {
                self.central?.cancelPeripheralConnection(peer)
            }
            self.known.removeAll()
            self.links.removeAll()
            self.pending.removeAll()
            self.peers.removeAll()
        }
    }

    /// Sends a frame this phone is originating.
    ///
    /// Goes through `Router.originate` first so it is recorded as seen. Without that, the
    /// copy a neighbour relays back would be shown to its own author as a new message.
    public func send(_ frame: Frame) {
        queue.async { [weak self] in
            guard let self else { return }
            let out = self.router.originate(frame)
            guard let bytes = try? out.encode() else { return }
            self.broadcast(bytes)
        }
    }

    // MARK: - sending

    /// Writes a frame to every peer currently in range.
    ///
    /// "Broadcast" describes the intent, not the mechanism: BLE cannot write to many peers
    /// at once, so this is a loop. That is why the density rule in `Router` matters so
    /// much — every relay it declines saves a real connection, not just airtime.
    private func broadcast(_ bytes: Data) {
        prunePeers()
        for id in peers.keys { enqueue(bytes, to: id) }
    }

    private func enqueue(_ bytes: Data, to id: String) {
        if let characteristic = links[id], let peer = known[id], peer.state == .connected {
            peer.writeValue(bytes, for: characteristic, type: .withoutResponse)
            return
        }
        pending[id, default: []].append(bytes)
        if let peer = known[id], peer.state == .disconnected {
            central.connect(peer, options: nil)
        }
    }

    private func drain(_ id: String) {
        guard let characteristic = links[id], let peer = known[id] else { return }
        guard var queued = pending[id], !queued.isEmpty else { return }
        // Written without response: an acknowledged write costs a round trip per frame,
        // and the mesh already tolerates loss — that is what the relay and carry rules
        // are for. Reliability here would buy less than it costs.
        while !queued.isEmpty, peer.canSendWriteWithoutResponse {
            peer.writeValue(queued.removeFirst(), for: characteristic, type: .withoutResponse)
        }
        pending[id] = queued.isEmpty ? nil : queued
    }

    /// Forgets peers not seen for a while, so the set does not grow all evening.
    private func prunePeers() {
        let cutoff = Date().addingTimeInterval(-Self.peerWindow)
        peers = peers.filter { $0.value >= cutoff }
    }

    private func noteSeen(_ id: String) {
        peers[id] = Date()
        let count = router.neighborCount()
        emit(.neighbours(count))
    }

    private func emit(_ event: Event) {
        let handler = onEvent
        callbackQueue.async { handler(event) }
    }

    /// Handles bytes that arrived over the radio.
    ///
    /// Decoding happens here; the decision comes from `Router` — the same code the Go
    /// simulator drives at five thousand nodes and the same code the conformance tests
    /// check against the Kotlin port.
    private func receive(_ bytes: Data, from id: String) {
        let frame: Frame
        do {
            frame = try Frame.decode(bytes)
        } catch {
            // Dropped silently. A public radio channel carries other people's traffic and
            // the occasional corrupt packet, and neither is worth reporting.
            return
        }

        router.observe(id)
        let decision = router.handle(frame, from: id)
        if decision.deliver { emit(.arrived(frame: frame, from: id)) }

        if decision.relay, let hopped = decision.hopped, let out = try? hopped.encode() {
            // Jittered, or every phone that heard the frame relays in the same
            // millisecond and they collide.
            queue.asyncAfter(deadline: .now() + .milliseconds(Int(decision.afterMillis))) {
                [weak self] in self?.broadcast(out)
            }
        }
        emit(.neighbours(router.neighborCount()))
    }

    /// Pushes the store-and-forward buffer at a peer just met.
    ///
    /// Gated on `Router.shouldOfferCarry`, for the reason documented there: doing it
    /// unconditionally is a broadcast storm through a side door, and the Go simulator
    /// measured how bad.
    private func offerCarry(to id: String) {
        guard router.shouldOfferCarry() else { return }
        for frame in router.carriedFrames() {
            guard let bytes = try? frame.encode() else { continue }
            enqueue(bytes, to: id)
        }
    }
}

// MARK: - central: scanning and writing

extension MeshRadio: CBCentralManagerDelegate {

    public func centralManagerDidUpdateState(_ manager: CBCentralManager) {
        guard manager.state == .poweredOn else {
            emit(.ready(false))
            return
        }
        emit(.ready(true))
        // Duplicates are wanted: each sighting is evidence of a neighbour still being
        // there, which is what keeps the router's density estimate honest. Without this
        // flag iOS reports a peer once and the estimate decays to zero while the crowd
        // is still present.
        manager.scanForPeripherals(
            withServices: [Self.serviceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        )
    }

    public func centralManager(
        _ manager: CBCentralManager,
        didDiscover peer: CBPeripheral,
        advertisementData: [String: Any],
        rssi: NSNumber
    ) {
        let id = peer.identifier.uuidString
        known[id] = peer
        router.observe(id)
        noteSeen(id)

        if links[id] == nil, peer.state == .disconnected, router.shouldOfferCarry() {
            manager.connect(peer, options: nil)
        }
    }

    public func centralManager(_ manager: CBCentralManager, didConnect peer: CBPeripheral) {
        peer.delegate = self
        peer.discoverServices([Self.serviceUUID])
    }

    public func centralManager(
        _ manager: CBCentralManager,
        didDisconnectPeripheral peer: CBPeripheral,
        error: Error?
    ) {
        let id = peer.identifier.uuidString
        links[id] = nil
        // Anything still queued is dropped rather than held forever. The carry buffer in
        // Router is the store-and-forward mechanism; a per-link queue outliving its link
        // is just a leak.
        pending[id] = nil
    }

    public func centralManager(
        _ manager: CBCentralManager,
        didFailToConnect peer: CBPeripheral,
        error: Error?
    ) {
        let id = peer.identifier.uuidString
        links[id] = nil
        pending[id] = nil
    }
}

extension MeshRadio: CBPeripheralDelegate {

    public func peripheral(_ peer: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil, let service = peer.services?.first(where: {
            $0.uuid == Self.serviceUUID
        }) else {
            central.cancelPeripheralConnection(peer)
            return
        }
        peer.discoverCharacteristics([Self.frameCharacteristicUUID], for: service)
    }

    public func peripheral(
        _ peer: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: Error?
    ) {
        let id = peer.identifier.uuidString
        guard error == nil, let characteristic = service.characteristics?.first(where: {
            $0.uuid == Self.frameCharacteristicUUID
        }) else {
            // Advertised the service but has no characteristic: not ours, or a stale
            // cache. Either way there is nothing to write to.
            central.cancelPeripheralConnection(peer)
            return
        }
        links[id] = characteristic
        offerCarry(to: id)
        drain(id)
    }

    public func peripheralIsReady(toSendWriteWithoutResponse peer: CBPeripheral) {
        drain(peer.identifier.uuidString)
    }
}

// MARK: - peripheral: advertising and receiving

extension MeshRadio: CBPeripheralManagerDelegate {

    public func peripheralManagerDidUpdateState(_ manager: CBPeripheralManager) {
        guard manager.state == .poweredOn else { return }

        let characteristic = CBMutableCharacteristic(
            type: Self.frameCharacteristicUUID,
            properties: [.write, .writeWithoutResponse],
            value: nil,
            permissions: [.writeable]
        )
        let service = CBMutableService(type: Self.serviceUUID, primary: true)
        service.characteristics = [characteristic]
        writable = characteristic
        manager.add(service)
    }

    public func peripheralManager(
        _ manager: CBPeripheralManager,
        didAdd service: CBService,
        error: Error?
    ) {
        guard error == nil else { return }
        // The service UUID and nothing else. No local name: the default is often the
        // owner's real name, and putting that in a packet every phone in the field can
        // read would be a privacy leak in an app whose identity model is ephemeral.
        manager.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [Self.serviceUUID]])
        advertising = true
    }

    public func peripheralManager(
        _ manager: CBPeripheralManager,
        didReceiveWrite requests: [CBATTRequest]
    ) {
        for request in requests {
            guard request.characteristic.uuid == Self.frameCharacteristicUUID,
                  let value = request.value else { continue }
            let id = request.central.identifier.uuidString
            // A peer that wrote to us is in range even if our own scan has not seen it,
            // which happens when its advertisement is drowned out but ours is not.
            noteSeen(id)
            receive(value, from: id)
        }
        // Answered once for the batch. Only the first request needs a response; iOS
        // treats the whole batch as resolved by it.
        if let first = requests.first {
            manager.respond(to: first, withResult: .success)
        }
    }
}
