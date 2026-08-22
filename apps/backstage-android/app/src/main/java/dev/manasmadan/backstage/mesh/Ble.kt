package dev.manasmadan.backstage.mesh

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * The radio under the mesh.
 *
 * Everything above this file — [Frame], [Router], the cuckoo filter — is pure logic
 * tested against Go conformance vectors. This is the part that cannot be: it talks to a
 * real Bluetooth stack whose behaviour differs between vendors, and no amount of unit
 * testing substitutes for two phones in a room. It is deliberately thin for that reason.
 * Anything that can be decided without a radio is decided in [Router].
 *
 * ## Why both roles at once
 *
 * Every phone runs as advertiser *and* scanner, central *and* peripheral. That is
 * unusual and it is the whole design: there is no server, no gateway and no phone with a
 * special job, so a node that can only scan is a node that cannot pass anything on. The
 * cost is that Android's peripheral role is the less-travelled path in every vendor's
 * stack, which is why [MeshRadio.isSupported] exists and why the UI says so plainly
 * rather than silently doing nothing.
 *
 * ## Why writes and not notifications
 *
 * A frame travels as a single GATT write to [FRAME_CHARACTERISTIC]. Notifications would
 * need a subscription per peer held open, which at festival density means dozens of
 * connections a phone cannot keep. A write is one connect, one write, one disconnect —
 * expensive per frame, but bounded, and 200-byte frames are rare enough that bounded
 * wins. [MAX_FRAME] is 200 bytes precisely so a frame fits one write on the 247-byte
 * default ATT MTU without negotiation.
 */
private const val TAG = "backstage.ble"

/**
 * The service UUID phones look for.
 *
 * Fixed, and the same for every event. Making it per-event would let anybody nearby
 * enumerate which festival a phone is at from its advertisement, which is exactly the
 * tracking property the rotating beacon tokens exist to avoid. Which channel a frame
 * belongs to is in the encrypted frame, not in the advertisement.
 */
val SERVICE_UUID: UUID = UUID.fromString("8f2a1b40-6c31-4a7e-9d55-0e1c7a5b3d21")

/** The characteristic a frame is written to. Write-only: there is nothing to read back. */
val FRAME_CHARACTERISTIC: UUID = UUID.fromString("8f2a1b41-6c31-4a7e-9d55-0e1c7a5b3d21")

/** How long a connection is given to deliver one frame before it is torn down. */
private const val WRITE_TIMEOUT_MILLIS = 8_000L

/**
 * How long to leave a just-used connection open.
 *
 * Reconnecting to the same peer costs roughly a second, and in a crowd the next frame
 * for a given neighbour usually arrives well inside that. Holding the connection briefly
 * turns a burst of frames into one connect instead of five.
 */
private const val LINGER_MILLIS = 5_000L

/**
 * How long a peer counts as in range after it was last heard from.
 *
 * Matches Router's neighbour window so that "in range" means one thing across the app.
 */
private const val PEER_WINDOW_MILLIS = 30_000L

/** A frame that arrived from a peer, with the peer's address for the density estimate. */
data class Inbound(val frame: Frame, val from: String)

/**
 * Wraps the platform Bluetooth stack in the two operations the mesh needs: shout a frame
 * at everybody in range, and be told when one arrives.
 *
 * Not thread-safe by accident: every callback the platform makes is bounced onto
 * [handler] so that [Router] — which is not thread-safe, and should not have to be — is
 * only ever touched from one thread.
 */
@SuppressLint("MissingPermission")
class MeshRadio(
    private val context: Context,
    private val router: Router,
    private val handler: Handler = Handler(Looper.getMainLooper()),
    private val onFrame: (Inbound) -> Unit,
    private val onNeighbours: (Int) -> Unit = {},
) {
    private val manager = context.getSystemService(BluetoothManager::class.java)
    private val adapter: BluetoothAdapter? = manager?.adapter

    private var gattServer: BluetoothGattServer? = null
    private var advertising = false
    private var scanning = false

    /** Live connections to peers, keyed by address, so a burst reuses one connect. */
    private val links = ConcurrentHashMap<String, Link>()

    /** Frames waiting for a link to come up, keyed by peer address. */
    private val pending = ConcurrentHashMap<String, MutableList<ByteArray>>()

    /**
     * Every peer seen recently, whether or not there is a connection to it.
     *
     * Kept separately from [links] because the two are not the same set and conflating
     * them was a bug: broadcasting to `links.keys` meant a frame this phone originated
     * reached only peers it already happened to have a connection to, which early on is
     * none of them. A phone would advertise, scan, see six neighbours and send nothing.
     * Broadcast has to mean "everybody in range", and connecting is how that gets done.
     */
    private val peers = ConcurrentHashMap<String, Long>()

    val isSupported: Boolean
        get() {
            val a = adapter ?: return false
            // Peripheral mode is the part that is missing on cheap handsets, and it is
            // the part without which this phone can only listen.
            return a.bluetoothLeAdvertiser != null && a.bluetoothLeScanner != null
        }

    val isEnabled: Boolean get() = adapter?.isEnabled == true

    /**
     * Starts advertising, scanning and the GATT server.
     *
     * Returns false when the radio is off or the phone cannot advertise, rather than
     * throwing: at a venue this is a normal state to be reported on screen, not an
     * exceptional one.
     */
    fun start(): Boolean {
        if (!isEnabled || !isSupported) return false
        startServer()
        startAdvertising()
        startScanning()
        return true
    }

    fun stop() {
        stopAdvertising()
        stopScanning()
        links.values.forEach { it.close() }
        links.clear()
        pending.clear()
        peers.clear()
        runCatching { gattServer?.close() }
        gattServer = null
    }

    /**
     * Sends a frame this phone is originating.
     *
     * The frame goes through [Router.originate] first so it is recorded as seen — without
     * that, the copy a neighbour relays back would be shown to its own author as a new
     * message.
     */
    fun send(frame: Frame) {
        val out = router.originate(frame)
        broadcast(out.encode())
    }

    /**
     * Writes a frame to every peer currently in range.
     *
     * "Broadcast" is a description of intent, not of mechanism: BLE has no way to write
     * to many peers at once, so this is a loop over connections. That is why the density
     * rule in [Router] matters so much — each relay decision it declines is a real
     * saving of connections, not just of airtime.
     */
    private fun broadcast(bytes: ByteArray) {
        prunePeers()
        if (peers.isEmpty()) return
        peers.keys.toList().forEach { address -> enqueue(address, bytes) }
    }

    /**
     * Forgets peers not seen for a while.
     *
     * Without this the set only grows, and a phone that walked the length of a festival
     * would try to connect to every stranger it passed all evening. The window matches
     * the one [Router] uses for its density estimate, so "in range" means the same thing
     * to both.
     */
    private fun prunePeers() {
        val cutoff = System.currentTimeMillis() - PEER_WINDOW_MILLIS
        peers.entries.removeAll { it.value < cutoff }
    }

    private fun enqueue(address: String, bytes: ByteArray) {
        val link = links[address]
        if (link != null && link.ready) {
            link.write(bytes)
            return
        }
        pending.getOrPut(address) { mutableListOf() }.add(bytes)
        if (link == null) connect(address)
    }

    // ---- advertising ----

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            advertising = true
        }

        override fun onStartFailure(errorCode: Int) {
            advertising = false
            // Logged rather than surfaced. ADVERTISE_FAILED_ALREADY_STARTED is routine
            // on a rotation, and the screen already reports whether peers are being
            // found, which is what the user can actually act on.
            Log.w(TAG, "advertising failed: $errorCode")
        }
    }

    private fun startAdvertising() {
        val advertiser = adapter?.bluetoothLeAdvertiser ?: return
        val settings = AdvertiseSettings.Builder()
            // Balanced, not low-latency. Low latency roughly doubles the advertising
            // rate for a marginal gain in discovery time and is the single fastest way
            // to flatten a phone's battery before the headline act.
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .setTimeout(0)
            .build()

        // The service UUID and nothing else. No device name: the default is often the
        // owner's real name, and putting that in a packet every phone in the field can
        // read would be a privacy leak in an app whose whole identity model is
        // ephemeral.
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        runCatching { advertiser.startAdvertising(settings, data, advertiseCallback) }
            .onFailure { Log.w(TAG, "could not start advertising", it) }
    }

    private fun stopAdvertising() {
        if (!advertising) return
        runCatching { adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
        advertising = false
    }

    // ---- scanning ----

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val address = result.device.address
            // Every sighting feeds the density estimate, whether or not a frame follows.
            // This is what makes the relay probability track the actual crowd rather
            // than the number of phones that happened to send something.
            peers[address] = System.currentTimeMillis()
            handler.post {
                router.observe(address)
                onNeighbours(router.neighborCount())
            }
            if (!links.containsKey(address)) {
                // Connect only when there is something to say, or when this phone is
                // sparse enough that the carry buffer is worth offering.
                if (router.shouldOfferCarry()) offerCarry(result.device)
            }
        }

        override fun onScanFailed(errorCode: Int) {
            scanning = false
            Log.w(TAG, "scan failed: $errorCode")
        }
    }

    private fun startScanning() {
        val scanner = adapter?.bluetoothLeScanner ?: return
        val filters = listOf(
            ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE_UUID)).build(),
        )
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .build()
        runCatching { scanner.startScan(filters, settings, scanCallback) }
            .onFailure { Log.w(TAG, "could not start scanning", it) }
        scanning = true
    }

    private fun stopScanning() {
        if (!scanning) return
        runCatching { adapter?.bluetoothLeScanner?.stopScan(scanCallback) }
        scanning = false
    }

    /**
     * Pushes the store-and-forward buffer at a peer just discovered.
     *
     * Gated by [Router.shouldOfferCarry] at the call site, for the reason documented
     * there: doing this unconditionally is a broadcast storm through a side door, and the
     * Go simulator measured exactly how bad.
     */
    private fun offerCarry(device: BluetoothDevice) {
        val frames = router.carriedFrames()
        if (frames.isEmpty()) return
        frames.forEach { enqueue(device.address, it.encode()) }
    }

    // ---- GATT server: receiving ----

    private fun startServer() {
        val callback = object : BluetoothGattServerCallback() {
            override fun onCharacteristicWriteRequest(
                device: BluetoothDevice,
                requestId: Int,
                characteristic: BluetoothGattCharacteristic,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray,
            ) {
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
                }
                if (characteristic.uuid != FRAME_CHARACTERISTIC) return
                receive(value, device.address)
            }

            override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    // A peer that connected to us is in range even if our own scan has
                    // not seen it yet, which happens when its advertisement is being
                    // drowned out but ours is not.
                    peers[device.address] = System.currentTimeMillis()
                    handler.post {
                        router.observe(device.address)
                        onNeighbours(router.neighborCount())
                    }
                }
            }
        }

        val server = manager?.openGattServer(context, callback) ?: return
        val characteristic = BluetoothGattCharacteristic(
            FRAME_CHARACTERISTIC,
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(characteristic)
        server.addService(service)
        gattServer = server
    }

    /**
     * Handles bytes that arrived over the radio.
     *
     * Decoding happens here and the decision comes from [Router], which is the whole
     * point of keeping them apart: the relay rule, the dedup filter and the hop limit are
     * the same code the Go simulator drives at five thousand nodes, and the same code the
     * conformance test checks byte for byte against the Swift port.
     */
    private fun receive(bytes: ByteArray, from: String) {
        val frame = try {
            Frame.decode(bytes)
        } catch (e: FrameError) {
            // Dropped silently and counted. A public radio channel carries other
            // people's traffic and the occasional corrupt packet, and neither is worth
            // a message on somebody's screen.
            Log.d(TAG, "dropped a malformed frame from $from: ${e.message}")
            return
        }

        handler.post {
            val decision = router.handle(frame, from)
            if (decision.deliver) onFrame(Inbound(frame, from))
            val hopped = decision.hopped
            if (decision.relay && hopped != null) {
                // Jittered, because the alternative is every phone that heard a frame
                // relaying it in the same millisecond and colliding.
                handler.postDelayed({ broadcast(hopped.encode()) }, decision.afterMillis)
            }
            onNeighbours(router.neighborCount())
        }
    }

    // ---- GATT client: sending ----

    private fun connect(address: String) {
        val device = runCatching { adapter?.getRemoteDevice(address) }.getOrNull() ?: return
        val link = Link(device)
        links[address] = link
        link.open()
    }

    /**
     * One connection to one peer.
     *
     * Its own class because a BLE connection has more states than a boolean and every one
     * of them can be reached by a peer walking out of range mid-write.
     */
    private inner class Link(private val device: BluetoothDevice) {
        private var gatt: BluetoothGatt? = null
        private var characteristic: BluetoothGattCharacteristic? = null
        @Volatile var ready = false
            private set

        private val timeout = Runnable {
            Log.d(TAG, "write to ${device.address} timed out")
            close()
        }

        private val closeAfterLinger = Runnable { close() }

        private val callback = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> g.discoverServices()
                    BluetoothProfile.STATE_DISCONNECTED -> close()
                }
            }

            override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    close()
                    return
                }
                characteristic = g.getService(SERVICE_UUID)?.getCharacteristic(FRAME_CHARACTERISTIC)
                if (characteristic == null) {
                    // Advertised the service but does not have the characteristic: not
                    // ours, or a stale cache. Either way there is nothing to write to.
                    close()
                    return
                }
                ready = true
                drain()
            }

            override fun onCharacteristicWrite(
                g: BluetoothGatt,
                c: BluetoothGattCharacteristic,
                status: Int,
            ) {
                handler.removeCallbacks(timeout)
                drain()
            }
        }

        fun open() {
            gatt = runCatching { device.connectGatt(context, false, callback) }.getOrNull()
            if (gatt == null) close()
        }

        fun write(bytes: ByteArray) {
            pending.getOrPut(device.address) { mutableListOf() }.add(bytes)
            drain()
        }

        /** Writes one queued frame, then waits for its completion before the next. */
        private fun drain() {
            if (!ready) return
            val g = gatt ?: return
            val c = characteristic ?: return
            val queue = pending[device.address]
            val next = queue?.removeFirstOrNull()
            if (next == null) {
                // Nothing left. Keep the connection briefly in case more follows, then
                // let it go: a phone cannot hold dozens of BLE links open.
                handler.removeCallbacks(closeAfterLinger)
                handler.postDelayed(closeAfterLinger, LINGER_MILLIS)
                return
            }
            handler.removeCallbacks(closeAfterLinger)
            handler.postDelayed(timeout, WRITE_TIMEOUT_MILLIS)

            val ok = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                g.writeCharacteristic(
                    c, next, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT,
                ) == BluetoothGatt.GATT_SUCCESS
            } else {
                @Suppress("DEPRECATION")
                run {
                    c.value = next
                    c.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                    g.writeCharacteristic(c)
                }
            }
            if (!ok) {
                handler.removeCallbacks(timeout)
                close()
            }
        }

        fun close() {
            ready = false
            handler.removeCallbacks(timeout)
            handler.removeCallbacks(closeAfterLinger)
            runCatching { gatt?.disconnect() }
            runCatching { gatt?.close() }
            gatt = null
            characteristic = null
            links.remove(device.address, this)
            // Anything still queued for this peer is dropped rather than held forever.
            // The carry buffer in Router is the store-and-forward mechanism; a per-link
            // queue that outlives its link is just a leak.
            pending.remove(device.address)
        }
    }
}
