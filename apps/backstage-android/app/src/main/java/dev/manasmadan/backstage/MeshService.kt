package dev.manasmadan.backstage

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder
import dev.manasmadan.backstage.mesh.Inbound
import dev.manasmadan.backstage.mesh.MeshRadio
import dev.manasmadan.backstage.mesh.Router

/**
 * Keeps the mesh alive while the phone is in a pocket.
 *
 * A foreground service rather than work tied to the activity, because the activity is
 * gone the moment somebody puts their phone away — which at a festival is most of the
 * evening. A mesh whose nodes only relay while their owner is looking at the screen has
 * almost no nodes.
 *
 * The visible notification is not a nuisance to be minimised. This app advertises over
 * Bluetooth continuously, and a persistent, dismissable-only-by-stopping notice is the
 * honest way to say so.
 */
class MeshService : Service() {

    private lateinit var radio: MeshRadio

    override fun onCreate() {
        super.onCreate()
        val state = MeshState.shared
        radio = MeshRadio(
            context = applicationContext,
            router = state.router,
            onFrame = { inbound: Inbound -> state.onInbound(inbound) },
            onNeighbours = { count -> state.onNeighbours(count) },
        )
        state.attach(radio)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, notification())
        // Reported rather than assumed: a phone that cannot advertise still runs the
        // service and still receives, and the screen says which of the two it is doing.
        MeshState.shared.onRadioStarted(radio.start())
        // Not sticky. If the system kills this to reclaim memory, silently restarting a
        // Bluetooth advertiser behind the user's back is the wrong default for an app
        // whose entire premise is that it does nothing you did not ask for.
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        radio.stop()
        MeshState.shared.detach()
        super.onDestroy()
    }

    /** Nothing binds to this: the shared state is [MeshState], not a binder. */
    override fun onBind(intent: Intent?): IBinder? = null

    private fun notification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Mesh",
                // Low: this is a status line, not an alert. Messages arriving is what
                // deserves attention, and that is the app's own business while open.
                NotificationManager.IMPORTANCE_LOW,
            )
            channel.description = "Shown while Backstage is relaying messages over Bluetooth."
            manager.createNotificationChannel(channel)
        }

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Backstage is on")
            .setContentText("Relaying messages nearby over Bluetooth")
            .setSmallIcon(R.drawable.ic_launcher)
            .setOngoing(true)
            .build()
    }

    private companion object {
        const val CHANNEL_ID = "mesh"
        const val NOTIFICATION_ID = 1
    }
}

/**
 * The one place the radio and the UI meet.
 *
 * A singleton, which is usually the wrong answer and is the right one here: there is
 * exactly one Bluetooth adapter and exactly one mesh, and the alternative is a binder
 * whose only job is to hand back the same object. [Router] is not thread-safe, so
 * everything that touches it arrives on the main thread — which is what [MeshRadio] is
 * built to guarantee.
 */
object MeshState {
    val shared: MeshState get() = this

    val router = Router()

    private var radio: MeshRadio? = null
    private val listeners = mutableListOf<(Event) -> Unit>()

    /** What the UI is told about. */
    sealed interface Event {
        data class Arrived(val inbound: Inbound) : Event
        data class Neighbours(val count: Int) : Event
        data class RadioStarted(val ok: Boolean) : Event
    }

    fun attach(r: MeshRadio) { radio = r }

    fun detach() { radio = null }

    val isRunning: Boolean get() = radio != null

    fun send(frame: dev.manasmadan.backstage.mesh.Frame) {
        radio?.send(frame)
    }

    fun observe(listener: (Event) -> Unit): () -> Unit {
        listeners.add(listener)
        return { listeners.remove(listener) }
    }

    fun onInbound(inbound: Inbound) = emit(Event.Arrived(inbound))

    fun onNeighbours(count: Int) = emit(Event.Neighbours(count))

    fun onRadioStarted(ok: Boolean) = emit(Event.RadioStarted(ok))

    private fun emit(event: Event) {
        // Copied before iterating: a listener that unsubscribes in response to an event
        // would otherwise mutate the list mid-loop.
        listeners.toList().forEach { it(event) }
    }
}
