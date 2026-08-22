package dev.manasmadan.backstage

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.runtime.toMutableStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.manasmadan.backstage.mesh.ID_SIZE
import dev.manasmadan.backstage.mesh.chatFrame
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Backstage: the crew radio that needs no radios.
 *
 * One screen on purpose. This is used by somebody holding a torch in one hand at a gate,
 * and every extra tab is a thing to get lost in. What is on it: whether the mesh is
 * working, who is in range, what has been said, a box to say something, and an SOS.
 */
class MainActivity : ComponentActivity() {

    private val permissions = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { granted ->
        // Started only once the permissions are actually in hand. Starting the service
        // first would mean a foreground notification for a radio that cannot legally
        // scan, which looks like a working app that finds nobody.
        if (granted.values.all { it }) startMesh()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { BackstageTheme { BackstageScreen() } }
        requestWhatIsNeeded()
    }

    private fun requestWhatIsNeeded() {
        val wanted = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            wanted += Manifest.permission.BLUETOOTH_SCAN
            wanted += Manifest.permission.BLUETOOTH_ADVERTISE
            wanted += Manifest.permission.BLUETOOTH_CONNECT
        } else {
            // Below API 31 a BLE scan requires fine location and there is no way around
            // it. Above it, this is never asked for.
            wanted += Manifest.permission.ACCESS_FINE_LOCATION
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            wanted += Manifest.permission.POST_NOTIFICATIONS
        }
        permissions.launch(wanted.toTypedArray())
    }

    private fun startMesh() {
        startForegroundService(Intent(this, MeshService::class.java))
    }
}

@Composable
private fun BackstageTheme(content: @Composable () -> Unit) {
    // Dark only, and not as a style preference. This is read at night, outdoors, by
    // somebody whose eyes are adjusted to the dark; a white screen at a gate ruins night
    // vision for a minute, which is a minute of not seeing wristbands.
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Color(0xFF4ADE80),
            background = Color(0xFF0B0B0F),
            surface = Color(0xFF14141B),
            onBackground = Color(0xFFE7E7EA),
            onSurface = Color(0xFFE7E7EA),
        ),
        content = content,
    )
}

/** One line in the log. */
private data class Line(
    val at: Long,
    val text: String,
    val mine: Boolean,
    val urgent: Boolean,
)

@Composable
private fun BackstageScreen() {
    val lines = remember { mutableListOf<Line>().toMutableStateList() }
    var neighbours by remember { mutableIntStateOf(0) }
    var radioOk by remember { mutableStateOf<Boolean?>(null) }
    var draft by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    DisposableEffect(Unit) {
        val cancel = MeshState.shared.observe { event ->
            when (event) {
                is MeshState.Event.Neighbours -> neighbours = event.count
                is MeshState.Event.RadioStarted -> radioOk = event.ok
                is MeshState.Event.Arrived -> {
                    val frame = event.inbound.frame
                    // Shown as text. The frames on the wire are encrypted with the
                    // channel key when a channel has been joined; an unkeyed build shows
                    // what arrived, which is what makes two phones in a room testable.
                    lines += Line(
                        at = System.currentTimeMillis(),
                        text = String(frame.body).ifBlank { "(${frame.kind})" },
                        mine = false,
                        urgent = frame.isPriority,
                    )
                }
            }
        }
        onDispose { cancel() }
    }

    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.animateScrollToItem(lines.size - 1)
    }

    Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
        ) {
            StatusBar(neighbours = neighbours, radioOk = radioOk)
            Spacer(Modifier.height(8.dp))
            Log(lines = lines, listState = listState, modifier = Modifier.weight(1f))
            Composer(
                draft = draft,
                onDraft = { draft = it },
                onSend = {
                    val body = draft.trim()
                    if (body.isNotEmpty()) {
                        send(body, urgent = false)
                        lines += Line(System.currentTimeMillis(), body, mine = true, urgent = false)
                        draft = ""
                    }
                },
                onSos = {
                    // Fixed text, not the draft. An SOS is pressed by somebody who does
                    // not have a spare hand to type, and a blank one still says where.
                    send("SOS — need help here", urgent = true)
                    lines += Line(System.currentTimeMillis(), "SOS sent", mine = true, urgent = true)
                },
            )
        }
    }
}

/**
 * Sends a message into the mesh.
 *
 * The frame itself is built by [chatFrame], which lives in the mesh package with no
 * Android imports so that CI can check it. This function is only the wiring.
 */
private fun send(body: String, urgent: Boolean) {
    val id = ByteArray(ID_SIZE)
    SecureRandom().nextBytes(id)
    MeshState.shared.send(chatFrame(body, urgent = urgent, id = id))
}

@Composable
private fun StatusBar(neighbours: Int, radioOk: Boolean?) {
    val (dot, label) = when {
        radioOk == false -> Color(0xFFF87171) to "Bluetooth off, or this phone cannot advertise"
        radioOk == null -> Color(0xFF9CA3AF) to "Starting…"
        neighbours == 0 -> Color(0xFFFBBF24) to "On — nobody in range yet"
        else -> Color(0xFF4ADE80) to "On — $neighbours in range"
    }

    Row(
        Modifier.fillMaxWidth().padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(10.dp).background(dot, CircleShape))
        Spacer(Modifier.width(8.dp))
        Column {
            Text("Backstage", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
            Text(label, fontSize = 12.sp, color = Color(0xFF9CA3AF))
        }
    }
}

@Composable
private fun Log(
    lines: SnapshotStateList<Line>,
    listState: androidx.compose.foundation.lazy.LazyListState,
    modifier: Modifier = Modifier,
) {
    if (lines.isEmpty()) {
        Box(modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            Text(
                "Nothing yet.\nMessages from phones in range appear here.",
                color = Color(0xFF6B7280),
                fontSize = 13.sp,
            )
        }
        return
    }

    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        state = listState,
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        items(lines) { line -> LineRow(line) }
    }
}

@Composable
private fun LineRow(line: Line) {
    // Urgent traffic is coloured, not just labelled. The same reasoning as the scanner's
    // verdict screen: in a crowd, at night, text is the thing people cannot read.
    val background = when {
        line.urgent -> Color(0xFF7F1D1D)
        line.mine -> Color(0xFF1E293B)
        else -> MaterialTheme.colorScheme.surface
    }
    val clock = remember { SimpleDateFormat("HH:mm", Locale.getDefault()) }

    Surface(color = background, shape = RoundedCornerShape(10.dp)) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Text(
                clock.format(Date(line.at)),
                color = Color(0xFF9CA3AF),
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
            )
            Spacer(Modifier.width(10.dp))
            Text(line.text, fontSize = 14.sp, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun Composer(
    draft: String,
    onDraft: (String) -> Unit,
    onSend: () -> Unit,
    onSos: () -> Unit,
) {
    Column(Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = draft,
                onValueChange = onDraft,
                placeholder = { Text("Say something to everyone nearby") },
                singleLine = true,
                modifier = Modifier.weight(1f),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                keyboardActions = KeyboardActions(onSend = { onSend() }),
            )
            Spacer(Modifier.width(8.dp))
            Button(onClick = onSend, enabled = draft.isNotBlank()) { Text("Send") }
        }

        Spacer(Modifier.height(10.dp))

        // Full width and unmissable, because the moment it is needed is the moment
        // nobody is looking carefully.
        Button(
            onClick = onSos,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
            shape = RoundedCornerShape(12.dp),
        ) {
            Text("SOS", fontWeight = FontWeight.Bold, fontSize = 18.sp, color = Color.White)
        }
    }
}
