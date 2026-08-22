import BackstageBLE
import BackstageMesh
import Foundation
import SwiftUI

/// Backstage: the crew radio that needs no radios.
///
/// One screen on purpose. This is used by somebody holding a torch in one hand at a gate,
/// and every extra tab is a thing to get lost in. What is on it: whether the mesh is
/// working, who is in range, what has been said, a box to say something, and an SOS.
///
/// ## Why this target is not built in CI
///
/// The views compile for macOS, and `swift build` checks them on every run. An installable
/// `.ipa` needs Xcode, an iOS SDK and a signing identity, none of which exist on a
/// command-line-tools machine — so the app is archived by hand. See README.md.
@main
struct BackstageApp: App {
    @StateObject private var mesh = MeshViewModel()

    var body: some Scene {
        WindowGroup {
            BackstageScreen(mesh: mesh)
                .onAppear { mesh.start() }
                // Dark only, and not as a style preference: this is read at night,
                // outdoors, by somebody whose eyes are adjusted to the dark. A white
                // screen at a gate ruins night vision for a minute, and that is a minute
                // of not seeing wristbands.
                .preferredColorScheme(.dark)
        }
    }
}

/// One line in the log.
struct Line: Identifiable {
    let id = UUID()
    let at: Date
    let text: String
    let mine: Bool
    let urgent: Bool
}

/// Holds the radio and the log.
///
/// `@MainActor` throughout, which is what lets it own a `Router`: the router is not
/// thread-safe and does not need to be, because `MeshRadio` is built to deliver every
/// callback on one queue. Declaring that here rather than hoping for it is the difference
/// between a data race and a compiler error.
@MainActor
final class MeshViewModel: ObservableObject {
    @Published var lines: [Line] = []
    @Published var neighbours = 0
    @Published var ready: Bool?

    private let router = Router()
    private var radio: MeshRadio?

    func start() {
        guard radio == nil else { return }
        let radio = MeshRadio(router: router) { [weak self] event in
            // The radio promises the callback queue, which is main by default; the hop is
            // spelled out so the actor isolation is checked rather than assumed.
            Task { @MainActor in self?.handle(event) }
        }
        self.radio = radio
        radio.start()
    }

    private func handle(_ event: MeshRadio.Event) {
        switch event {
        case .neighbours(let count):
            neighbours = count
        case .ready(let ok):
            ready = ok
        case .arrived(let frame, _):
            let body = String(decoding: frame.body)
            lines.append(
                Line(
                    at: Date(),
                    text: body.isEmpty ? "(\(frame.kind))" : body,
                    mine: false,
                    urgent: frame.isPriority
                )
            )
        }
    }

    func send(_ body: String, urgent: Bool) {
        var id = Data(count: idSize)
        // The system CSPRNG. A predictable message id would let somebody pre-insert ids
        // into the dedup filter and stop a message before it was ever sent.
        _ = id.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, idSize, buffer.baseAddress!)
        }
        radio?.send(chatFrame(body: body, urgent: urgent, id: id))
        lines.append(
            Line(at: Date(), text: urgent ? "SOS sent" : body, mine: true, urgent: urgent)
        )
    }
}

private extension String {
    /// Bytes off the wire are not guaranteed to be UTF-8, so a lossy decode rather than a
    /// failable one: showing the replacement character beats showing nothing.
    init(decoding data: Data) {
        self = String(decoding: data, as: UTF8.self)
    }
}

struct BackstageScreen: View {
    @ObservedObject var mesh: MeshViewModel
    @State private var draft = ""

    var body: some View {
        VStack(spacing: 0) {
            StatusBar(neighbours: mesh.neighbours, ready: mesh.ready)
            Divider().overlay(Color.white.opacity(0.08))
            Log(lines: mesh.lines)
            Composer(
                draft: $draft,
                onSend: {
                    let body = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !body.isEmpty else { return }
                    mesh.send(body, urgent: false)
                    draft = ""
                },
                // Fixed text, not the draft: an SOS is pressed by somebody without a
                // spare hand to type, and a blank one still says where they are.
                onSOS: { mesh.send("SOS — need help here", urgent: true) }
            )
        }
        .background(Color(red: 0.043, green: 0.043, blue: 0.059))
    }
}

private struct StatusBar: View {
    let neighbours: Int
    let ready: Bool?

    private var state: (Color, String) {
        switch (ready, neighbours) {
        case (false, _): (.red, "Bluetooth is off, or not permitted")
        case (nil, _): (.gray, "Starting…")
        case (_, 0): (.orange, "On — nobody in range yet")
        case (_, let count): (.green, "On — \(count) in range")
        }
    }

    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(state.0).frame(width: 10, height: 10)
            VStack(alignment: .leading, spacing: 1) {
                Text("Backstage").font(.system(size: 16, weight: .semibold))
                Text(state.1).font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}

private struct Log: View {
    let lines: [Line]

    var body: some View {
        if lines.isEmpty {
            Spacer()
            Text("Nothing yet.\nMessages from phones in range appear here.")
                .multilineTextAlignment(.center)
                .font(.system(size: 13))
                .foregroundStyle(.tertiary)
            Spacer()
        } else {
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(spacing: 6) {
                        ForEach(lines) { LineRow(line: $0) }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                }
                // The single-argument form, which exists on macOS 13 as well as 14. The
                // zero-argument overload is macOS 14 and up, and the package still
                // targets 13 so the protocol tests run on older machines.
                .onChange(of: lines.count) { _ in
                    guard let last = lines.last else { return }
                    withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
        }
    }
}

private struct LineRow: View {
    let line: Line

    private var background: Color {
        // Urgent traffic is coloured, not just labelled — the same reasoning as the
        // scanner's verdict screen: in a crowd, at night, text is what people cannot read.
        if line.urgent { return Color(red: 0.50, green: 0.11, blue: 0.11) }
        if line.mine { return Color(red: 0.12, green: 0.16, blue: 0.23) }
        return Color(red: 0.078, green: 0.078, blue: 0.106)
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(line.at, format: .dateTime.hour().minute())
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
            Text(line.text).font(.system(size: 14))
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(background, in: RoundedRectangle(cornerRadius: 10))
        .id(line.id)
    }
}

private struct Composer: View {
    @Binding var draft: String
    let onSend: () -> Void
    let onSOS: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            HStack(spacing: 8) {
                TextField("Say something to everyone nearby", text: $draft)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(onSend)
                Button("Send", action: onSend)
                    .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            // Full width and unmissable, because the moment it is needed is the moment
            // nobody is looking carefully.
            Button(action: onSOS) {
                Text("SOS")
                    .font(.system(size: 18, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity, minHeight: 52)
                    .background(Color(red: 0.86, green: 0.15, blue: 0.15),
                                in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
        }
        .padding(16)
    }
}
