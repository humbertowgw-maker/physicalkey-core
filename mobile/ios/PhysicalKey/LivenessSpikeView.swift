import SwiftUI

// Debug-only entry point for the Phase 0 spike — deliberately not reachable from the real
// auth flow. See ContentView's toolbar (#if DEBUG) and the security-layers plan.
struct LivenessSpikeView: View {
    @StateObject private var audioTester = AudioLoopbackTester()
    @StateObject private var hapticTester = HapticMotionTester()
    @State private var audioError: String?
    @State private var hapticError: String?
    @State private var isRunningAudio = false
    @State private var isRunningHaptic = false

    var body: some View {
        Form {
            Section("Audio loopback") {
                Text(audioTester.status).font(.callout).foregroundStyle(.secondary)
                if let result = audioTester.lastResult {
                    resultRow(label: "Detected", value: result.detected ? "Yes" : "No", good: result.detected)
                    resultRow(label: "Signal / noise floor", value: String(format: "%.1fx", result.signalToNoiseRatio), good: result.detected)
                }
                if let audioError {
                    Text(audioError).font(.caption).foregroundStyle(.red)
                }
                Button {
                    Task {
                        isRunningAudio = true
                        audioError = nil
                        do { _ = try await audioTester.runLoopbackTest() }
                        catch { audioError = error.localizedDescription }
                        isRunningAudio = false
                    }
                } label: {
                    if isRunningAudio { ProgressView() } else { Text("Run audio loopback test") }
                }
                .disabled(isRunningAudio)
            }

            Section("Haptic + motion loopback") {
                Text(hapticTester.status).font(.callout).foregroundStyle(.secondary)
                if let result = hapticTester.lastResult {
                    resultRow(label: "Matched events", value: "\(result.matchedEvents)/\(result.totalEvents)", good: result.detected)
                }
                if let hapticError {
                    Text(hapticError).font(.caption).foregroundStyle(.red)
                }
                Button {
                    Task {
                        isRunningHaptic = true
                        hapticError = nil
                        do { _ = try await hapticTester.runHapticMotionTest() }
                        catch { hapticError = error.localizedDescription }
                        isRunningHaptic = false
                    }
                } label: {
                    if isRunningHaptic { ProgressView() } else { Text("Run haptic + motion test") }
                }
                .disabled(isRunningHaptic)
            }

            Section {
                Text("Hold the phone in your hand, off any soft/absorbent surface, for the haptic test. Run the audio test somewhere with normal room noise, not silent.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Liveness Spike")
    }

    private func resultRow(label: String, value: String, good: Bool) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(value).foregroundStyle(good ? .green : .red).bold()
        }
    }
}

#Preview {
    NavigationStack { LivenessSpikeView() }
}
