import AVFoundation
import CoreHaptics
import CoreMotion

// Phase 0 spike (see the security-layers plan): can the phone reliably prove to itself
// that it just played a tone and heard it back, and fired a haptic pattern and felt it
// back? Deliberately isolated from AuthViewModel / the real auth flow — this only proves
// the sensing mechanics work on real hardware before anything gets wired into a session.

struct AudioLoopbackResult {
    let detected: Bool
    let targetMagnitude: Double
    let noiseFloorMagnitude: Double
    /// How many times louder the target frequency was during playback vs. the ambient
    /// baseline. The real signal, not a magic threshold, is what this number tells you.
    var signalToNoiseRatio: Double { noiseFloorMagnitude > 0 ? targetMagnitude / noiseFloorMagnitude : targetMagnitude }
}

/// Plain stdout so `devicectl device process launch --console` can stream results back to a
/// connected Mac in real time — @Published alone only reaches the on-screen UI.
private func spikeLog(_ tag: String, _ message: String) {
    print("[LivenessSpike][\(tag)] \(message)")
}

/// AVAudioEngine calls the tap block on its own internal real-time audio render thread, not the
/// main thread. Confirmed via an actual on-device crash log (pulled through `devicectl device
/// copy from --domain-type systemCrashLogs`, not guessed): the trap was
/// `swift_task_checkIsolatedSwift` -> `dispatch_assert_queue_fail` inside the tap closure.
/// A closure *literal written inside a method of an @MainActor class* is inferred MainActor-
/// isolated by Swift 6 by default, regardless of what it captures — installTap's block
/// parameter isn't marked @Sendable (it predates Swift concurrency), so nothing stops that
/// inference, and Swift's runtime deliberately traps the moment Core Audio invokes it from the
/// real-time thread instead of the main actor's. The fix is to type the closure explicitly as
/// @Sendable so Swift never infers MainActor isolation for it in the first place — which is
/// also why this accumulator has to be @unchecked Sendable: a @Sendable closure can only
/// capture Sendable state. Safe here because usage is strictly single-writer (only the live
/// tap touches it) then read-only after that tap is removed — never concurrent.
private final class FloatAccumulator: @unchecked Sendable {
    private(set) var samples: [Float] = []
    func append(_ buffer: UnsafeBufferPointer<Float>) { samples.append(contentsOf: buffer) }
}

/// A free function, not a method on the @MainActor tester — deliberately, so the closure it
/// returns is defined in a nonisolated context and its explicit @Sendable typing is the only
/// thing that determines its isolation, with nothing left for the compiler to infer.
private func tapBlock(into accumulator: FloatAccumulator) -> @Sendable (AVAudioPCMBuffer, AVAudioTime) -> Void {
    { buffer, _ in
        guard let channel = buffer.floatChannelData?[0] else { return }
        accumulator.append(UnsafeBufferPointer(start: channel, count: Int(buffer.frameLength)))
    }
}

@MainActor
final class AudioLoopbackTester: NSObject, ObservableObject {
    @Published var status = "Idle" {
        didSet { spikeLog("Audio", status) }
    }
    @Published var lastResult: AudioLoopbackResult?

    private let engine = AVAudioEngine()
    /// Near-ultrasonic — audible on a good ear but well above normal speech/ambient noise,
    /// so it's easy to isolate with Goertzel without needing a huge FFT.
    private let targetFrequency: Double = 18_500

    func requestMicPermission() async -> Bool {
        await withCheckedContinuation { continuation in
            AVAudioApplication.requestRecordPermission { granted in
                continuation.resume(returning: granted)
            }
        }
    }

    /// Plays `targetFrequency` for `duration` seconds while recording concurrently, then
    /// runs Goertzel on the captured input to see whether the tone actually made it back
    /// in through the mic — the whole point being iOS's default echo cancellation is
    /// designed to strip exactly this out, so this is the thing we don't know the answer to
    /// yet.
    ///
    /// The engine and input format are set up exactly once; each measurement phase gets its
    /// own tap (installed, sampled, removed) rather than sharing one tap across phases via a
    /// mid-stream flag — see FloatAccumulator's doc comment for why.
    func runLoopbackTest(duration: TimeInterval = 1.5) async throws -> AudioLoopbackResult {
        status = "Requesting mic permission…"
        guard await requestMicPermission() else {
            status = "Mic permission denied"
            throw LivenessSpikeError.permissionDenied
        }

        let session = AVAudioSession.sharedInstance()
        // .measurement mode asks iOS to disable AGC/echo-cancellation/noise-suppression —
        // exactly the processing that would otherwise cancel out our own played tone. This
        // is the untested assumption the whole spike exists to check. No .defaultToSpeaker —
        // that option is meant for .voiceChat-style modes and may not be valid alongside
        // .measurement.
        try session.setCategory(.playAndRecord, mode: .measurement, options: [])
        try session.setActive(true)

        let input = engine.inputNode
        let inputFormat = input.outputFormat(forBus: 0)
        guard inputFormat.sampleRate > 0, inputFormat.channelCount > 0 else {
            try? session.setActive(false)
            status = "Input format invalid — mic route not ready"
            throw LivenessSpikeError.invalidAudioFormat
        }
        let toneFormat = AVAudioFormat(standardFormatWithSampleRate: inputFormat.sampleRate, channels: 1)!

        let playerNode = AVAudioPlayerNode()
        engine.attach(playerNode)
        engine.connect(playerNode, to: engine.mainMixerNode, format: toneFormat)

        spikeLog("Audio", "step: engine.prepare()")
        engine.prepare()
        spikeLog("Audio", "step: engine.start()")
        try engine.start()
        spikeLog("Audio", "step: engine started ok, isRunning=\(engine.isRunning)")

        status = "Measuring ambient noise floor…"
        let noiseAccumulator = FloatAccumulator()
        input.installTap(onBus: 0, bufferSize: 2048, format: inputFormat, block: tapBlock(into: noiseAccumulator))
        try await Task.sleep(nanoseconds: 500_000_000)
        input.removeTap(onBus: 0)
        spikeLog("Audio", "step: ambient phase done, samples=\(noiseAccumulator.samples.count)")

        status = "Playing + recording tone at \(Int(targetFrequency)) Hz…"
        let signalAccumulator = FloatAccumulator()
        input.installTap(onBus: 0, bufferSize: 2048, format: inputFormat, block: tapBlock(into: signalAccumulator))
        playerNode.scheduleBuffer(toneBuffer(format: toneFormat, sampleRate: inputFormat.sampleRate, duration: duration), completionHandler: nil)
        playerNode.play()
        spikeLog("Audio", "step: tone playing, sleeping \(duration)s")
        try await Task.sleep(nanoseconds: UInt64(duration * 1_000_000_000))
        input.removeTap(onBus: 0)
        spikeLog("Audio", "step: tone phase done, samples=\(signalAccumulator.samples.count)")

        playerNode.stop()
        engine.disconnectNodeOutput(playerNode)
        engine.detach(playerNode)
        engine.stop()
        try? session.setActive(false)
        spikeLog("Audio", "step: teardown done, computing goertzel")

        let noiseSamples = noiseAccumulator.samples
        let signalSamples = signalAccumulator.samples
        let noiseFloor = goertzelMagnitude(samples: noiseSamples, targetFrequency: targetFrequency, sampleRate: inputFormat.sampleRate)
        let signal = goertzelMagnitude(samples: signalSamples, targetFrequency: targetFrequency, sampleRate: inputFormat.sampleRate)

        let ratio = noiseFloor > 0 ? signal / noiseFloor : signal
        let result = AudioLoopbackResult(detected: ratio > 3.0, targetMagnitude: signal, noiseFloorMagnitude: noiseFloor)
        status = result.detected
            ? "Detected — SNR \(String(format: "%.1f", ratio))x"
            : "Not detected — SNR only \(String(format: "%.1f", ratio))x (echo cancellation likely suppressed it)"
        spikeLog("Audio", "RESULT detected=\(result.detected) targetMagnitude=\(signal) noiseFloor=\(noiseFloor) snr=\(ratio)")
        lastResult = result
        return result
    }

    private func toneBuffer(format: AVAudioFormat, sampleRate: Double, duration: TimeInterval) -> AVAudioPCMBuffer {
        let frameCount = AVAudioFrameCount(sampleRate * duration)
        let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: frameCount)!
        buffer.frameLength = frameCount
        let data = buffer.floatChannelData![0]
        for frame in 0..<Int(frameCount) {
            data[frame] = Float(sin(2.0 * .pi * targetFrequency * Double(frame) / sampleRate)) * 0.8
        }
        return buffer
    }

    /// Goertzel: cheap way to measure the energy at exactly one known frequency, without
    /// running a full FFT — fine here since we're only ever checking for our own tone.
    private func goertzelMagnitude(samples: [Float], targetFrequency: Double, sampleRate: Double) -> Double {
        guard !samples.isEmpty else { return 0 }
        let n = samples.count
        let k = Int(0.5 + Double(n) * targetFrequency / sampleRate)
        let omega = 2.0 * .pi * Double(k) / Double(n)
        let coeff = 2.0 * cos(omega)
        var q0 = 0.0, q1 = 0.0, q2 = 0.0
        for sample in samples {
            q0 = coeff * q1 - q2 + Double(sample)
            q2 = q1
            q1 = q0
        }
        let real = q1 - q2 * cos(omega)
        let imag = q2 * sin(omega)
        return sqrt(real * real + imag * imag) / Double(n)
    }
}

enum LivenessSpikeError: LocalizedError {
    case permissionDenied
    case hapticsUnsupported
    case invalidAudioFormat

    var errorDescription: String? {
        switch self {
        case .permissionDenied: return "Microphone permission was denied."
        case .hapticsUnsupported: return "This device doesn't support haptics."
        case .invalidAudioFormat: return "The mic's input format wasn't ready yet — try again."
        }
    }
}

struct HapticMotionResult {
    let matchedEvents: Int
    let totalEvents: Int
    var detected: Bool { totalEvents > 0 && matchedEvents == totalEvents }
}

@MainActor
final class HapticMotionTester: NSObject, ObservableObject {
    @Published var status = "Idle" {
        didSet { spikeLog("Haptic", status) }
    }
    @Published var lastResult: HapticMotionResult?

    private var hapticEngine: CHHapticEngine?
    private let motionManager = CMMotionManager()
    private var motionSamples: [(t: TimeInterval, magnitude: Double)] = []
    private let start = DispatchTime.now()

    /// Derived (in the spike, fixed) pattern: three sharp taps at known offsets. In the real
    /// protocol this timing would come from HKDF(session nonce) — see the plan.
    private let eventOffsets: [TimeInterval] = [0.0, 0.35, 0.70]

    func runHapticMotionTest() async throws -> HapticMotionResult {
        guard CHHapticEngine.capabilitiesForHardware().supportsHaptics else {
            status = "Device doesn't support haptics"
            throw LivenessSpikeError.hapticsUnsupported
        }

        status = "Starting haptic engine…"
        let engine = try CHHapticEngine()
        hapticEngine = engine
        try await engine.start()

        motionSamples.removeAll()
        guard motionManager.isDeviceMotionAvailable else {
            status = "Device motion unavailable"
            return HapticMotionResult(matchedEvents: 0, totalEvents: eventOffsets.count)
        }

        motionManager.deviceMotionUpdateInterval = 1.0 / 100.0
        let t0 = DispatchTime.now()
        motionManager.startDeviceMotionUpdates(to: .main) { [weak self] motion, _ in
            guard let self, let motion else { return }
            let elapsed = Double(DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000_000
            let a = motion.userAcceleration
            let magnitude = sqrt(a.x * a.x + a.y * a.y + a.z * a.z)
            self.motionSamples.append((t: elapsed, magnitude: magnitude))
        }

        status = "Playing haptic pattern + sensing motion…"
        let events = try eventOffsets.map { offset in
            CHHapticEvent(eventType: .hapticTransient, parameters: [
                CHHapticEventParameter(parameterID: .hapticIntensity, value: 1.0),
                CHHapticEventParameter(parameterID: .hapticSharpness, value: 1.0)
            ], relativeTime: offset)
        }
        let pattern = try CHHapticPattern(events: events, parameters: [])
        let player = try engine.makePlayer(with: pattern)
        try player.start(atTime: 0)

        try await Task.sleep(nanoseconds: UInt64((eventOffsets.last! + 0.5) * 1_000_000_000))
        motionManager.stopDeviceMotionUpdates()
        try? await engine.stop()

        let matched = eventOffsets.filter { offset in
            motionSamples.contains { abs($0.t - offset) < 0.15 && $0.magnitude > 0.05 }
        }.count
        let peakMagnitude = motionSamples.map(\.magnitude).max() ?? 0

        let result = HapticMotionResult(matchedEvents: matched, totalEvents: eventOffsets.count)
        status = result.detected
            ? "Detected all \(matched)/\(eventOffsets.count) haptic events via motion"
            : "Only matched \(matched)/\(eventOffsets.count) — check phone isn't on a soft surface"
        spikeLog("Haptic", "RESULT matched=\(matched)/\(eventOffsets.count) sampleCount=\(motionSamples.count) peakMagnitude=\(peakMagnitude)")
        lastResult = result
        return result
    }
}
