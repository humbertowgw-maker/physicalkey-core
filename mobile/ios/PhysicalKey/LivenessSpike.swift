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

@MainActor
final class AudioLoopbackTester: NSObject, ObservableObject {
    @Published var status = "Idle"
    @Published var lastResult: AudioLoopbackResult?

    private let engine = AVAudioEngine()
    private var capturedSamples: [Float] = []
    private let sampleRate: Double = 44_100
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
    func runLoopbackTest(duration: TimeInterval = 1.5) async throws -> AudioLoopbackResult {
        status = "Requesting mic permission…"
        guard await requestMicPermission() else {
            status = "Mic permission denied"
            throw LivenessSpikeError.permissionDenied
        }

        let session = AVAudioSession.sharedInstance()
        // .measurement mode asks iOS to disable AGC/echo-cancellation/noise-suppression —
        // exactly the processing that would otherwise cancel out our own played tone. This
        // is the untested assumption the whole spike exists to check.
        try session.setCategory(.playAndRecord, mode: .measurement, options: [.defaultToSpeaker])
        try session.setActive(true)

        status = "Measuring ambient noise floor…"
        let noiseFloor = try await captureAndMeasure(playTone: false, duration: 0.5)

        status = "Playing + recording tone at \(Int(targetFrequency)) Hz…"
        let signal = try await captureAndMeasure(playTone: true, duration: duration)

        try? session.setActive(false)

        let ratio = noiseFloor > 0 ? signal / noiseFloor : signal
        let result = AudioLoopbackResult(detected: ratio > 3.0, targetMagnitude: signal, noiseFloorMagnitude: noiseFloor)
        status = result.detected
            ? "Detected — SNR \(String(format: "%.1f", ratio))x"
            : "Not detected — SNR only \(String(format: "%.1f", ratio))x (echo cancellation likely suppressed it)"
        lastResult = result
        return result
    }

    private func captureAndMeasure(playTone: Bool, duration: TimeInterval) async throws -> Double {
        capturedSamples.removeAll()
        let input = engine.inputNode
        let format = input.outputFormat(forBus: 0)

        input.installTap(onBus: 0, bufferSize: 2048, format: format) { [weak self] buffer, _ in
            guard let self, let channel = buffer.floatChannelData?[0] else { return }
            self.capturedSamples.append(contentsOf: UnsafeBufferPointer(start: channel, count: Int(buffer.frameLength)))
        }

        var playerNode: AVAudioPlayerNode?
        if playTone {
            let node = AVAudioPlayerNode()
            engine.attach(node)
            engine.connect(node, to: engine.mainMixerNode, format: toneBuffer().format)
            playerNode = node
        }

        try engine.start()
        if let playerNode {
            playerNode.scheduleBuffer(toneBuffer(duration: duration), completionHandler: nil)
            playerNode.play()
        }

        try await Task.sleep(nanoseconds: UInt64(duration * 1_000_000_000))

        input.removeTap(onBus: 0)
        if let playerNode {
            playerNode.stop()
            engine.disconnectNodeOutput(playerNode)
            engine.detach(playerNode)
        }
        engine.stop()

        return goertzelMagnitude(samples: capturedSamples, targetFrequency: targetFrequency, sampleRate: sampleRate)
    }

    private func toneBuffer(duration: TimeInterval = 1.5) -> AVAudioPCMBuffer {
        let format = AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 1)!
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

    var errorDescription: String? {
        switch self {
        case .permissionDenied: return "Microphone permission was denied."
        case .hapticsUnsupported: return "This device doesn't support haptics."
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
    @Published var status = "Idle"
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

        let result = HapticMotionResult(matchedEvents: matched, totalEvents: eventOffsets.count)
        status = result.detected
            ? "Detected all \(matched)/\(eventOffsets.count) haptic events via motion"
            : "Only matched \(matched)/\(eventOffsets.count) — check phone isn't on a soft surface"
        lastResult = result
        return result
    }
}
