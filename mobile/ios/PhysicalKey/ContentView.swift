import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = AuthViewModel()

    var body: some View {
        VStack(spacing: 20) {
            Text("PhysicalKey")
                .font(.largeTitle.bold())

            statusView

            actionButton

            if !viewModel.lastLog.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(viewModel.lastLog.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 200)
                .padding(.horizontal)
            }
        }
        .padding()
        .onAppear { viewModel.onAppear() }
    }

    @ViewBuilder
    private var statusView: some View {
        switch viewModel.stage {
        case .notReady:
            Label("No identity on this device yet", systemImage: "person.badge.key")
                .foregroundStyle(.secondary)
        case .ready:
            Label("Identity ready", systemImage: "checkmark.seal")
                .foregroundStyle(.green)
        case .phoneVerifying:
            Label("Verifying phone…", systemImage: "faceid")
                .foregroundStyle(.blue)
        case .phoneVerified:
            Label("Phone verified — ready to connect to your key device", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
        case .connectingToDevice:
            Label("Connecting to key device…", systemImage: "wave.3.right")
                .foregroundStyle(.blue)
        case .authenticated:
            Label("Authenticated — full access granted", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
        case .failed(let message):
            Label(message, systemImage: "exclamationmark.triangle")
                .foregroundStyle(.red)
                .font(.footnote)
        }
    }

    @ViewBuilder
    private var actionButton: some View {
        switch viewModel.stage {
        case .notReady:
            Button("Create Identity") { viewModel.createIdentity() }
                .buttonStyle(.borderedProminent)
        case .ready, .failed:
            Button("Authenticate with Face ID") { viewModel.authenticatePhone() }
                .buttonStyle(.borderedProminent)
        case .phoneVerifying, .connectingToDevice:
            ProgressView()
        case .phoneVerified:
            Button("Connect to Key Device") { viewModel.connectAndAuthenticateDevice() }
                .buttonStyle(.borderedProminent)
        case .authenticated:
            EmptyView()
        }
    }
}

#Preview {
    ContentView()
}
