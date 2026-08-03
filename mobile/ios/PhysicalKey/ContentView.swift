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
            VStack(spacing: 8) {
                Label("Phone verified", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                Text("Waiting on IoT key device to complete authentication — no physical device exists yet, so this flow stops here.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
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
        case .phoneVerifying:
            ProgressView()
        case .phoneVerified:
            EmptyView()
        }
    }
}

#Preview {
    ContentView()
}
