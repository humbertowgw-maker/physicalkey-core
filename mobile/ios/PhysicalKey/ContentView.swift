import SwiftUI
import UIKit

struct ContentView: View {
    @StateObject private var viewModel = AuthViewModel()
    @State private var orgViewModel: OrganizationViewModel?

    var body: some View {
        NavigationStack {
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
            .toolbar {
                // Team management only needs a phone session, not a full device-paired
                // one — see AuthViewModel.phoneSessionToken and OrganizationViewModel.
                if let token = viewModel.phoneSessionToken {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        NavigationLink("Team") {
                            TeamView(viewModel: orgViewModel(for: token))
                        }
                    }
                }
                #if DEBUG
                // Phase 0 spike only — not part of the real auth flow. See the
                // security-layers plan and LivenessSpike.swift.
                ToolbarItem(placement: .navigationBarLeading) {
                    NavigationLink("Spike") {
                        LivenessSpikeView()
                    }
                }
                #endif
            }
        }
        .onAppear { viewModel.onAppear() }
    }

    private func orgViewModel(for token: String) -> OrganizationViewModel {
        if let orgViewModel {
            orgViewModel.updateSessionToken(token)
            return orgViewModel
        }
        let created = OrganizationViewModel(api: viewModel.api, myDeviceId: viewModel.myDeviceId, phoneSessionToken: token)
        orgViewModel = created
        return created
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
        case .authenticated(_, let gitCredentials):
            VStack(alignment: .leading, spacing: 10) {
                Label("Authenticated — full access granted", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                GitCredentialsView(credentials: gitCredentials)
            }
        case .failed(let message):
            Label(message, systemImage: "exclamationmark.triangle")
                .foregroundStyle(.red)
                .font(.footnote)
        case .repairing:
            Label("Authorizing repair with your physical key…", systemImage: "wave.3.right")
                .foregroundStyle(.blue)
        }
    }

    @ViewBuilder
    private var actionButton: some View {
        switch viewModel.stage {
        case .notReady:
            Button("Create Identity") { viewModel.createIdentity() }
                .buttonStyle(.borderedProminent)
        case .ready:
            Button("Authenticate with Face ID") { viewModel.authenticatePhone() }
                .buttonStyle(.borderedProminent)
        case .failed:
            VStack(spacing: 12) {
                if viewModel.hasIdentity {
                    Button("Authenticate with Face ID") { viewModel.authenticatePhone() }
                        .buttonStyle(.borderedProminent)
                    // Surfaced here specifically: hasIdentity being true after a failure
                    // is exactly the "a local key exists but the backend doesn't recognize
                    // it" symptom — a stuck registration, not a wrong password. Retrying
                    // Face ID alone would just fail identically again.
                    Button("Repair with Physical Key") { viewModel.repairViaPhysicalKey() }
                        .buttonStyle(.bordered)
                } else {
                    Button("Create Identity") { viewModel.createIdentity() }
                        .buttonStyle(.borderedProminent)
                }
            }
        case .phoneVerifying, .connectingToDevice, .repairing:
            ProgressView()
        case .phoneVerified:
            Button("Connect to Key Device") { viewModel.connectAndAuthenticateDevice() }
                .buttonStyle(.borderedProminent)
        case .authenticated:
            EmptyView()
        }
    }
}

/// Surfaces the git credentials `/auth/device/verify` actually returns — previously
/// decoded and immediately discarded, so a real, successful authentication had no way to
/// hand them to the person who just earned them. Tap-to-copy, not shown as a QR/share
/// sheet: these are short-lived (24h) and scoped to whatever the backend granted, not
/// meant to persist anywhere beyond this screen.
private struct GitCredentialsView: View {
    let credentials: PhysicalKeyAPI.GitCredentials
    @State private var copiedField: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Git credentials")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            credentialRow(label: "Username", value: credentials.username)
            credentialRow(label: "Password", value: credentials.password)
            Text("Scope: \(credentials.scope) · expires \(credentials.expiresAt.formattedExpiry)")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
    }

    private func credentialRow(label: String, value: String) -> some View {
        HStack {
            Text(value)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Button {
                UIPasteboard.general.string = value
                copiedField = label
            } label: {
                Image(systemName: copiedField == label ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .font(.caption)
        }
    }
}

private extension Double {
    var formattedExpiry: String {
        Date(timeIntervalSince1970: self / 1000).formatted(date: .omitted, time: .shortened)
    }
}

#Preview {
    ContentView()
}
