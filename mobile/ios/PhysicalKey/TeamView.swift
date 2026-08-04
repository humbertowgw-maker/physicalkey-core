import SwiftUI

/// Team/org management, backed by OrganizationViewModel. Reachable once a phone session
/// exists (see ContentView) — deliberately usable without a physical key device on hand,
/// since revoking a departing member is exactly the kind of thing done from just a phone.
struct TeamView: View {
    @ObservedObject var viewModel: OrganizationViewModel

    var body: some View {
        content
            .navigationTitle(viewModel.org?.name ?? "Team")
            .task { await viewModel.loadKnownOrg() }
            .refreshable { await viewModel.refresh() }
            .alert("Error", isPresented: Binding(
                get: { viewModel.errorMessage != nil },
                set: { if !$0 { viewModel.errorMessage = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(viewModel.errorMessage ?? "")
            }
    }

    @ViewBuilder
    private var content: some View {
        if viewModel.isLoading && viewModel.org == nil {
            ProgressView()
        } else if let org = viewModel.org {
            OrgDetailView(viewModel: viewModel, org: org)
        } else {
            NoOrgView(viewModel: viewModel)
        }
    }
}

private struct NoOrgView: View {
    @ObservedObject var viewModel: OrganizationViewModel
    @State private var newOrgName = ""
    @State private var joinOrgId = ""

    var body: some View {
        Form {
            Section("Create a new team") {
                TextField("Team name", text: $newOrgName)
                Button("Create Team") {
                    Task { await viewModel.createOrg(name: newOrgName) }
                }
                .disabled(newOrgName.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            Section("Join an existing team") {
                Text("Ask your team's admin for the team ID and enter it here.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                TextField("Team ID", text: $joinOrgId)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                Button("Join") {
                    Task { await viewModel.joinKnownOrg(orgId: joinOrgId) }
                }
                .disabled(joinOrgId.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }
}

private struct OrgDetailView: View {
    @ObservedObject var viewModel: OrganizationViewModel
    let org: PhysicalKeyAPI.OrgDetail

    @State private var showingAddMember = false
    @State private var isScanning = false

    var body: some View {
        List {
            Section {
                LabeledContent("Your role", value: viewModel.myRole ?? "unknown")
                LabeledContent("Team ID") {
                    Text(org.id)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
            }

            Section("Members (\(org.members.count))") {
                ForEach(org.members) { member in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(member.deviceId)
                                .font(.callout.monospaced())
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Text(member.role)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if member.status == "revoked" {
                            Text("Revoked")
                                .font(.caption)
                                .foregroundStyle(.red)
                        }
                    }
                }
                .onDelete { offsets in
                    guard viewModel.canManage else { return }
                    for index in offsets {
                        let member = org.members[index]
                        if member.role == "owner" { continue } // backend rejects this anyway
                        Task { await viewModel.removeMember(deviceId: member.deviceId) }
                    }
                }

                if viewModel.canManage {
                    Button("Add Member", systemImage: "person.badge.plus") {
                        showingAddMember = true
                    }
                }
            }

            Section("Devices (\(org.devices.count))") {
                ForEach(org.devices) { device in
                    if viewModel.canManage {
                        NavigationLink {
                            DeviceAccessView(viewModel: viewModel, device: device, members: org.members)
                        } label: {
                            Text(device.deviceId)
                                .font(.callout.monospaced())
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    } else {
                        Text(device.deviceId)
                            .font(.callout.monospaced())
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                .onDelete { offsets in
                    guard viewModel.canManage else { return }
                    for index in offsets {
                        Task { await viewModel.releaseDevice(deviceId: org.devices[index].deviceId) }
                    }
                }

                if viewModel.canManage {
                    if isScanning {
                        HStack {
                            ProgressView()
                            Text("Hold your phone near the key device…")
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        Button("Claim a Nearby Key Device", systemImage: "key") {
                            isScanning = true
                            Task {
                                await viewModel.scanAndClaimNearbyDevice()
                                isScanning = false
                            }
                        }
                    }
                }
            }
        }
        .sheet(isPresented: $showingAddMember) {
            AddMemberSheet { deviceId, role in
                Task { await viewModel.addMember(deviceId: deviceId, role: role) }
            }
        }
    }
}

private struct AddMemberSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var deviceId = ""
    @State private var role = "member"
    let onSubmit: (String, String) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Member's phone device ID", text: $deviceId)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    Picker("Role", selection: $role) {
                        Text("Member").tag("member")
                        Text("Admin").tag("admin")
                    }
                } footer: {
                    Text("The member's device ID is shown on their own phone once they've created an identity.")
                }
            }
            .navigationTitle("Add Member")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        onSubmit(deviceId, role)
                        dismiss()
                    }
                    .disabled(deviceId.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
    }
}

private struct DeviceAccessView: View {
    @ObservedObject var viewModel: OrganizationViewModel
    let device: PhysicalKeyAPI.OrgDevice
    let members: [PhysicalKeyAPI.OrgMember]

    @State private var grants: [PhysicalKeyAPI.DeviceAccessGrant] = []
    @State private var showingGrantPicker = false

    private var activeMembers: [PhysicalKeyAPI.OrgMember] {
        members.filter { $0.status == "active" && $0.role == "member" }
    }
    private var ungrantedMembers: [PhysicalKeyAPI.OrgMember] {
        let grantedIds = Set(grants.map(\.memberDeviceId))
        return activeMembers.filter { !grantedIds.contains($0.deviceId) }
    }

    var body: some View {
        List {
            Section {
                Text("Owners and admins can always use this device. The grants below are for plain members only.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("Granted access") {
                if grants.isEmpty {
                    Text("No members granted yet").foregroundStyle(.secondary)
                }
                ForEach(grants) { grant in
                    Text(grant.memberDeviceId).font(.callout.monospaced())
                }
                .onDelete { offsets in
                    for index in offsets {
                        let memberDeviceId = grants[index].memberDeviceId
                        Task {
                            await viewModel.revokeDeviceAccess(deviceId: device.deviceId, memberDeviceId: memberDeviceId)
                            grants = await viewModel.listDeviceAccess(deviceId: device.deviceId)
                        }
                    }
                }
            }
            if !ungrantedMembers.isEmpty {
                Button("Grant a Member Access", systemImage: "plus") {
                    showingGrantPicker = true
                }
            }
        }
        .navigationTitle(device.deviceId)
        .task { grants = await viewModel.listDeviceAccess(deviceId: device.deviceId) }
        .confirmationDialog("Grant access to", isPresented: $showingGrantPicker, titleVisibility: .visible) {
            ForEach(ungrantedMembers) { member in
                Button(member.deviceId) {
                    Task {
                        await viewModel.grantDeviceAccess(deviceId: device.deviceId, memberDeviceId: member.deviceId)
                        grants = await viewModel.listDeviceAccess(deviceId: device.deviceId)
                    }
                }
            }
        }
    }
}
