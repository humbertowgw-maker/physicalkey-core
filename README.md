# PhysicalKey

**Hardware + phone authentication with cryptographic verification.**

![License](https://img.shields.io/badge/license-BUSL%201.1%20%2B%20MIT%20(hardware)-blue.svg)
![Status](https://img.shields.io/badge/status-beta-orange.svg)

> **Project status:** First public beta. This is an early version for development and evaluation, not a finished or production-ready security product.

## What is PhysicalKey?

PhysicalKey is a hardware authentication system that combines:

- **Phone biometric** (Face ID, fingerprint)
- **Hardware device** (ESP32 with cryptographic signing)
- **Backend verification** (P-256 phone identity, Ed25519 device identity — challenge-response)

The result is designed to resist cloning, theft, and forgery for:

- Git repositories and SSH keys
- API credentials and OAuth tokens
- Door locks and physical access control
- Cryptocurrency wallets
- Government and enterprise authentication

## Current Scope

PhysicalKey currently combines phone biometric approval, an ESP32 hardware device,
challenge-response backend verification (P-256 for the phone identity, Secure-Enclave-
resident; Ed25519 for the device identity), organization controls, and audit records.
Device-side biometrics and door-lock integrations are roadmap items, not features in the
current beta.

## How It Works

```text
1. User unlocks phone with Face ID
2. User opens PhysicalKey and taps Authenticate
3. Phone generates a random challenge
4. Phone sends the challenge to the device over Bluetooth
5. Device signs the challenge with its Ed25519 key
6. Device returns the signature
7. Phone verifies the signature locally
8. Phone sends proof to the backend
9. Backend verifies crypto, organization membership, and device binding
10. Authentication is granted and a one-hour session is created
```

Threat model highlights:

- Stolen phone: no hardware device, so authentication cannot complete
- Stolen device: no Face ID, so the phone remains locked
- Cloned device: signature verification fails
- Passive BLE interception: LE Secure Connections encrypts transport
- Active BLE man-in-the-middle attacks at first pairing: closed via Passkey Entry pairing
  (a per-unit passkey generated once on first boot, written on the physical
  enclosure/label at provisioning time — see `hardware/firmware-idf/.../main/pairing.cpp`).
  Boards paired before this change keep working via their existing bond without
  re-pairing; this only applies to a board's *next* first pairing (a fresh board, or one
  that's been explicitly un-paired)
- Compromised backend: identities can be revoked and the audit log records activity

## Architecture

### Backend (Node.js/Express on Railway)

- Ed25519 challenge-response authentication
- Multi-tenant organization and team management
- Device provenance tracking and anti-clone controls (admin allow-list, enforced)
- Session-ratchet state machine, backend-verified (not client-asserted)
- Honeypot forensics system, including a real bait git repository (`/backup.git`) served
  over git smart-HTTP — logs every hit's attempted credentials and user-agent, not just
  the fact of an attempt
- Git credential issuance tied to verified device sessions, with session and
  git-credential revocation wired to real admin endpoints (not defined-but-unused)
- Audit log and admin recovery tooling, with the admin action log SHA-256 hash-chained —
  an edited or deleted entry is detectable, not just recorded
- Per-identity recovery policy: `permanent` identities are code-enforced as
  unresettable (no admin override exists in the code path); `self-service` identities
  can be re-paired via a board-signed proof of physical possession, with no admin
  involved
- Scheduled + on-demand database snapshots (`/admin/backups`), health check that verifies
  database connectivity rather than just process liveness, and a documented self-host
  path ([SELF_HOSTING.md](./backend/SELF_HOSTING.md)) — **note the honest limit**: this is
  still a single process against a single SQLite file with no replica or failover, whether
  PK-hosted or self-hosted. Backups shrink blast radius and recovery time; they don't add
  redundancy. See SELF_HOSTING.md for what real HA would require.

### Hardware (ESP32-DevKitC-32D, ESP-IDF)

- BLE Secure Connections pairing
- Single-bond-per-board enforcement
- Flash and NVS encryption
- Device ID derived from eFuse MAC
- GATT challenge-response service
- Acoustic and motion fingerprinting roadmap

### iOS App (SwiftUI, Swift 6)

- Secure-Enclave-resident P-256 identity (`SecureEnclave.P256.Signing.PrivateKey`) —
  hardware key material that never leaves the secure co-processor, gated by
  `.biometryCurrentSet`
- Face ID gating
- BLE client for challenge exchange
- Team and membership management
- Device claiming
- Session-ratchet verification

## Getting Started

### Prerequisites

- iPhone (iOS 17+)
- ESP32-DevKitC-32D board
- Micro USB cable
- Mac with Xcode 15+

### For Users (Planned TestFlight Beta)

TestFlight distribution is not available yet. The current iOS app is installed
directly from Xcode on a trusted development device. Follow the
[PhysicalKey website](https://physicalkey.whitegwireless.com) for future beta access.

### For Developers (Self-Hosted)

```bash
git clone git@github.com:humbertowgw-maker/physicalkey-core.git
cd physicalkey-core

# Backend
cd backend
npm install
cp .env.example .env
npm start

# Hardware (requires ESP-IDF v5.3.1)
cd ../hardware/firmware-idf/PhysicalKeyDevice
source ~/esp-idf-test/esp-idf/export.sh
idf.py -p /dev/cu.usbserial-0001 flash monitor

# iOS
cd ../../../mobile/ios
xcodegen generate
open PhysicalKey.xcodeproj
```

See [SETUP_COMPLETE.md](./SETUP_COMPLETE.md) for the current setup and validation record.

## Security Model

### What's Protected

- Phone identity via a Secure-Enclave-resident P-256 private key (never leaves the
  co-processor); device identity via an Ed25519 private key encrypted at rest. A
  previously-registered legacy Ed25519 phone identity remains valid — the migration
  didn't force re-pairing
- Cryptographically verified challenge-response
- Backend-enforced organization and team isolation
- Device binding and provenance checks
- Audit records for authentication attempts, hash-chained so an edited or deleted entry
  is detectable (tamper-evident, not tamper-proof — see [Technical Details](#cryptography))
- Sessions and git credentials can be revoked before their natural expiry, not just left
  to time out
- A `permanent` recovery policy is a literal, code-level guarantee, not a promise —
  the admin reset endpoint refuses to touch it, with no override path anywhere in
  the code

### What's Not Protected Yet

- [ ] HSM-backed KMS integration
- [ ] Post-quantum cryptography
- [ ] Device-side hardware tamper detection

## Roadmap

### Phase 1: Authentication (August 2026 — closed 2026-08-10)

- [x] Git repository authentication
- [x] API credential management
- [x] Multi-device support
- [x] Organization and team management
- [x] Audit logging and honeypot forensics

### Phase 2: Honeypot (August–September 2026)

- [x] Deploy a honeypot Git repository
- [ ] Collect attacker techniques
- [ ] Publish forensics

### Phase 3: Physical Access (October 2026)

- [ ] PKA-Lock door locks
- [ ] PKA-Safe biometric safes
- [ ] Multi-device coordination

### Phase 4: Public Launch (September–October 2026)

- [ ] App Store and GitHub public launch
- [ ] Product Hunt launch
- [ ] Technical deep-dives

### Phase 5: Enterprise (2027+)

- [ ] PKA Ultra
- [ ] FIPS 140-2 Level 3 certification
- [ ] KMS integration
- [ ] White-label licensing

## Technical Details

### Cryptography

- Key generation and signing: P-256/ECDSA-SHA256 for the phone identity
  (Secure-Enclave-resident; legacy Ed25519 phones still accepted), Ed25519 for the
  device identity
- Verification: constant-time comparison
- Randomness: `crypto.randomBytes`
- Transport: BLE Secure Connections (AES-128-CCM with ECDH key agreement)

### Storage

- Phone: iOS Keychain
- Device: ESP32 flash and NVS encryption
- Backend: SQLite with protected secrets and audit records

### Network

- Backend API: HTTPS
- BLE: LE Secure Connections with single-bond enforcement
- Git credentials: issued from a verified device session

## Testing

Run the backend test suite:

```bash
cd backend
npm test
```

The beta release includes 127 automated tests.

## Reporting Security Issues

Do not open a public issue for a vulnerability. Email `security@physicalkey.io` with a description, reproduction steps, affected version, and proof of concept when possible. See [SECURITY.md](./SECURITY.md).

## Contributing

Contributions are welcome for hardware support, firmware optimization, iOS UX, backend hardening, and documentation.

## License

Split by component, on purpose:

- **`hardware/`** (firmware, schematics, BOM) — **MIT**, see
  [hardware/LICENSE](./hardware/LICENSE). Fully open: build your own board,
  flash it, modify it, sell boards built from it — no restriction. This is
  the part meant to be freely copied, verified, and improved by anyone.
- **Everything else** (backend, mobile app) — **Business Source License
  1.1**, see [LICENSE](./LICENSE). Free to read, self-host, and modify for
  your own use — including running it yourself to secure your own
  infrastructure — but you can't stand up a competing hosted PhysicalKey
  service with it. Converts automatically to Apache 2.0 on 2030-08-13.

Why split it: the device's security doesn't depend on anything about its
design being secret — each unit generates its own key on first boot, in
hardware, and never shares it — so there's no security cost to the hardware
being fully open, only upside (trust, community-built boards, independent
verification). The backend and app are the actual commercial product.

## Author

**Humberto Zepeda** ([@humbertowgw-maker](https://github.com/humbertowgw-maker))

## Links

- [Website](https://physicalkey.whitegwireless.com)
- Documentation: coming soon
- TestFlight: coming soon

---

**PhysicalKey: The key you can't steal, clone, or guess.**
