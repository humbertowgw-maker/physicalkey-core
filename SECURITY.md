# Security Policy

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

Instead, email: security@physicalkey.io

Include:

- Vulnerability description
- Steps to reproduce
- Proof of concept (if possible)
- Affected version

We'll respond within 48 hours and coordinate a fix before public disclosure.

## Security Model

### What's Protected

- Device identity (Ed25519 private key, encrypted at rest); phone identity
  (Secure-Enclave-resident P-256, hardware key material that never leaves the
  co-processor)
- Challenge-response authentication (cryptographically verified)
- Organization/team isolation (backend enforced)
- Audit trail (every admin action and auth attempt logged, queryable), and
  SHA-256 hash-chained — editing or deleting a logged entry is now detectable,
  not just recorded (tamper-evident, not tamper-proof: a full backend
  compromise with raw database write access could still recompute the whole
  chain — closing that needs a KMS/external mirror, see below)
- BLE out-of-band pairing — first-time pairing now uses per-unit Passkey Entry
  (a passkey generated once on first boot, written on the unit at provisioning
  time), closing the prior active-attacker-at-first-pairing gap. Boards paired
  before this shipped keep working via their existing bond, unaffected.
- Sessions and git credentials can be revoked before their natural expiry via
  real admin endpoints, not just left to time out
- Per-identity recovery policy — a `permanent` identity is code-enforced as
  unresettable, with no admin override path anywhere in the code

### What's Not Protected (Yet)

- KMS-backed signing key (backend compromise could otherwise mint arbitrary
  sessions) (roadmap: 2027)
- Factory-signed device attestation — a `deviceId` is trust-on-first-use plus
  an admin allow-list, not a manufacturing-time certificate
- Quantum-resistant cryptography (roadmap: 2027)
- Hardware tamper detection (roadmap: PKA Ultra)

## Audit Status

- [x] Internal security audit (Aug 2026)
- [ ] Third-party security audit (roadmap: Oct 2026)
- [ ] FIPS 140-2 L3 certification (roadmap: 2027)
- [ ] Common Criteria EAL4+ (roadmap: 2027)

## Security Updates

Critical security updates are released on a rolling basis. Users on TestFlight will receive updates automatically.

For production deployments, monitor:

- GitHub releases
- Security advisories
- Twitter @PhysicalKeyAuth

---

**Latest update:** August 10, 2026
