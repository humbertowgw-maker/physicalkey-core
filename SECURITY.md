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

- Device identity (Ed25519 private key, encrypted at rest)
- Challenge-response authentication (cryptographically verified)
- Organization/team isolation (backend enforced)
- Audit trail (every admin action and auth attempt logged, queryable)
- Per-identity recovery policy — a `permanent` identity is code-enforced as
  unresettable, with no admin override path anywhere in the code

### What's Not Protected (Yet)

- Tamper-evident audit log — today's logs are ordinary database rows with no
  hash-chaining or external mirror, so a backend compromise could erase its own
  trail (not "immutable" until this is addressed)
- KMS-backed signing key (backend compromise could otherwise mint arbitrary
  sessions) (roadmap: 2027)
- BLE out-of-band pairing — first-time pairing has no protection against an
  active attacker present at that exact moment (needs a per-unit passkey, a
  packaging decision, not just code)
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

**Latest update:** August 6, 2026
