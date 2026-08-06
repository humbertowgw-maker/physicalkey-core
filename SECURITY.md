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
- Audit trail (immutable logs of every auth attempt)

### What's Not Protected (Yet)

- Quantum-resistant cryptography (roadmap: 2027)
- Hardware tamper detection (roadmap: PKA Ultra)
- KMS integration (roadmap: 2027)

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
