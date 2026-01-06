# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: (Alpha) |

**Note**: Silencia is currently in alpha. Not production-ready.

## Reporting a Vulnerability

**DO NOT** open public issues for security vulnerabilities.

### How to Report

Email: **security@silencia.org** (or create private security advisory on GitHub)

Include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix timeline**: Depends on severity (Critical: 7-14 days; High: 14-30 days)
- **Disclosure**: Coordinated disclosure after fix is released

### PGP Key

```
TODO: Add PGP public key for security@silencia.org
```

## Security Considerations

### Threat Model
See [THREAT_MODEL.md](THREAT_MODEL.md) for detailed adversary assumptions.

### Known Limitations (Alpha)
- Post-quantum primitives are NIST draft standards (not finalized)
- Cover traffic parameters not yet optimized
- No formal security audit (planned for v1)
- Onion routing circuits use fixed 3-hop design

### Out of Scope
- Physical device access
- OS/hardware 0-days
- Malicious roommates with device access
- Supply chain attacks on dependencies (until reproducible builds in W16)

## Responsible Disclosure

We follow responsible disclosure:
1. Reporter privately discloses to Silencia team
2. Team confirms and develops fix
3. Fix is released with security advisory
4. Public disclosure 7-14 days after fix release
5. Reporter credited (if desired)

## Security Tooling

We use:
- `cargo-deny` for dependency audits
- `cargo-audit` for known vulnerabilities
- Fuzzing with `cargo-fuzz` (W2+)
- Static analysis with `clippy` and custom lints

---

Thank you for helping keep Silencia secure!
