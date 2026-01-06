# Silencia Threat Model v0.1

## Adversaries

### 1. Global Passive Observer
**Capabilities**: Monitor all network traffic, correlate timing/size/endpoints  
**Mitigations**:
- Onion routing (multi-hop circuits) obscures sender-receiver relationship
- Fixed-size message frames (512B default) prevent size correlation
- Periodic cover traffic + jittered send schedules mask idle periods
- Circuit rotation with timing jitter

### 2. Active MITM Attacker
**Capabilities**: Intercept, modify, replay, inject messages  
**Mitigations**:
- Hybrid PQ handshake (X25519 + ML-KEM) with downgrade protection
- HPKE-style encapsulation with authenticated envelopes
- Signature verification (ML-DSA + Ed25519 fallback)
- Epoch-based MLS rekeying prevents long-term key compromise

### 3. Spammer Botnets
**Capabilities**: Mass account creation, message flooding  
**Mitigations**:
- Zero-knowledge Proof-of-Human: one credential per person, rate-limited
- RLN (Rate-Limit Nullifier): provably enforce N messages/epoch without identity
- Optional anonymous postage (refundable micro-bonds)
- Community-defined policies with zk-proof verification

### 4. Abusive Insiders
**Capabilities**: Social engineering, exploit trust, dox users  
**Mitigations**:
- ZK-verified uniqueness: no PII required, no identity linkage
- Moderation via zk-proofs: ban by nullifier, not identity
- Encrypted vault: SQLCipher with passphrase-derived keys
- Zero metadata storage: only public keys stored, no IP/timestamps/connection logs

### 5. Device Compromise
**Capabilities**: Steal keys, read plaintext messages  
**Mitigations**:
- Forward secrecy: frequent epoch rekeying, no transcript retention
- Memory locking (`mlock`) + zeroization of sensitive data
- Encrypted vault: SQLCipher protects keys at rest (passphrase required)
- Identity rotation: periodic libp2p keypair refresh without breaking peer trust

### 6. Update Channel Compromise
**Capabilities**: Distribute backdoored binaries  
**Mitigations**:
- Reproducible builds (documented, verifiable)
- Offline-stored signing key with key ceremony
- TUF-like metadata for rollback protection
- Canary builds for transparency

## Attack Scenarios & Defenses

| Attack | Impact | Defense |
|--------|--------|---------|
| Traffic correlation (timing) | Deanonymize sender | Cover traffic, jittered delays |
| Message size fingerprinting | Infer content type | Fixed 512B frames, fragmentation |
| Social graph mapping | Reveal who-talks-to-who | Onion routing, DHT-based discovery (no stored contact lists) |
| Quantum computer (future) | Break classical crypto | Hybrid PQ KEM (ML-KEM) + signatures (ML-DSA) |
| Spam flood | DoS communities | RLN rate limits, PoH Sybil resistance |
| Stolen device → key exfil | Read past messages | Encrypted vault (passphrase required), forward secrecy |
| Compromised relay node | Trace circuits | Multi-hop (≥3), circuit rotation, no single point |
| Persistent identity tracking | Long-term correlation | Libp2p keypair rotation + DHT republishing |

## Out of Scope (v0.1)

- Nation-state 0-days (OS, hardware)
- Physical access with forensics
- Malicious roommates with device access
- Quantum attacks on SHA-2/SHA-3 (collision resistance assumed)

## Assumptions

- Post-quantum primitives (ML-KEM, ML-DSA) are sound (NIST draft standards)
- Device TEE/secure enclave not relied upon (but can enhance if available)
- Users verify peer fingerprints for high-assurance channels
- Community committee for PoH mint is diverse and honest (alpha version)
- Encrypted vault passphrase has sufficient entropy (enforced minimum strength)
- DHT/gossipsub discovery sufficiently anonymizes peer lookups

## Open Questions for Review

1. Cover traffic overhead vs. privacy gain: optimal Poisson λ?
2. RLN circuit choice: Poseidon vs. MiMC for proof size/speed tradeoff?
3. Credential revocation: nullifier vs. accumulator-based?
4. Mobile background mode: how to maintain circuits with OS constraints?
5. Identity rotation frequency: balance between unlinkability and peer discovery overhead?
6. DHT pollution attacks: how to prevent malicious nodes from poisoning peer discovery?

---

**Next revision**: Post-alpha feedback, external review findings
