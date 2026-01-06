//! Integration tests for pure Rust PQ crypto
use libp2p::PeerId;
use silencia_crypto::*;

#[test]
fn test_pure_rust_pq_crypto() {
    println!("\n🎯 Pure Rust PQ Crypto Integration Test");
    println!("=========================================\n");

    // Test 1: Hybrid KEM
    println!("1️⃣  Hybrid KEM (X25519 + Kyber768)");
    let alice = kem::HybridKem::generate().unwrap();
    let bob = kem::HybridKem::generate().unwrap();

    let bob_pq_pk = bob.pq_public_key().unwrap();
    println!("   ✅ PQ public key: {} bytes", bob_pq_pk.len());

    let (ct, alice_shared) = alice
        .encapsulate(bob.classical_public_key(), &bob_pq_pk)
        .unwrap();
    println!("   ✅ Ciphertext: {} bytes", ct.len());

    let bob_shared = bob.decapsulate(alice.classical_public_key(), &ct).unwrap();
    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    println!("   ✅ Shared secrets match!\n");

    // Test 2: Signatures
    println!("2️⃣  Hybrid Signatures (Ed25519 + Dilithium3)");
    let identity = identity::IdentityKey::generate().unwrap();
    let sig = identity.sign(b"test").unwrap();
    println!("   ✅ Ed25519: {} bytes", sig.classical.len());
    println!("   ✅ Dilithium3: {} bytes", sig.pq.as_ref().unwrap().len());
    identity.verify(b"test", &sig).unwrap();
    println!("   ✅ Verification passed!\n");

    // Test 3: Handshake
    println!("3️⃣  Full Handshake Protocol");
    let alice_id = identity::IdentityKey::generate().unwrap();
    let bob_id = identity::IdentityKey::generate().unwrap();

    let alice_hs = handshake::Handshake::new(alice_id.clone()).unwrap();
    let bob_hs = handshake::Handshake::new(bob_id.clone()).unwrap();

    let init = alice_hs.initiate(PeerId::random()).unwrap();
    println!("   ✅ Handshake initiated");

    let (resp, bob_key, _transcript) = bob_hs
        .respond(PeerId::random(), &init, alice_id.verifying_key())
        .unwrap();
    println!("   ✅ Handshake response created");

    let alice_key = alice_hs
        .complete(&init, &resp, bob_id.verifying_key())
        .unwrap();

    assert_eq!(alice_key, bob_key);
    println!("   ✅ Handshake complete - keys match!\n");

    println!("✅ All integration tests passed!");
    println!("Pure Rust PQ crypto working perfectly! 🚀");
}
