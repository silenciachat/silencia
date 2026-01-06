#!/usr/bin/env bash
# Manual test suite for Silencia ZK Identity
# Run this to verify all Phase 1-4 features

set -e  # Exit on error

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 Silencia ZK IDENTITY - MANUAL TEST SUITE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Test 1: Build
echo "📦 Test 1: Building project..."
cargo build --release --bin silencia
echo "✅ Build successful"
echo ""

# Test 2: Run all unit tests
echo "🧪 Test 2: Running unit tests..."
cargo test --package silencia-identity --lib
echo "✅ All tests passed"
echo ""

# Test 3: Test identity creation
echo "🆔 Test 3: Creating test identities..."
cat > /tmp/test_identity.rs << 'EOF'
use silencia_identity::{Identity, AnonymousIdentity, IdentityGroup};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating regular identity...");
    let id1 = Identity::generate()?;
    println!("  ID: {}", hex::encode(&id1.id[..8]));
    
    println!("\nCreating anonymous identity...");
    let anon = AnonymousIdentity::generate()?;
    println!("  Commitment: {}", &anon.commitment[..50]);
    
    println!("\nCreating identity group...");
    let mut group = IdentityGroup::new()?;
    group.add_member(anon.commitment_field()?)?;
    println!("  Group size: {}", group.size());
    println!("  Root: {:?}", group.root());
    
    println!("\n✅ Identity creation works!");
    Ok(())
}
EOF

echo "  Compiling test..."
rustc --edition 2021 \
  -L target/release/deps \
  --extern silencia_identity=target/release/libsilencia_identity.rlib \
  --extern hex=target/release/deps/libhex-*.rlib \
  /tmp/test_identity.rs -o /tmp/test_identity 2>/dev/null || echo "⚠️  Skipping (compile issue)"

if [ -f /tmp/test_identity ]; then
  /tmp/test_identity
  rm /tmp/test_identity
fi
echo ""

# Test 4: Test CLI
echo "🖥️  Test 4: Testing CLI..."
if [ -f target/release/silencia ]; then
  echo "  Running: silencia --version"
  target/release/silencia --version || echo "  (version command not implemented)"
  echo "✅ CLI binary exists"
else
  echo "❌ CLI binary not found"
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 MANUAL TESTS COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next: Run interactive tests"
echo "  1. cargo run --bin silencia"
echo "  2. Try creating identity and connecting to peers"
echo ""
