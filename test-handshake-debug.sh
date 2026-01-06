#!/bin/bash

# Silencia Handshake Debug Test Script
# Tests handshake protocol with enhanced logging

set -e

echo "=================================="
echo "Silencia Handshake Debug Test"
echo "=================================="
echo ""

# Clean up any old data
rm -rf /tmp/silencia-test-alice /tmp/silencia-test-bob
mkdir -p /tmp/silencia-test-alice /tmp/silencia-test-bob

# Create password files
echo "testpass123" > /tmp/alice-password.txt
echo "testpass123" > /tmp/bob-password.txt

echo "Step 1: Creating identities..."
echo ""

# Create Alice's identity
echo "Creating Alice's identity..."
RUST_LOG=info ./target/release/silencia --data-dir /tmp/silencia-test-alice identity create testpass123 2>&1 | grep -E "(Created|identity|ID:)"

# Create Bob's identity  
echo "Creating Bob's identity..."
RUST_LOG=info ./target/release/silencia --data-dir /tmp/silencia-test-bob identity create testpass123 2>&1 | grep -E "(Created|identity|ID:)"

echo ""
echo "Step 2: Starting Bob (will run in background)..."
echo ""

# Start Bob in background with enhanced logging
RUST_LOG=info,silencia_net=debug,silencia_net::handshake=trace ./target/release/silencia \
    --data-dir /tmp/silencia-test-bob \
    start -u bob -p 9100 < /tmp/bob-password.txt \
    > /tmp/bob-handshake-debug.log 2>&1 &

BOB_PID=$!
echo "Bob started with PID $BOB_PID"

# Wait for Bob to start
sleep 3

# Extract Bob's peer ID from log
BOB_PEER_ID=$(grep "Local peer id:" /tmp/bob-handshake-debug.log | head -1 | awk '{print $NF}')
echo "Bob's Peer ID: $BOB_PEER_ID"

echo ""
echo "Step 3: Starting Alice and connecting to Bob..."
echo ""

# Start Alice in background with enhanced logging
RUST_LOG=info,silencia_net=debug,silencia_net::handshake=trace ./target/release/silencia \
    --data-dir /tmp/silencia-test-alice \
    start -u alice -p 9101 < /tmp/alice-password.txt \
    > /tmp/alice-handshake-debug.log 2>&1 &

ALICE_PID=$!
echo "Alice started with PID $ALICE_PID"

# Wait for Alice to start
sleep 3

echo ""
echo "Step 4: Initiating connection from Alice to Bob..."
echo ""

# Send connect command to Alice (this is tricky with background processes)
# For now, we'll just let auto-connect happen

# Wait for handshake to complete (or timeout)
echo "Waiting 10 seconds for handshake..."
sleep 10

echo ""
echo "Step 5: Analyzing logs..."
echo ""

echo "=== BOB'S LOG ANALYSIS ==="
echo ""
echo "Handshake INIT messages sent by Bob:"
grep "📤 Sending handshake INIT" /tmp/bob-handshake-debug.log || echo "  None found"
echo ""
echo "Handshake INIT messages received by Bob:"
grep "🔐 Decoded handshake message.*INIT" /tmp/bob-handshake-debug.log || echo "  None found"
echo ""
echo "Handshake RESP messages sent by Bob:"
grep "📤 Sending handshake RESP" /tmp/bob-handshake-debug.log || echo "  None found"
echo ""
echo "Handshake RESP messages received by Bob:"
grep "🔐 Decoded handshake message.*RESP" /tmp/bob-handshake-debug.log || echo "  None found"
echo ""
echo "Handshake completion:"
grep "✅.*handshake completed" /tmp/bob-handshake-debug.log || echo "  None found"
echo ""
echo "Errors:"
grep "❌" /tmp/bob-handshake-debug.log || echo "  None found"
echo ""

echo "=== ALICE'S LOG ANALYSIS ==="
echo ""
echo "Handshake INIT messages sent by Alice:"
grep "📤 Sending handshake INIT" /tmp/alice-handshake-debug.log || echo "  None found"
echo ""
echo "Handshake INIT messages received by Alice:"
grep "🔐 Decoded handshake message.*INIT" /tmp/alice-handshake-debug.log || echo "  None found"
echo ""
echo "Handshake RESP messages sent by Alice:"
grep "📤 Sending handshake RESP" /tmp/alice-handshake-debug.log || echo "  None found"
echo ""
echo "Handshake RESP messages received by Alice:"
grep "🔐 Decoded handshake message.*RESP" /tmp/alice-handshake-debug.log || echo "  None found"
echo ""
echo "Handshake completion:"
grep "✅.*handshake completed" /tmp/alice-handshake-debug.log || echo "  None found"
echo ""
echo "Errors:"
grep "❌" /tmp/alice-handshake-debug.log || echo "  None found"
echo ""

echo "=== SUMMARY ==="
echo ""
echo "Full logs available at:"
echo "  Alice: /tmp/alice-handshake-debug.log"
echo "  Bob:   /tmp/bob-handshake-debug.log"
echo ""

# Cleanup
echo "Stopping processes..."
kill $BOB_PID $ALICE_PID 2>/dev/null || true
sleep 1
kill -9 $BOB_PID $ALICE_PID 2>/dev/null || true

echo ""
echo "Test complete!"
