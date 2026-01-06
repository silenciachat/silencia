#!/bin/bash
# Security audit helper script
# Runs cargo-deny and cargo-audit with helpful output

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔒 Silencia Security Audit"
echo "======================="
echo ""

# Check if tools are installed
MISSING_TOOLS=0

if ! command -v cargo-deny &> /dev/null; then
    echo -e "${YELLOW}⚠️  cargo-deny not installed${NC}"
    echo "   Install with: cargo install cargo-deny --locked"
    MISSING_TOOLS=1
fi

if ! command -v cargo-audit &> /dev/null; then
    echo -e "${YELLOW}⚠️  cargo-audit not installed${NC}"
    echo "   Install with: cargo install cargo-audit --locked"
    MISSING_TOOLS=1
fi

if [ $MISSING_TOOLS -eq 1 ]; then
    echo ""
    echo "See docs/DEPENDENCY_AUDITING.md for more information"
    exit 1
fi

echo "Running security audits..."
echo ""

# Run cargo-deny checks
echo "📋 Running cargo-deny checks..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "  • Checking advisories (security vulnerabilities)..."
if cargo deny check advisories 2>&1 | grep -q "error"; then
    echo -e "${RED}    ✗ Advisories check failed${NC}"
    FAILED=1
else
    echo -e "${GREEN}    ✓ Advisories check passed${NC}"
fi

echo "  • Checking licenses..."
if cargo deny check licenses 2>&1 | grep -q "error"; then
    echo -e "${RED}    ✗ License check failed${NC}"
    FAILED=1
else
    echo -e "${GREEN}    ✓ License check passed${NC}"
fi

echo "  • Checking bans..."
if cargo deny check bans 2>&1 | grep -q "error"; then
    echo -e "${RED}    ✗ Bans check failed${NC}"
    FAILED=1
else
    echo -e "${GREEN}    ✓ Bans check passed${NC}"
fi

echo "  • Checking sources..."
if cargo deny check sources 2>&1 | grep -q "error"; then
    echo -e "${RED}    ✗ Sources check failed${NC}"
    FAILED=1
else
    echo -e "${GREEN}    ✓ Sources check passed${NC}"
fi

echo ""

# Run cargo-audit
echo "🔍 Running cargo-audit..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"

if cargo audit; then
    echo -e "${GREEN}✓ No known security vulnerabilities${NC}"
else
    echo -e "${RED}✗ Security vulnerabilities found!${NC}"
    FAILED=1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -n "$FAILED" ]; then
    echo -e "${RED}❌ Security audit FAILED${NC}"
    echo ""
    echo "See docs/DEPENDENCY_AUDITING.md for how to fix issues"
    exit 1
else
    echo -e "${GREEN}✅ All security checks PASSED${NC}"
    exit 0
fi
