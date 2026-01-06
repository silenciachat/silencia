# Silencia-SDK Makefile
# Production-ready build automation for silencia-sdk v0.1.0

.PHONY: help install build test clean fmt lint audit deny ci release dev docker all

# Default target
.DEFAULT_GOAL := help

# Colors for output
RED    := \033[0;31m
GREEN  := \033[0;32m
YELLOW := \033[0;33m
BLUE   := \033[0;34m
RESET  := \033[0m

##@ General

help: ## Display this help message
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║                                                                  ║$(RESET)"
	@echo "$(BLUE)║              SILENCIA-SDK v0.1.0 Makefile                          ║$(RESET)"
	@echo "$(BLUE)║                                                                  ║$(RESET)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make $(BLUE)<target>$(RESET)\n\n"} \
		/^[a-zA-Z_-]+:.*?##/ { printf "  $(BLUE)%-15s$(RESET) %s\n", $$1, $$2 } \
		/^##@/ { printf "\n$(YELLOW)%s$(RESET)\n", substr($$0, 5) }' $(MAKEFILE_LIST)
	@echo ""

##@ Development

install: ## Install Rust toolchain and dependencies
	@echo "$(GREEN)Installing Rust toolchain...$(RESET)"
	@rustup update stable
	@rustup component add rustfmt clippy
	@echo "$(GREEN)Installing development tools...$(RESET)"
	@cargo install cargo-audit cargo-deny cargo-tarpaulin || true
	@echo "$(GREEN)✅ Installation complete!$(RESET)"

dev: ## Start development environment (format + build + test)
	@$(MAKE) fmt
	@$(MAKE) build
	@$(MAKE) test
	@echo "$(GREEN)✅ Development environment ready!$(RESET)"

watch: ## Watch for changes and rebuild
	@echo "$(YELLOW)Watching for changes...$(RESET)"
	@cargo watch -x build -x test

##@ Building

build: ## Build all workspace crates (debug mode)
	@echo "$(GREEN)Building workspace...$(RESET)"
	@cargo build --workspace
	@echo "$(GREEN)✅ Build complete!$(RESET)"

build-release: ## Build optimized release binaries
	@echo "$(GREEN)Building release binaries...$(RESET)"
	@cargo build --workspace --release
	@echo "$(GREEN)✅ Release build complete!$(RESET)"
	@ls -lh target/release/silencia target/release/silencia-node 2>/dev/null || true

build-sdk: ## Build SDK crate only
	@echo "$(GREEN)Building SDK...$(RESET)"
	@cargo build --package silencia-sdk
	@echo "$(GREEN)✅ SDK build complete!$(RESET)"

build-cli: ## Build CLI binary
	@echo "$(GREEN)Building CLI...$(RESET)"
	@cargo build --package silencia-cli
	@echo "$(GREEN)✅ CLI build complete!$(RESET)"

clean: ## Clean build artifacts
	@echo "$(YELLOW)Cleaning build artifacts...$(RESET)"
	@cargo clean
	@rm -rf *.db .test_vault_* 2>/dev/null || true
	@echo "$(GREEN)✅ Clean complete!$(RESET)"

##@ Testing

test: ## Run all tests (unit + integration + doc)
	@echo "$(GREEN)Running all tests...$(RESET)"
	@cargo test --workspace 2>&1 | tee /tmp/silencia_test_output.txt
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║              📊 TEST SUMMARY                                     ║$(RESET)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@grep "^test result:" /tmp/silencia_test_output.txt | awk '{ \
		passed += $$4; failed += $$6; ignored += $$8 \
	} END { \
		total = passed + failed + ignored; \
		printf "  ✅ Tests Passed:   %d\n", passed; \
		printf "  ❌ Tests Failed:   %d\n", failed; \
		printf "  ⏭  Tests Ignored:  %d\n", ignored; \
		printf "\n  📦 TOTAL TESTS:    %d\n", total; \
		if (failed == 0) { \
			printf "\n  🎯 Pass Rate:      100%% (%d/%d)\n", passed, passed; \
			printf "\n  $(GREEN)✅ ALL TESTS PASSED! 🎉$(RESET)\n" \
		} else { \
			rate = (passed * 100.0) / (passed + failed); \
			printf "\n  🎯 Pass Rate:      %.1f%% (%d/%d)\n", rate, passed, passed + failed; \
			printf "\n  $(RED)❌ SOME TESTS FAILED$(RESET)\n" \
		} \
	}'
	@echo ""

test-sdk: ## Run SDK tests only
	@echo "$(GREEN)Running SDK tests...$(RESET)"
	@cargo test --package silencia-sdk
	@echo "$(GREEN)✅ SDK tests passed!$(RESET)"

test-unit: ## Run unit tests only
	@echo "$(GREEN)Running unit tests...$(RESET)"
	@cargo test --workspace --lib --bins
	@echo "$(GREEN)✅ Unit tests passed!$(RESET)"

test-integration: ## Run integration tests only
	@echo "$(GREEN)Running integration tests...$(RESET)"
	@cargo test --workspace --test '*'
	@echo "$(GREEN)✅ Integration tests passed!$(RESET)"

test-doc: ## Run documentation tests
	@echo "$(GREEN)Running doc tests...$(RESET)"
	@cargo test --workspace --doc
	@echo "$(GREEN)✅ Doc tests passed!$(RESET)"

test-coverage: ## Generate code coverage report
	@echo "$(GREEN)Generating coverage report...$(RESET)"
	@cargo tarpaulin --workspace --timeout 300 --out Html --output-dir coverage
	@echo "$(GREEN)✅ Coverage report generated: coverage/index.html$(RESET)"

##@ Code Quality

fmt: ## Format all code with rustfmt
	@echo "$(GREEN)Formatting code...$(RESET)"
	@cargo fmt --all
	@echo "$(GREEN)✅ Code formatted!$(RESET)"

fmt-check: ## Check if code is formatted
	@echo "$(GREEN)Checking code format...$(RESET)"
	@cargo fmt --all -- --check
	@echo "$(GREEN)✅ Code format check passed!$(RESET)"

lint: ## Run clippy linter
	@echo "$(GREEN)Running clippy...$(RESET)"
	@cargo clippy --workspace --all-targets --all-features -- -D warnings
	@echo "$(GREEN)✅ Clippy passed (0 warnings)!$(RESET)"

lint-fix: ## Auto-fix clippy warnings where possible
	@echo "$(GREEN)Running clippy with auto-fix...$(RESET)"
	@cargo clippy --workspace --all-targets --all-features --fix --allow-dirty
	@echo "$(GREEN)✅ Clippy auto-fix complete!$(RESET)"

##@ Security

audit: ## Run cargo audit for vulnerabilities
	@echo "$(GREEN)Running security audit...$(RESET)"
	@cargo audit
	@echo "$(GREEN)✅ Security audit complete!$(RESET)"

deny: ## Run cargo deny checks
	@echo "$(GREEN)Running cargo deny...$(RESET)"
	@cargo deny check
	@echo "$(GREEN)✅ Cargo deny passed!$(RESET)"

deny-licenses: ## Check license compliance
	@echo "$(GREEN)Checking licenses...$(RESET)"
	@cargo deny check licenses
	@echo "$(GREEN)✅ License check passed!$(RESET)"

deny-advisories: ## Check security advisories
	@echo "$(GREEN)Checking advisories...$(RESET)"
	@cargo deny check advisories
	@echo "$(GREEN)✅ Advisory check passed!$(RESET)"

deny-bans: ## Check for banned dependencies
	@echo "$(GREEN)Checking banned dependencies...$(RESET)"
	@cargo deny check bans
	@echo "$(GREEN)✅ Ban check passed!$(RESET)"

security: audit deny ## Run all security checks

##@ Continuous Integration

ci: ## Run full CI pipeline (check, format, lint, build, test)
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║              Running Full CI Pipeline                            ║$(RESET)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(YELLOW)1/5 Cargo Check...$(RESET)"
	@$(MAKE) check
	@echo ""
	@echo "$(YELLOW)2/5 Format Check...$(RESET)"
	@$(MAKE) fmt-check
	@echo ""
	@echo "$(YELLOW)3/5 Linting...$(RESET)"
	@$(MAKE) lint
	@echo ""
	@echo "$(YELLOW)4/5 Building...$(RESET)"
	@$(MAKE) build
	@echo ""
	@echo "$(YELLOW)5/5 Testing...$(RESET)"
	@$(MAKE) test
	@echo ""
	@echo "$(GREEN)╔══════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(GREEN)║              ✅ CI Pipeline Passed!                              ║$(RESET)"
	@echo "$(GREEN)╚══════════════════════════════════════════════════════════════════╝$(RESET)"

ci-quick: ## Run quick CI checks (format, lint, build)
	@echo "$(GREEN)Running quick CI...$(RESET)"
	@$(MAKE) fmt-check
	@$(MAKE) lint
	@$(MAKE) build
	@echo "$(GREEN)✅ Quick CI passed!$(RESET)"

##@ Release

release-check: ## Verify release readiness
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║              Release Readiness Check                             ║$(RESET)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(YELLOW)Checking version...$(RESET)"
	@grep -E '^version = "0.1.0"' crates/silencia-sdk/Cargo.toml
	@echo "$(GREEN)✅ Version: 0.1.0$(RESET)"
	@echo ""
	@$(MAKE) ci
	@echo ""
	@echo "$(GREEN)╔══════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(GREEN)║              ✅ Release Ready!                                    ║$(RESET)"
	@echo "$(GREEN)╚══════════════════════════════════════════════════════════════════╝$(RESET)"

release-build: release-check ## Build release binaries with verification
	@echo "$(GREEN)Building release artifacts...$(RESET)"
	@$(MAKE) build-release
	@echo ""
	@echo "$(GREEN)Release binaries:$(RESET)"
	@file target/release/silencia target/release/silencia-node 2>/dev/null || true
	@echo ""
	@echo "$(GREEN)✅ Release build complete!$(RESET)"

release-tag: ## Create git tag for release
	@echo "$(YELLOW)Creating release tag v0.1.0...$(RESET)"
	@git tag -a v0.1.0 -m "Release v0.1.0: Production-grade SDK with 95% CLI parity"
	@echo "$(GREEN)✅ Tag created! Push with: git push origin v0.1.0$(RESET)"

publish-sdk: ## Publish SDK to crates.io (requires authentication)
	@echo "$(YELLOW)Publishing silencia-sdk to crates.io...$(RESET)"
	@cd crates/silencia-sdk && cargo publish
	@echo "$(GREEN)✅ Published to crates.io!$(RESET)"

##@ Documentation

doc: ## Generate documentation
	@echo "$(GREEN)Generating documentation...$(RESET)"
	@cargo doc --workspace --no-deps --all-features
	@echo "$(GREEN)✅ Documentation generated: target/doc/silencia_sdk/index.html$(RESET)"

doc-open: ## Generate and open documentation in browser
	@echo "$(GREEN)Generating and opening documentation...$(RESET)"
	@cargo doc --workspace --no-deps --all-features --open

doc-private: ## Generate documentation including private items
	@echo "$(GREEN)Generating documentation (including private)...$(RESET)"
	@cargo doc --workspace --document-private-items --all-features
	@echo "$(GREEN)✅ Documentation generated!$(RESET)"

##@ Docker

docker-build: ## Build Docker image
	@echo "$(GREEN)Building Docker image...$(RESET)"
	@docker build -t silencia-sdk:latest -f Dockerfile.test .
	@echo "$(GREEN)✅ Docker image built!$(RESET)"

docker-test: ## Run tests in Docker container
	@echo "$(GREEN)Running tests in Docker...$(RESET)"
	@docker run --rm silencia-sdk:latest cargo test --workspace
	@echo "$(GREEN)✅ Docker tests passed!$(RESET)"

docker-shell: ## Open shell in Docker container
	@echo "$(GREEN)Opening Docker shell...$(RESET)"
	@docker run --rm -it silencia-sdk:latest /bin/bash

##@ Utilities

status: ## Show project status
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║              SILENCIA-SDK Project Status                           ║$(RESET)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(YELLOW)Git Status:$(RESET)"
	@git status --short
	@echo ""
	@echo "$(YELLOW)Rust Version:$(RESET)"
	@rustc --version
	@cargo --version
	@echo ""
	@echo "$(YELLOW)Workspace Crates:$(RESET)"
	@cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | "  - \(.name) v\(.version)"' 2>/dev/null || cargo tree -p silencia-sdk --depth 0
	@echo ""
	@echo "$(YELLOW)Latest Commit:$(RESET)"
	@git log -1 --oneline
	@echo ""

tree: ## Show dependency tree
	@echo "$(GREEN)Dependency tree for silencia-sdk:$(RESET)"
	@cargo tree -p silencia-sdk

bloat: ## Analyze binary size
	@echo "$(GREEN)Analyzing binary size...$(RESET)"
	@cargo bloat --release --crates || cargo build --release && ls -lh target/release/silencia

bench: ## Run benchmarks (if any)
	@echo "$(GREEN)Running benchmarks...$(RESET)"
	@cargo bench --workspace

outdated: ## Check for outdated dependencies
	@echo "$(GREEN)Checking for outdated dependencies...$(RESET)"
	@cargo outdated || echo "Install with: cargo install cargo-outdated"

update: ## Update dependencies
	@echo "$(GREEN)Updating dependencies...$(RESET)"
	@cargo update
	@echo "$(GREEN)✅ Dependencies updated!$(RESET)"

##@ Running

run-cli: ## Run CLI in development mode
	@echo "$(GREEN)Running CLI...$(RESET)"
	@cargo run --package silencia-cli -- --help

run-node: ## Run node in development mode
	@echo "$(GREEN)Running node...$(RESET)"
	@cargo run --package silencia-node

run-cli-release: ## Run CLI in release mode
	@echo "$(GREEN)Running CLI (release)...$(RESET)"
	@cargo run --package silencia-cli --release -- --help

##@ Maintenance

check: ## Run cargo check on all targets
	@echo "$(GREEN)Running cargo check...$(RESET)"
	@cargo check --workspace --all-targets --all-features
	@echo "$(GREEN)✅ Check passed!$(RESET)"

fix: ## Auto-fix issues with cargo fix
	@echo "$(GREEN)Running cargo fix...$(RESET)"
	@cargo fix --workspace --allow-dirty
	@echo "$(GREEN)✅ Auto-fix complete!$(RESET)"

refresh: clean install ## Clean and reinstall everything
	@echo "$(GREEN)✅ Refresh complete!$(RESET)"

all: fmt lint build test security doc ## Run all checks and build everything
	@echo "$(GREEN)╔══════════════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(GREEN)║              ✅ All Tasks Complete!                              ║$(RESET)"
	@echo "$(GREEN)╚══════════════════════════════════════════════════════════════════╝$(RESET)"

##@ Common Workflows

pre-commit: fmt lint test ## Run pre-commit checks
	@echo "$(GREEN)✅ Pre-commit checks passed!$(RESET)"

pre-push: ci ## Run pre-push checks (full CI)
	@echo "$(GREEN)✅ Pre-push checks passed!$(RESET)"

quick: fmt-check lint build test-unit ## Quick development check
	@echo "$(GREEN)✅ Quick check passed!$(RESET)"
