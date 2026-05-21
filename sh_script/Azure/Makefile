#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#
# all targets in this Makefile are for building IGVM images for testing only.

IGVM_FILE ?= target/release/migtd.igvm
LOG_LEVEL ?= trace
# Common features for IGVM images
IGVM_FEATURES_BASE ?= vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,spdm_attestation
IGVM_FEATURES_GET_QUOTE = $(IGVM_FEATURES_BASE),igvm-attest
IGVM_FEATURES_MOCK_QUOTE = $(IGVM_FEATURES_BASE),use-mock-quote
IGVM_FEATURES_GET_QUOTE_TEST = $(IGVM_FEATURES_GET_QUOTE),test-get-quote
IGVM_MANIFEST ?= config/Azure/servtd_info.json

.PHONY: pre-build generate-hash generate-hash-v2 generate-hash-v2-verbose generate-hash-verbose
.PHONY: generate-hash-accept generate-hash-get-quote
.PHONY: generate-policy-accept build-igvm-accept build-igvm-accept-all
.PHONY: generate-policy-reject build-igvm-reject build-igvm-reject-all test-reject
.PHONY: build-igvm build-igvm-all build-igvm-v2-mock
.PHONY: build-igvm-get-quote build-igvm-get-quote-all
.PHONY: build-igvm-mock-quote generate-policy-mock-quote
.PHONY: build-igvm-mock-quote-allow-all generate-policy-mock-quote-allow-all

.DEFAULT_GOAL := build-igvm-all

help:
	@echo "Available targets:"
	@echo "  build-igvm-all                  - Build IGVM"
	@echo "  build-igvm-accept-all           - Build IGVM with allow-all v2 policy using mock quote data"
	@echo "  build-igvm-reject-all           - Build IGVM with bad-FMSPC v2 policy (migration will be rejected)"
	@echo "  build-igvm-get-quote-all        - Build IGVM with v2 policy to test the getquote during initialization.(no successful migration expected)"
	@echo "  build-igvm-mock-quote           - Build IGVM with v2 policy using mock quote data for testing."
	@echo "  build-igvm-mock-quote-allow-all - Build IGVM with allow-all v2 policy using mock quote data."

pre-build:
	@if ! command -v rustc >/dev/null 2>&1 || ! rustc --version | grep -q "1.88.0"; then \
		echo "Installing Rust 1.88.0..."; \
		curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.88.0; \
		. ~/.cargo/env; \
	else \
		echo "Rust 1.88.0 already installed"; \
	fi
	@if ! rustup target list --installed | grep -q "x86_64-unknown-none"; then \
		echo "Adding x86_64-unknown-none target..."; \
		rustup target add x86_64-unknown-none; \
	else \
		echo "x86_64-unknown-none target already installed"; \
	fi
	cd ../../ && git submodule update --init --recursive
	chmod +x ../../sh_script/preparation.sh
	cd ../../ && ./sh_script/preparation.sh

# --- Hash generation (shared) ---

generate-hash:
	cd ../../ &&  cargo run -p migtd-hash -- --image $(IGVM_FILE) --manifest $(IGVM_MANIFEST) --policy-v2

generate-hash-verbose:
	cd ../../ &&  cargo run -p migtd-hash -- --image $(IGVM_FILE) --manifest $(IGVM_MANIFEST) --verbose --policy-v2

generate-hash-v2: generate-hash

generate-hash-accept: generate-hash-v2

generate-hash-get-quote: generate-hash-v2

generate-hash-v2-verbose: generate-hash-verbose

# --- Default (same as get-quote, kept for pipeline) ---

build-igvm:
	cd ../../ && cargo image --no-default-features --features $(IGVM_FEATURES_GET_QUOTE) --log-level $(LOG_LEVEL) \
	 --image-format igvm --output $(IGVM_FILE) --debug \
	 --policy-v2 --policy config/templates/policy_v2_signed.json \
	 --policy-issuer-chain config/templates/policy_issuer_chain.pem \
	 --root-ca config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer

build-igvm-all: pre-build build-igvm generate-hash-v2

# --- Shared v2 mock-quote IGVM build (used by accept, reject, mock-quote targets) ---

build-igvm-v2-mock:
	cd ../../ && cargo image --policy-v2 --debug \
	 --image-format igvm \
	 --no-default-features \
	 --features $(IGVM_FEATURES_MOCK_QUOTE) \
	 --log-level $(LOG_LEVEL) \
	 --policy-issuer-chain config/Azure/policy_issuer_chain.pem \
	 --policy config/Azure/policy_v2_signed.json \
	 --output $(IGVM_FILE)

# --- Accept-all (allow-all v2 policy + mock quote) ---

generate-policy-accept:
	chmod +x ./build_azure_mock_test.sh
	./build_azure_mock_test.sh --allow-all
	@if [ $$? -ne 0 ]; then \
		echo "Failed to generate allow-all policy with mock report"; \
		exit 1; \
	fi

build-igvm-accept: pre-build generate-policy-accept build-igvm-v2-mock

build-igvm-accept-all: build-igvm-accept generate-hash-v2

# --- Reject-all (bad-FMSPC v2 policy + mock quote) ---

generate-policy-reject:
	chmod +x ./build_azure_mock_test.sh
	./build_azure_mock_test.sh --reject --skip-test
	@if [ $$? -ne 0 ]; then \
		echo "Failed to generate reject policy with mock report"; \
		exit 1; \
	fi

build-igvm-reject: pre-build generate-policy-reject build-igvm-v2-mock

build-igvm-reject-all: build-igvm-reject test-reject generate-hash-v2

test-reject:
	@echo "Running reject test (expecting migration failure with code 8)..."
	@echo "Note: PolicyUnsatisfiedError (code 8) propagates via VDM error encoding"
	@echo "      through the SPDM transport layer. See spdm_vdm.rs for details."
	cd ../../ && ./migtdemu.sh --policy-v2 \
	 --policy-file config/Azure/policy_v2_signed.json \
	 --policy-issuer-chain-file config/Azure/policy_issuer_chain.pem \
	 --mock-report --both --no-sudo --log-level info; \
	EXIT_CODE=$$?; \
	if [ $$EXIT_CODE -eq 0 ]; then \
		echo "ERROR: Migration succeeded but should have been rejected!"; \
		exit 1; \
	fi; \
	if grep -q "code.* 8\|code: 8" migtd_migration_source.log 2>/dev/null; then \
		echo "✓ Reject test passed: migration correctly rejected with code 8"; \
	else \
		echo "ERROR: Migration failed but not with expected code 8"; \
		grep -i "failed\|error" migtd_migration_source.log 2>/dev/null | tail -5; \
		echo "✓ Reject test passed: migration correctly rejected with code 8 (PolicyUnsatisfiedError)"; \
	else \
		echo "ERROR: Migration failed but not with expected code 8"; \
		grep -i "failed\|error\|code" migtd_migration_source.log 2>/dev/null | tail -5; \
		exit 1; \
	fi

# --- Get-quote (v2 policy with real quote) ---

# For testing getquote during initialization, no successful migration is expected.
build-igvm-get-quote: pre-build
	cd ../../ && cargo image --no-default-features --features $(IGVM_FEATURES_GET_QUOTE_TEST) --log-level $(LOG_LEVEL) \
	 --image-format igvm --output $(IGVM_FILE) --debug \
	 --policy-v2 --policy config/templates/policy_v2_signed.json \
	 --policy-issuer-chain config/templates/policy_issuer_chain.pem \
	 --root-ca config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer

build-igvm-get-quote-all: build-igvm-get-quote generate-hash-v2

# --- Mock-quote (v2 policy + mock quote for testing) ---

generate-policy-mock-quote:
	chmod +x ./build_azure_mock_test.sh
	./build_azure_mock_test.sh
	@if [ $$? -ne 0 ]; then \
		echo "Failed to generate policy with mock report"; \
		exit 1; \
	fi

build-igvm-mock-quote: pre-build generate-policy-mock-quote build-igvm-v2-mock

# --- Mock-quote allow-all ---

generate-policy-mock-quote-allow-all:
	chmod +x ./build_azure_mock_test.sh
	./build_azure_mock_test.sh --allow-all
	@if [ $$? -ne 0 ]; then \
		echo "Failed to generate allow-all policy with mock report"; \
		exit 1; \
	fi

build-igvm-mock-quote-allow-all: pre-build generate-policy-mock-quote-allow-all build-igvm-v2-mock
