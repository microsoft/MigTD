AZCVMEMU_FEATURES ?= AzCVMEmu
IGVM_FILE ?= target/release/migtd.igvm
LOG_LEVEL ?= info
# Common features for IGVM images
IGVM_FEATURES_BASE ?= vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic
# test_accept_all feature skips policy verification, bypasses RATLS security
IGVM_FEATURES_ACCEPT_ALL ?= $(IGVM_FEATURES_BASE),test_accept_all
# test_reject_all feature forces migrations to be rejected by returning Unsupported and skipping exchange_msk
IGVM_FEATURES_REJECT_ALL ?= $(IGVM_FEATURES_BASE),test_reject_all
# test_disable_ra_and_accept_all feature disables remote attestation and skips policy verification, bypassing RATLS security
# test feature skips the compilation of attestation library when the remote attestation is not enabled or needed
IGVM_FEATURES_DISABLE_RA_AND_ACCEPT_ALL ?= $(IGVM_FEATURES_BASE),test_disable_ra_and_accept_all

.PHONY: help build-AzCVMEmu test-migtd-emu build-test-migtd-emu
.PHONY: build-igvm-accept generate-hash-accept build-igvm-accept-all build-igvm-reject build-igvm-reject-all
.PHONY: pre-build build-igvm generate-hash build-igvm-all

.DEFAULT_GOAL := build-igvm-all

help:
	@echo "Available targets:"
	@echo "  build-AzCVMEmu              - Build with AzCVMEmu features"
	@echo "  test-migtd-emu              - Run emulation tests"
	@echo "  build-test-migtd-emu        - Build and run emulation tests"
	@echo "  build-igvm-all              - Build IGVM"
	@echo "  build-igvm-accept-all       - Build IGVM with accept all policy"
	@echo "  build-igvm-reject-all       - Build IGVM with reject all policy"
	@echo "  build-igvm-disable-RA-all - Build IGVM with disabled RA and accept all policy"
	

build-AzCVMEmu:
	cargo build --no-default-features --features $(AZCVMEMU_FEATURES)

test-migtd-emu:
	./migtdemu.sh --both

build-test-migtd-emu: build-AzCVMEmu test-migtd-emu

pre-build:
	@if ! command -v rustc >/dev/null 2>&1 || ! rustc --version | grep -q "1.83.0"; then \
		echo "Installing Rust 1.83.0..."; \
		curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.83.0; \
		. ~/.cargo/env; \
	else \
		echo "Rust 1.83.0 already installed"; \
	fi
	@if ! rustup target list --installed | grep -q "x86_64-unknown-none"; then \
		echo "Adding x86_64-unknown-none target..."; \
		rustup target add x86_64-unknown-none; \
	else \
		echo "x86_64-unknown-none target already installed"; \
	fi
	git submodule update --init --recursive
	./sh_script/preparation.sh

build-igvm-accept:
	cargo image --no-default-features --features $(IGVM_FEATURES_ACCEPT_ALL) --log-level $(LOG_LEVEL) --image-format igvm --output $(IGVM_FILE)

generate-hash:
	cargo hash --image $(IGVM_FILE)

build-igvm-accept-all: pre-build build-igvm-accept generate-hash

build-igvm-disable-RA:
	cargo image --no-default-features --features $(IGVM_FEATURES_DISABLE_RA_AND_ACCEPT_ALL) --log-level $(LOG_LEVEL) --image-format igvm --output $(IGVM_FILE)

generate-hash-disable-RA:
	cargo hash --image $(IGVM_FILE) --test-disable-ra-and-accept-all

build-igvm-disable-RA-all: pre-build build-igvm-disable-RA generate-hash-disable-RA

build-igvm-reject:
	cargo image --no-default-features --features $(IGVM_FEATURES_REJECT_ALL) --log-level $(LOG_LEVEL) --image-format igvm --output $(IGVM_FILE)

build-igvm-reject-all: pre-build build-igvm-reject generate-hash

build-igvm:
	cargo image --no-default-features --features $(IGVM_FEATURES_BASE) --log-level $(LOG_LEVEL) --image-format igvm --output $(IGVM_FILE)

build-igvm-all: pre-build build-igvm generate-hash