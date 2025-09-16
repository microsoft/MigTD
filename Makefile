IGVM_FILE ?= target/release/migtd.igvm
LOG_LEVEL ?= info
# test_accept_all feature skips policy verification, bypasses RATLS security
IGVM_FEATURES_ACCEPT_ALL ?= vmcall-raw,stack-guard,main,test_accept_all,vmcall-interrupt,oneshot-apic
# test_reject_all feature forces migrations to be rejected by returning Unsupported and skipping exchange_msk
IGVM_FEATURES_REJECT_ALL ?= vmcall-raw,stack-guard,main,test_reject_all,vmcall-interrupt,oneshot-apic
AZCVMEMU_FEATURES ?= AzCVMEmu

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

build-igvm:
	cargo image --no-default-features --features $(IGVM_FEATURES_ACCEPT_ALL) --log-level $(LOG_LEVEL) --image-format igvm --output $(IGVM_FILE)

build-AzCVMEmu:
	cargo build --no-default-features --features $(AZCVMEMU_FEATURES)

generate-hash:
	cargo hash --image $(IGVM_FILE) --test-disable-ra-and-accept-all

build-igvm-all: pre-build build-igvm generate-hash

# test_reject_all feature forces migrations to be rejected by returning Unsupported and skipping exchange_msk
build-igvm-reject:
	cargo image --no-default-features --features $(IGVM_FEATURES_REJECT_ALL) --log-level $(LOG_LEVEL) --image-format igvm --output $(IGVM_FILE)

build-igvm-reject-all: pre-build build-igvm-reject generate-hash
