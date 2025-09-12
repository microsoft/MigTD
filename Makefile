IGVM_FILE ?= target/release/migtd.igvm
LOG_LEVEL ?= info
IGVM_FEATURES ?= vmcall-raw,stack-guard,main,test_accept_all,vmcall-interrupt,oneshot-apic
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
	cargo image --no-default-features --features $(IGVM_FEATURES) --log-level $(LOG_LEVEL) --image-format igvm --output $(IGVM_FILE)

build-AzCVMEmu:
	cargo build --no-default-features --features $(AZCVMEMU_FEATURES)

generate-hash:
	cargo hash --image $(IGVM_FILE) --test-disable-ra-and-accept-all

build-igvm-all: pre-build build-igvm generate-hash
