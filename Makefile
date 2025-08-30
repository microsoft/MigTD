IGVM_FILE ?= target/release/migtd.igvm

pre-build:
	curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.83.0
	rustup target add x86_64-unknown-none
	git submodule update --init --recursive
	./sh_script/preparation.sh

build-igvm:
	cargo image --no-default-features --features vmcall-raw,stack-guard,main,test_disable_ra_and_accept_all --log-level info --image-format igvm --output $(IGVM_FILE)

build-AzCVMEmu:
	cargo build --no-default-features --features AzCVMEmu

generate-hash:
	cargo hash --image $(IGVM_FILE) --test-disable-ra-and-accept-all
