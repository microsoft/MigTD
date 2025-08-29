IGVM_FILE ?= target/release/migtd.igvm

build-igvm:
	cargo image --no-default-features --features vmcall-raw,stack-guard,main,test_disable_ra_and_accept_all --log-level info --image-format igvm --output $(IGVM_FILE)

generate-hash:
	cargo hash --image $(IGVM_FILE) --test-disable-ra-and-accept-all
