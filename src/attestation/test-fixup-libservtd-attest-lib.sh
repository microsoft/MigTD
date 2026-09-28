#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/../.." && pwd -P)"
fixup_script="$script_dir/fixup-libservtd-attest-lib.sh"
mkdir -p "$repo_root/target"
test_root="$(mktemp -d "$repo_root/target/servtd-attest-fixup-tests.XXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT

working_dir="$test_root/migtd/src/attestation"
sgx_dir="$test_root/migtd/deps/linux-sgx"
library_dir="$sgx_dir/external/dcap_source/QuoteGeneration/quote_wrapper/servtd_attest/linux"
firmware="$library_dir/libservtd_attest.a"
application="$library_dir/libservtd_attest_app.a"
mkdir -p "$working_dir" "$library_dir" "$test_root/tmp"

cat >"$test_root/exit_stubs.c" <<'EOF'
int atexit(void (*callback)(void)) { return 0; }
int __cxa_atexit(void (*callback)(void *), void *argument, void *dso) { return 0; }
int servtd_fixture(void) { return 7; }
EOF
gcc -c "$test_root/exit_stubs.c" -o "$test_root/exit_stubs.o"
for name in tlibc_stub sgxssl_stub; do
    printf 'int %s(void) { return 0; }\n' "$name" >"$test_root/$name.c"
    gcc -c "$test_root/$name.c" -o "$test_root/$name.o"
done
ar crs "$sgx_dir/libtlibc.a" "$test_root/tlibc_stub.o"
ar crs "$sgx_dir/libsgx_tsgxssl_crypto.a" "$test_root/sgxssl_stub.o"
ar crs "$firmware" "$test_root/exit_stubs.o" \
    "$test_root/tlibc_stub.o" "$test_root/sgxssl_stub.o"
firmware_hash="$(sha256sum "$firmware")"

cat >"$test_root/crypto.c" <<'EOF'
#include <stdio.h>
extern int atexit(void (*callback)(void));
static void c_exit(void) { puts("host C exit callback ran"); }
int crypto_register_exit(void) { return atexit(c_exit); }
EOF
gcc -c "$test_root/crypto.c" -o "$test_root/crypto.o"
ar crs "$test_root/libcrypto.a" "$test_root/crypto.o"

cat >"$test_root/probe.c" <<'EOF'
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

extern int servtd_fixture(void);
extern int *__errno(void);
extern int crypto_register_exit(void);
extern int __cxa_atexit(void (*callback)(void *), void *argument, void *dso);

static void cxx_exit(void *argument) { puts((const char *)argument); }

int main(void)
{
    if (servtd_fixture() != 7 || __errno() != &errno)
        return 1;
    if (crypto_register_exit() != 0 ||
        __cxa_atexit(cxx_exit, (void *)"host C++ exit callback ran", NULL) != 0)
        return 1;
    return 0;
}
EOF

run_fixup() {
    (
        cd "$working_dir"
        TMPDIR="$test_root/tmp" bash "$fixup_script"
    )
}

for attempt in 1 2; do
    run_fixup
    if [[ "$(sha256sum "$firmware")" != "$firmware_hash" ]]; then
        echo "error: application fixup changed the firmware archive" >&2
        exit 1
    fi
    global_symbols="$(nm --defined-only --extern-only "$application")"
    if grep -Eq '[[:space:]](atexit|__cxa_atexit)$' <<<"$global_symbols"; then
        echo "error: application archive still exports enclave exit stubs" >&2
        exit 1
    fi
    for build_script in "$script_dir/build.rs" "$repo_root/src/migtd/build.rs"; do
        mapfile -t native_links < <(
            sed -n 's/^[[:space:]]*println!("cargo:rustc-link-arg=\(-l[^"]*\)");/\1/p' "$build_script"
        )
        if [[ ${#native_links[@]} == 0 ]]; then
            echo "error: native link directives missing from $build_script" >&2
            exit 1
        fi
        # Cargo suppresses implicit libraries; GNU ld cannot resolve late
        # libcrypto references by rescanning an earlier libc archive like LLD.
        gcc -fuse-ld=bfd -nodefaultlibs "$test_root/probe.c" \
            -Wl,--as-needed -lc -L"$library_dir" -L"$test_root" \
            "${native_links[@]}" -o "$test_root/probe"
        if [[ "$("$test_root/probe")" != $'host C++ exit callback ran\nhost C exit callback ran' ]]; then
            echo "error: host libc exit callbacks did not run" >&2
            exit 1
        fi
    done
done

mkdir -p "$test_root/bin"
cat >"$test_root/bin/objcopy" <<'EOF'
#!/usr/bin/env bash
exit 17
EOF
chmod +x "$test_root/bin/objcopy"
if PATH="$test_root/bin:$PATH" run_fixup >"$test_root/failure.log" 2>&1; then
    echo "error: application fixup accepted an objcopy failure" >&2
    exit 1
fi
grep -q 'failed to localize enclave exit stubs' "$test_root/failure.log" || {
    cat "$test_root/failure.log" >&2
    exit 1
}
echo "ServTD application archive fixup tests passed"
