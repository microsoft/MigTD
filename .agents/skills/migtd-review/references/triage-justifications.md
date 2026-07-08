# Boilerplate triage justifications

Reusable text for the `--note` arg of `clawpatch triage`. Adapt the file:line and specifics.

## Out-of-scope feature

```
Dead code in target build: function is gated by `#[cfg(feature = "<X>")]` at
<file>:<line>. The target build set (vmcall-raw, policy_v2, ...) does NOT enable
`<X>`, so the offending code is not compiled. No action needed for this build.
```

## VMM-controlled offsets in shared circular buffer

```
False-positive. The shared log area is a circular buffer where the migtd is the
writer and the VMM is the reader. Wrapping arithmetic in <file>:<line> keeps
write offsets in bounds. VMM-supplied offsets cannot drive OOB reads because the
migtd never reads from the buffer; the VMM only reads. See <writer-fn> for the
wrap logic.
```

## DoS by untrusted VMM

```
Wont-fix. VMM is untrusted and has inherent DoS capability (can starve resources
or kill the TD outright). Unbounded allocation / blocking call here is bounded by
the per-session buffer (max <N> bytes) and the 7 MiB heap — worst case is the TD
exits, which is already part of the VMM's threat surface.
```

## Cert-chain weakness in attested path

```
False-positive. The root CA chain is measured into RTMR<N> and attested via the
TDX quote — see <attestation-init>. A compromised cert alone is insufficient
because the peer's verification of our quote would catch a divergent measurement.
Trust root is hardware attestation, not the software chain.
```

## vmcall-raw 0-byte read

```
False-positive. The vmcall-raw transport in <file>:<line> blocks until data
arrives or returns an error; it never returns Ok(0). The "infinite loop on EOF"
pattern flagged by the static rule does not apply to this transport.
```

## Spurious interrupt wake

```
False-positive. The vmcall-interrupt model broadcasts to all migrations on every
event, but each context re-checks its own buffer status (data_status field) before
acting. Spurious wakes are absorbed correctly — see <buffer-status-check>.
```

## Single-threaded firmware, no race

```
False-positive. MigTD is a single-core, single-threaded no_std firmware. The
flagged access cannot race with another thread; there is no other thread. The
only re-entrancy source is interrupt handlers, which do not mutate the field at
<file>:<line>.
```

## Dead public API

```
Wont-fix. Function is public but has no in-tree callers in the target build.
Verified with `grep -rn "<fn-name>" src/ --include=*.rs` — only the definition is
returned. Will be removed in a future cleanup pass; not exploitable today.
```

## Misspelling without user impact

```
Wont-fix (cosmetic). Misspelled internal identifier <ident> at <file>:<line> is
not user-visible (no print, no API, no wire format). Renaming would touch <N>
call sites without behavior change. Deferred.
```

## Duplicate finding

```
Duplicate of finding <other-id>. Same root cause / same fix surface.
```
