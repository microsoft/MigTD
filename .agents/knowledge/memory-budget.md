---
type: Reference
title: Memory Budget — Stack, Heap & Shared Memory
description: Current stack/heap/shared-memory sizing equations for multi-session SPDM attestation, and how the multi-session memory test methodology works.
tags: [memory, heap, stack, spdm, sizing]
timestamp: 2026-07-13T22:37:00+00:00
---

# Memory Budget — Stack, Heap & Shared Memory

Canonical source: [doc/memory_usage_test.md](../../doc/memory_usage_test.md)
(methodology: [PR #556](https://github.com/intel/MigTD/pull/556) pends both
sides mid-attestation to force multiple concurrent sessions since vsock
doesn't support multi-link transport).

## Current sizing equations (destination MigTD, policy v2, SPDM attestation)

```text
Stack Size = 0x20_0000
Heap Size  = 0x10_0000 + 0x8_0000 * session_num
Shared Memory Size = 0x4_0000 + 0x2_0000 * session_num   # vmcall-raw only
```

Per-session heap breakdown: ~`0x2_8000` SPDM context data + ~`0x2_0000` remote
policy data. `0x2_0000` shared-memory-per-session is the max vmcall-raw buffer
for a v2 policy payload.

> Cross-reference: [Domain Facts § Heap allocator](domain-facts.md) records
> the **`ATTEST_HEAP_SIZE = 2 MiB`** production constant and why it was
> bumped from 512 KiB — that is a different (smaller, single-session-focused)
> number from the equations above; don't conflate the two when reasoning
> about OOM reports.

## How to reproduce the test

Build with `test_stack_size,test_heap_size` features + `-l info`, then
manually pend both requester and responder after `key_exchange_rsp` (per the
reference PR) so N session pairs are simultaneously mid-handshake with no
in-flight messages, avoiding the vsock single-link constraint. Read
[doc/memory_usage_test.md](../../doc/memory_usage_test.md) for the full QEMU
socat/vsock wiring if you need to rerun this experiment.

## Caveat

Shared-memory consumption **cannot** be measured with vsock (allocated in the
device layer for vmcall data, and vsock has no multi-link support) — the
equation above is deductive, not measured, for that term.
