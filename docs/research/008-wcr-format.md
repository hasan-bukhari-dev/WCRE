# Research 008 — Persistent `.wcr` Checkpoint Format

## Status

**PASS — WCRE successfully persisted a captured Windows process model into a standalone `.wcr` checkpoint artifact and reconstructed/queryed that state after the original process had terminated.**

---

## Objective

The goal of this experiment was to cross the boundary from an in-memory WCRE-owned checkpoint representation to an independently persistent checkpoint artifact.

Research 007 established that WCRE could convert coherent Windows Process Snapshotting state into a `CheckpointModel` containing:

- process provenance,
- image/module metadata,
- virtual-memory metadata,
- WCRE-owned memory payload bytes,
- live-thread metadata,
- selected x64 integer/control register state.

Research 008 asks a stronger question:

> Can WCRE serialize that model to disk, terminate the source process, then reconstruct the model from the checkpoint file without depending on the original process, the PSS snapshot, or any live Windows memory reads?

---

## Persistent Format

A new versioned `.wcr` binary format was introduced.

The persistent format version is deliberately separate from the in-memory checkpoint-model version.

Current versions:

- `.wcr` format version: `1`
- `CheckpointModel` version: `1`

The format uses explicit fixed-width wire representations rather than serializing Rust structure layouts directly.

The current format persists:

- process metadata,
- architecture,
- image/module inventory,
- memory-region metadata,
- memory-payload data,
- live-thread metadata,
- selected x64 register state.

---

## Format Safety Properties

The initial `.wcr` decoder includes explicit structural validation.

The implemented validation currently includes:

- magic validation,
- persistent format-version validation,
- checkpoint-model-version validation,
- architecture decoding validation,
- explicit little-endian fixed-width values,
- bounded collection counts,
- bounded string sizes,
- bounded individual payload sizes,
- UTF-8 validation,
- boolean encoding validation,
- memory-state encoding validation,
- memory-kind encoding validation,
- payload-link validation,
- unique payload-ID validation,
- one-to-one payload ownership validation,
- rejection of truncated input,
- rejection of trailing bytes.

Unknown architecture values are encoded and decoded losslessly.

These checks are the beginning of checkpoint-file validation and are not intended to represent the final hostile-input security boundary.

---

## Codec Validation

The `wcre-image` crate now includes tests covering persistent checkpoint behavior.

Validated properties include:

- complete `CheckpointModel` round-trip equality,
- recovery of model-owned memory after serialization,
- invalid-magic rejection,
- unsupported-format-version rejection,
- truncated-checkpoint rejection,
- trailing-garbage rejection,
- lossless unknown-architecture round trip.

At the time of the final experiment:

- `wcre-image`: 12 tests passing,
- `wcre-win32`: 21 tests passing.

No existing WCRE tests regressed.

---

## CLI

Two persistent-checkpoint commands were introduced.

### Create checkpoint

```text
wcre-cli checkpoint --pid <PID> --output <FILE.wcr>
```

This performs:

```text
live process
    ↓
checkpoint-capable PSS snapshot
    ↓
CheckpointModel
    ↓
model validation
    ↓
.wcr serialization
```

### Inspect checkpoint

```text
wcre-cli inspect-checkpoint <FILE.wcr> [--address <HEX> ...]
```

This performs:

```text
.wcr file
    ↓
decode
    ↓
CheckpointModel
    ↓
model validation
    ↓
offline metadata / memory inspection
```

The inspection path does not require the original PID to exist.

---

## Controlled Target

The existing native x64 controlled target was used.

The target plants five known 64-bit sentinels:

| State | Expected value |
|---|---|
| Global sentinel | `0x1122334455667788` |
| Heap sentinel | `0x8877665544332211` |
| Level-one stack local | `0xA1A1A1A1A1A1A1A1` |
| Level-two stack local | `0xB2B2B2B2B2B2B2B2` |
| Level-three stack local | `0xC3C3C3C3C3C3C3C3` |

A fresh controlled target was launched for this experiment.

Source process:

```text
PID:          2708
Architecture: x86_64
```

The target-reported addresses for this run were:

```text
GLOBAL_SENTINEL:         0x00007FF6099B4000
Heap sentinel:           0x0000019654B196E0
Level-one stack local:   0x0000005C75CFF9D8
Level-two stack local:   0x0000005C75CFF990
Level-three stack local: 0x0000005C75CFF600
```

These addresses belonged specifically to PID 2708.

---

## Persistent Checkpoint Creation

The checkpoint was created with:

```text
wcre-cli checkpoint --pid 2708 --output .\experiments\wcr-v1\controlled-2708.wcr
```

WCRE reported:

```text
Source PID:       2708
Architecture:     X64
Loaded images:    6
Memory regions:   101
Memory payloads:  59
Live threads:     1
Payload bytes:    10.47 MiB
File size:        10.48 MiB
```

The physical file size was:

```text
10,984,951 bytes
```

The checkpoint was successfully written to:

```text
C:\Users\hasan\WCRE\experiments\wcr-v1\controlled-2708.wcr
```

---

## Checkpoint Integrity

Before terminating the source process, the checkpoint SHA-256 was:

```text
EAC4C3CF29E9D0162092AF3F2861EA23A176E07FEBD34FC53B2C103422D12C4E
```

The checkpoint was then inspected from disk.

All model integrity checks passed:

```text
Payload links valid:        YES
Payload IDs unique:         YES
Every payload referenced:   YES
```

Captured thread metadata included:

```text
TID:         3200
TEB:         0x0000005C75A48000
StackLimit:  0x0000005C75CFC000
StackBase:   0x0000005C75D00000
RIP:         0x00007FF60999278C
RSP:         0x0000005C75CFF5A0
```

The captured RIP resolved to the controlled target executable.

---

## Sentinel Validation Before Source Termination

While PID 2708 was still alive, WCRE loaded the `.wcr` file and read the five sentinel addresses using the reconstructed checkpoint model.

Results:

| Address | Expected | Observed | Result |
|---|---|---|---|
| `0x00007FF6099B4000` | `0x1122334455667788` | `0x1122334455667788` | MATCH |
| `0x0000019654B196E0` | `0x8877665544332211` | `0x8877665544332211` | MATCH |
| `0x0000005C75CFF9D8` | `0xA1A1A1A1A1A1A1A1` | `0xA1A1A1A1A1A1A1A1` | MATCH |
| `0x0000005C75CFF990` | `0xB2B2B2B2B2B2B2B2` | `0xB2B2B2B2B2B2B2B2` | MATCH |
| `0x0000005C75CFF600` | `0xC3C3C3C3C3C3C3C3` | `0xC3C3C3C3C3C3C3C3` | MATCH |

---

## Source Process Termination

The original process was then forcibly terminated.

WCRE's test harness verified:

```text
PID 2708 no longer exists.
```

At this point:

- the original process no longer existed,
- the original address space no longer existed,
- the original threads no longer existed,
- no live PID could be queried,
- the checkpoint artifact remained on disk.

---

## Artifact Stability After Termination

After PID 2708 had terminated, SHA-256 was calculated again.

Result:

```text
EAC4C3CF29E9D0162092AF3F2861EA23A176E07FEBD34FC53B2C103422D12C4E
```

This exactly matched the pre-termination hash.

Therefore the `.wcr` checkpoint remained byte-for-byte unchanged after the source process ceased to exist.

---

## Sentinel Validation After Source Termination

With PID 2708 confirmed dead, WCRE reopened:

```text
.\experiments\wcr-v1\controlled-2708.wcr
```

The file decoded successfully into a `CheckpointModel`.

The reconstructed model still reported:

```text
Model version:          1
Captured PID:           2708
Architecture:           X64
Loaded images:          6
Memory regions:         101
Memory payloads:        59
Live threads:           1
Payload bytes:          10.47 MiB
```

All payload invariants still passed:

```text
Payload links valid:        YES
Payload IDs unique:         YES
Every payload referenced:   YES
```

The previously captured thread metadata was still present.

Most importantly, all five values were recovered again:

| Address | Expected | Observed | Result |
|---|---|---|---|
| `0x00007FF6099B4000` | `0x1122334455667788` | `0x1122334455667788` | MATCH |
| `0x0000019654B196E0` | `0x8877665544332211` | `0x8877665544332211` | MATCH |
| `0x0000005C75CFF9D8` | `0xA1A1A1A1A1A1A1A1` | `0xA1A1A1A1A1A1A1A1` | MATCH |
| `0x0000005C75CFF990` | `0xB2B2B2B2B2B2B2B2` | `0xB2B2B2B2B2B2B2B2` | MATCH |
| `0x0000005C75CFF600` | `0xC3C3C3C3C3C3C3C3` | `0xC3C3C3C3C3C3C3C3` | MATCH |

---

## What This Demonstrates

Research 008 demonstrates that WCRE can:

1. capture coherent Windows process state,
2. convert that state into a WCRE-owned `CheckpointModel`,
3. serialize the model into a persistent `.wcr` file,
4. terminate the original process,
5. reopen the `.wcr` independently,
6. reconstruct the checkpoint model from disk,
7. validate its internal memory-payload relationships,
8. retain captured process, image, memory, thread, stack, TEB, RIP, and RSP metadata,
9. recover known global, heap, and nested-stack values exactly.

The persistent checkpoint is therefore independent of the continued existence of the original process.

---

## What This Does Not Demonstrate

This experiment does **not** demonstrate process restoration.

WCRE has not yet demonstrated:

- creation of a replacement process,
- exact virtual-address-space reconstruction,
- installation of memory payloads into a replacement process,
- executable-image reconstruction,
- restoration of complete x64 CPU state,
- restoration of SIMD/XMM/XSTATE state,
- TEB reconstruction,
- TLS reconstruction,
- kernel-handle reconstruction,
- synchronization-object reconstruction,
- file-handle restoration,
- IPC restoration,
- process-tree restoration,
- execution continuation,
- machine-to-machine migration.

The `.wcr` artifact contains captured state, but that state has not yet been used to resume a Windows process.

---

## Result

**PASS — persistent checkpoint representation validated.**

The central result is:

> WCRE can capture coherent Windows process state into a standalone persistent `.wcr` checkpoint file and reconstruct/query that captured state after the original process has terminated.

This establishes the persistence boundary required before restore work can begin.

---

## Next Steps

The immediate next milestone is checkpoint-file validation hardening.

Planned work includes:

- stronger structural validation,
- malformed-offset and malformed-length rejection,
- duplicate/overlapping record rejection where applicable,
- integer-overflow validation,
- defensive allocation limits,
- explicit corruption tests,
- checkpoint checksum/integrity strategy,
- eventual fuzz testing.

After the `.wcr` parser is hardened, the next existential restore experiment is:

> Can WCRE reconstruct supported captured virtual-memory regions at their exact original virtual addresses inside a new process?

That begins the restore half of the architecture.
