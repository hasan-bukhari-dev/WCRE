# Research 007 — WCRE-Owned Checkpoint Model

## Status

**PASS — in-memory checkpoint model established with coherent memory payload capture and controlled-state validation.**

This experiment does **not** demonstrate process restoration.

It demonstrates that WCRE can convert state captured from one Windows Process Snapshotting (PSS) snapshot into a WCRE-owned, platform-independent in-memory checkpoint representation and preserve meaningful controlled process state inside that representation.

---

## Objective

Previous WCRE experiments established that Windows Process Snapshotting can provide a sufficiently coherent observation point for:

- virtual-address-space metadata,
- readable process memory,
- loaded image identity,
- live thread inventory,
- selected x64 register state,
- TEB-derived stack metadata.

Those experiments still depended directly on Windows/PSS objects.

The purpose of Research 007 was to introduce a WCRE-owned checkpoint representation that separates later serialization and restoration work from raw Windows snapshot structures.

The central question was:

> Can WCRE convert a coherent PSS snapshot into its own checkpoint model while preserving meaningful process memory and execution metadata?

---

## New `wcre-image` crate

A new workspace crate was introduced:

`crates/wcre-image`

The crate contains the platform-independent checkpoint model and forbids unsafe Rust.

The model currently contains:

- process provenance,
- process architecture,
- loaded PE image metadata,
- virtual-memory-region metadata,
- memory payloads,
- live thread metadata,
- selected x64 integer/control register state.

The current model version is:

`CHECKPOINT_MODEL_VERSION = 1`

This model version is an in-memory schema version.

It is **not** a `.wcr` checkpoint-file format version.

---

## Checkpoint Model Structure

The primary representation is `CheckpointModel`.

It contains:

- `ProcessRecord`
- `Vec<ImageRecord>`
- `Vec<MemoryRegionRecord>`
- `Vec<MemoryPayload>`
- `Vec<ThreadRecord>`

Memory-region metadata is deliberately separated from captured bytes.

A memory region may reference a payload using `payload_id`.

A payload contains:

- a unique payload ID,
- its virtual base address,
- the exact captured bytes owned by WCRE.

---

## Capture Source

`capture_checkpoint_model(pid)` uses stable source-process information for process provenance and then creates one checkpoint-capable PSS snapshot.

The same snapshot supplies volatile execution state.

From that snapshot WCRE derives:

- thread inventory,
- selected x64 contexts,
- TEB stack metadata,
- loaded image inventory,
- virtual-memory-region metadata,
- memory payload bytes.

Memory payload reads are performed against the PSS VA-clone process handle associated with that same snapshot.

This prevents the checkpoint model from mixing memory gathered from a separate live-process observation with thread and image state from the snapshot.

---

## Memory Payload Policy

For this experiment WCRE captures complete bytes for regions that are:

1. committed,
2. readable according to the existing WCRE page-protection classifier,
3. not explicitly classified as known Windows-managed volatile state.

The policy currently includes readable:

- `MEM_PRIVATE`,
- `MEM_MAPPED`,
- `MEM_IMAGE`

regions.

Including readable image pages is intentional.

Mutable process state may reside inside image-backed sections, so restricting payload capture to private memory would not preserve all controlled workload state.

Unreadable, guarded, reserved, and free regions do not receive payloads.

---

## Known Volatile Windows State

The Windows x64 `KUSER_SHARED_DATA` page at:

`0x000000007FFE0000`

was previously observed changing even within VA-clone consistency experiments.

WCRE therefore continues to classify this page explicitly as Windows-managed volatile system state rather than ordinary immutable process-owned checkpoint data.

It is excluded from checkpoint payload capture by the current policy.

---

## Complete-Region Requirement

A `MemoryPayload` represents a complete region.

Payload capture is chunked internally, but WCRE does not silently record an incomplete region as a valid payload.

If a selected region cannot be copied completely, checkpoint-model capture fails rather than attaching partial data to that region.

This preserves a clear invariant:

> If a memory region contains a payload ID, the referenced payload represents the complete captured byte range of that region.

---

## Model Memory Access

`CheckpointModel` now supports reading captured bytes by virtual address.

The model provides:

- `read_bytes(address, length)`
- `read_u64(address)`

These operations read only WCRE-owned `MemoryPayload` data.

They do not access:

- the original process,
- a PSS handle,
- the VA clone,
- `ReadProcessMemory`,
- any other Windows API.

A unit test verifies little-endian `u64` recovery directly from model-owned bytes.

---

## Payload Integrity Invariants

The checkpoint model now validates several structural relationships.

### Payload link validity

Every populated `MemoryRegionRecord.payload_id` must resolve to exactly one payload.

That payload must have:

- the same base address as the region,
- a byte length equal to the region size.

### Unique payload IDs

Every payload ID must be unique within the model.

### Payload ownership

Every payload must be referenced by exactly one memory region.

### Payload byte accounting

The model can calculate the total number of captured payload bytes.

These checks are surfaced by the `checkpoint-model` CLI experiment.

---

## Controlled Target Validation

The existing controlled native x64 target was used for validation.

The target plants five known 64-bit sentinels representing distinct categories of process memory:

| State | Expected value |
|---|---|
| Global sentinel | `0x1122334455667788` |
| Heap sentinel | `0x8877665544332211` |
| Level-one stack local | `0xA1A1A1A1A1A1A1A1` |
| Level-two stack local | `0xB2B2B2B2B2B2B2B2` |
| Level-three stack local | `0xC3C3C3C3C3C3C3C3` |

For the recorded validation run, the known addresses were:

- global: `0x00007FF6099B4000`
- heap: `0x00000166262B96F0`
- level-one stack local: `0x00000011475EFC28`
- level-two stack local: `0x00000011475EFBE0`
- level-three stack local: `0x00000011475EF850`

A checkpoint model was captured for PID `6992`.

The model contained:

- 102 memory regions,
- 59 memory payloads,
- 10,977,280 payload bytes.

Each sentinel was then read using `CheckpointModel::read_u64()`.

Observed results:

| Address | Expected | Observed | Result |
|---|---|---|---|
| `0x00007FF6099B4000` | `0x1122334455667788` | `0x1122334455667788` | MATCH |
| `0x00000166262B96F0` | `0x8877665544332211` | `0x8877665544332211` | MATCH |
| `0x00000011475EFC28` | `0xA1A1A1A1A1A1A1A1` | `0xA1A1A1A1A1A1A1A1` | MATCH |
| `0x00000011475EFBE0` | `0xB2B2B2B2B2B2B2B2` | `0xB2B2B2B2B2B2B2B2` | MATCH |
| `0x00000011475EF850` | `0xC3C3C3C3C3C3C3C3` | `0xC3C3C3C3C3C3C3C3` | MATCH |

Result:

`Model payload validation: PASS`

This proves that known global, heap, and nested-stack state survived the conversion from PSS snapshot state into the WCRE-owned checkpoint model.

---

## Final Model Validation

A later controlled capture reported:

- model version: 1
- architecture: x64
- loaded images: 6
- memory regions: 102
- live threads: 1
- memory payloads: 59
- payload-linked regions: 59
- payload size: approximately 10.47 MiB

Model integrity checks reported:

- all live contexts present: YES
- all stack metadata present: YES
- image inventory present: YES
- memory map present: YES
- payload links valid: YES
- payload IDs unique: YES
- every payload referenced exactly once: YES

The primary captured thread's instruction pointer resolved into the controlled target executable and its stack pointer remained within the TEB-reported stack interval.

---

## Thread-Count Observation

Some captures of the controlled target temporarily exposed additional live thread entries whose instruction pointers resolved inside `ntdll.dll`.

Other captures returned to the target's expected single live thread.

Research 006 already established that the controlled workload has a stable single-threaded steady state while transient thread observations can occur.

Research 007 therefore does not require the captured thread count to always equal one.

The checkpoint model must represent the live thread set observed by the snapshot rather than assuming a fixed thread count.

No causal claim is made here about the origin of transient Windows thread entries.

---

## Automated Tests

After this experiment the workspace contains:

- 5 `wcre-image` tests,
- 21 `wcre-win32` tests,
- controlled-target and CLI test harnesses.

The model-specific tests include validation for:

- checkpoint model version initialization,
- separation of memory metadata and payload bytes,
- distinction between loaded and preferred image bases,
- model-owned `u64` reads,
- payload-link integrity.

All tests pass.

---

## What This Experiment Demonstrates

Research 007 demonstrates that WCRE can:

- construct a Windows-independent in-memory checkpoint representation,
- preserve stable process provenance,
- preserve loaded-image identity,
- preserve virtual-address-space metadata,
- preserve live-thread metadata,
- preserve selected x64 integer/control register state,
- preserve TEB-reported stack metadata,
- copy complete readable memory regions from the same PSS VA clone,
- associate those bytes with their virtual-memory regions,
- validate payload-table integrity,
- query captured memory without using the source process or PSS,
- recover known global, heap, and nested-stack values exactly from WCRE-owned data.

---

## What This Experiment Does Not Demonstrate

Research 007 does **not** demonstrate:

- process restoration,
- recreation of a process from the checkpoint model,
- exact virtual-address reconstruction in a new process,
- continuation from captured RIP,
- restoration of RSP/RBP,
- complete Windows x64 `CONTEXT` restoration,
- SIMD/XMM/AVX/XSTATE restoration,
- TLS restoration,
- TEB reconstruction,
- thread recreation,
- synchronization-object restoration,
- handle recreation,
- file-state restoration,
- IPC restoration,
- GUI restoration,
- cross-machine migration,
- `.wcr` serialization,
- persistent checkpoint integrity.

Those remain later milestones.

---

## Conclusion

**PASS**

WCRE now owns a coherent in-memory representation of meaningful captured process state instead of depending directly on PSS structures after capture.

The controlled experiment demonstrated exact recovery of planted global, heap, and nested-stack values from WCRE-owned payload memory.

This establishes the representation boundary required before persistent checkpoint serialization and later restoration experiments.

The next major step is to define the first versioned `.wcr` checkpoint-file format capable of serializing and reconstructing this model without loss.
