# WCRE

### Windows Checkpoint/Restore Engine

**WCRE** ("Waker") is an experimental user-space checkpoint/restore engine
for Windows x64.

Its long-term goal is CRIU-style process checkpoint/restore for Windows:
capture the execution state of a supported running process, terminate the
original process, reconstruct that state later, and eventually continue
execution from the captured instruction rather than restarting the program
from its entry point.

WCRE is a systems-research project. It is not yet a general-purpose process
restore tool and is not ready for production use.

---

## Current milestone

### M3 — Thread Restoration Research

WCRE has progressed beyond isolated memory reconstruction and now has an
integrated controlled restore-staging pipeline.

The current controlled x64 pipeline can:

- inspect Windows processes and virtual address spaces,
- create coherent PSS-backed snapshots,
- capture virtual-memory metadata and readable payload bytes,
- capture loaded-image inventory,
- capture live-thread inventory,
- capture TEB addresses and TEB-reported stack bounds,
- capture an x64 integer/control register subset including RIP and RSP,
- persist state into versioned `.wcr` checkpoint files,
- verify `.wcr` v2 integrity with SHA-256,
- inspect and validate checkpoints after the source process has terminated,
- derive deterministic Windows x64 address-space reconstruction plans,
- stop a replacement process at `CREATE_PROCESS_DEBUG_EVENT`,
- fence required PRIVATE address ranges before loader initialization,
- allow the normal Windows loader to initialize the replacement process,
- stop before the executable entry instruction executes,
- reconstruct supported PRIVATE allocations at their captured addresses,
- restore and byte-verify captured PRIVATE payloads,
- restore and verify supported memory protections including guard pages,
- prepare a relocated PE32+ bootstrap whose executable image can be loaded at
  a checkpoint's captured base address,
- verify that the captured image-layout requirements are present before memory
  restoration proceeds.

WCRE has **not yet resumed captured execution**.

---

## Current restore boundary

The strongest demonstrated pipeline is:

```text
running Windows process
        |
        v
coherent PSS snapshot
        |
        v
CheckpointModel
        |
        v
integrity-protected .wcr v2
        |
        v
source process may terminate
        |
        v
validated restore plan
        |
        v
checkpoint-specific executable bootstrap
        |
        v
CREATE_PROCESS_DEBUG_EVENT
        |
        v
early address-space fencing
        |
        v
normal Windows loader initialization
        |
        v
stop before executable entry instruction
        |
        +--> verify captured IMAGE bases
        |
        +--> reconstruct supported PRIVATE memory
        |
        +--> install and verify captured payload bytes
        |
        +--> restore and verify page protections
        |
        v
controlled stop
```

The following execution-state transition has **not** yet been performed:

```text
captured TEB/runtime reconciliation
        |
        v
captured CPU context installation
        |
        v
captured RIP/RSP
        |
        v
execution continuation
```

WCRE therefore does **not** yet claim successful process restoration.

---

## Demonstrated IMAGE-layout restoration

Windows ASLR means that simply launching the same executable again does not
guarantee that code will exist at the addresses referenced by a checkpoint.

For the controlled native x64 target, WCRE can now prepare a temporary PE32+
bootstrap by:

1. reading the executable's original on-disk PE `ImageBase`,
2. applying supported `IMAGE_REL_BASED_DIR64` relocations for the captured base,
3. updating the PE `ImageBase`,
4. clearing `DYNAMIC_BASE` and `HIGH_ENTROPY_VA`,
5. launching that temporary image through the normal Windows loader,
6. verifying the resulting captured image layout before restoration continues.

This technique has been demonstrated across different ASLR placements for the
controlled target.

This is **not yet general IMAGE reconstruction**. Other modules are currently
accepted when the Windows loader reproduces their captured addresses; WCRE
does not yet forcibly place arbitrary captured DLLs.

---

## What WCRE captures today

The checkpoint model currently preserves:

- process provenance and architecture,
- loaded-image records,
- virtual-memory-region metadata,
- captured readable memory payloads,
- live-thread records,
- captured TEB addresses,
- TEB-reported stack bounds,
- selected x64 integer/control registers:
  - RAX, RBX, RCX, RDX,
  - RSI, RDI,
  - R8-R15,
  - RIP, RSP, RBP,
  - EFLAGS.

Capture currently contains more state than the restore path knows how to
reconstruct safely.

---

## What remains deliberately incomplete

Important unfinished areas include:

- mutable state inside IMAGE mappings,
- forced reconstruction of arbitrary DLL layouts,
- MAPPED section reconstruction,
- TEB reconciliation,
- TLS restoration,
- full Windows x64 `CONTEXT` restoration,
- floating-point and SIMD/XMM/AVX/XSTATE restoration,
- captured-thread recreation and multithreading,
- PEB and runtime-state reconciliation,
- process heap/runtime relationships,
- kernel HANDLE reconstruction,
- files and file mappings,
- synchronization objects,
- pipes and IPC,
- sockets and network state,
- process trees,
- compatibility across Windows installations,
- machine-to-machine migration.

These are research boundaries, not features WCRE silently approximates.

---

## Architecture

WCRE deliberately separates three layers:

### `wcre-image`

Platform-independent checkpoint representation and persistence.

Owns:

- `CheckpointModel`,
- `.wcr` v1/v2 encoding and decoding,
- SHA-256 checkpoint integrity,
- semantic validation,
- deterministic restore planning.

This crate forbids unsafe Rust and does not expose Win32/PSS structures.

### `wcre-win32`

Windows-specific systems primitives.

Owns:

- process inspection,
- virtual-memory enumeration,
- PSS capture,
- memory reads,
- thread/context capture,
- exact remote allocation,
- remote payload installation,
- protection restoration,
- loader/debugger staging,
- PE relocation for controlled executable-layout reconstruction.

Unsafe Windows interaction is kept at this boundary.

### `wcre-cli`

Developer-facing orchestration and research tooling.

It composes `wcre-image` and `wcre-win32` into checkpoint, inspection,
validation, reconstruction, and controlled restore experiments.

The current CLI is a research interface. A dedicated usability and
productization pass is planned before any public release.

---

## Research progression

The project is advancing through increasingly difficult state classes:

```text
1. Process inspection                         COMPLETE
2. Virtual-address-space enumeration          COMPLETE
3. PSS-backed coherent capture                COMPLETE
4. Thread/context capture                     COMPLETE
5. WCRE-owned checkpoint model                COMPLETE
6. Persistent checkpoint format               COMPLETE
7. Checkpoint integrity and validation        COMPLETE
8. Exact PRIVATE VA reconstruction            COMPLETE
9. PRIVATE payload/protection restoration     COMPLETE
10. Loader-controlled restore staging         COMPLETE
11. Main executable layout recreation         CONTROLLED TARGET
12. IMAGE mutable-state restoration           NEXT
13. TEB/runtime reconciliation                PLANNED
14. CPU-context installation                  PLANNED
15. Single-thread execution continuation      NOT YET DEMONSTRATED
16. Multithread restoration                   FUTURE
17. Kernel/resource reconstruction            FUTURE
18. Supported real-world applications         FUTURE
19. Machine-to-machine migration              LONG-TERM
```

The milestone that changes WCRE from reconstruction research into genuine
checkpoint/restore is:

```text
capture
   |
kill original
   |
reconstruct
   |
install captured runtime/thread state
   |
restore captured RIP/RSP
   |
resume
   |
continue through the preexisting captured call stack
```

Restarting the executable at `main` does not count.

---

## Project principles

- correctness before features,
- evidence before architecture,
- fail closed rather than silently approximate unsupported state,
- no restore claim until captured execution actually resumes,
- explicit compatibility boundaries,
- automated verification wherever practical,
- preserve useful failed experiments,
- keep platform-independent state separate from Windows-owned structures.

---

## Public-release goal

Before WCRE is presented as a usable public tool, the research CLI will receive
a dedicated productization pass focused on:

- coherent command naming,
- clear `--help` output,
- useful defaults,
- actionable errors,
- progress reporting,
- readable restore-stage visualization,
- reproducible examples,
- installation guidance,
- compatibility reporting,
- documentation that explains both what WCRE is doing and why.

The interface should make difficult systems work easier to understand without
hiding the underlying state transitions.

---

## Status

**Experimental Windows x64 systems research.**

WCRE has demonstrated substantial checkpoint capture, persistence,
address-space reconstruction, PRIVATE-memory restoration, loader staging, and
controlled executable-layout recreation.

It has **not yet demonstrated continuation from a captured instruction
pointer** and should not yet be described as a complete Windows process
checkpoint/restore implementation.
