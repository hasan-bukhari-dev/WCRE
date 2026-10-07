# WCRE Roadmap

## Windows Checkpoint/Restore Engine ("Waker")

WCRE is an experimental Windows x64 checkpoint/restore engine.

Its long-term goal is CRIU-style process checkpoint/restore for Windows:

```text
running process
        |
        v
capture coherent execution state
        |
        v
persist .wcr checkpoint
        |
        v
original process terminates
        |
        v
create replacement process
        |
        v
reconstruct captured process state
        |
        v
restore captured execution state
        |
        v
continue from the captured instruction
```

WCRE is not intended to become an application restart framework, a memory
dumper, or a system that requires applications to cooperate with restoration.

The first major proof is controlled continuation of one captured Windows x64
application thread from a persisted checkpoint without restarting `main()`.

---

# Project phases

| Phase | Goal | Status |
|---|---|---|
| 1 | Process capture | Complete for current controlled scope |
| 2 | Persistent checkpoint image | Complete for current controlled scope |
| 3 | Exact memory reconstruction | Substantial controlled support |
| 4 | Controlled thread resurrection | **Current focus** |
| 5 | Complete x64 process state | Future |
| 6 | Multi-thread restoration | Future |
| 7 | Windows resource restoration | Future |
| 8 | Process-tree checkpoint/restore | Future |
| 9 | Cross-machine migration | Future |
| 10 | Incremental/live migration and production hardening | Long term |

---

# Demonstrated foundation

## Phase 1 — Process capture

WCRE can currently:

- inspect Windows process metadata,
- enumerate virtual address space,
- read live process memory,
- create coherent PSS-backed snapshots,
- inventory loaded images,
- capture thread inventory,
- capture TEB addresses,
- capture TEB-reported stack bounds,
- capture an x64 integer/control register subset,
- capture readable PRIVATE, IMAGE, and other supported payload bytes into the
  WCRE-owned checkpoint model.

## Phase 2 — Persistent checkpoint image

WCRE can currently:

- represent captured process state in `CheckpointModel`,
- encode and decode `.wcr` checkpoint files,
- validate checkpoint structure,
- verify `.wcr` v2 integrity with SHA-256,
- inspect checkpoints after the source process has terminated.

## Phase 3 — Memory reconstruction

WCRE has demonstrated:

- deterministic address-space restore planning,
- exact PRIVATE address reservation and commit,
- captured payload installation,
- byte-for-byte payload readback verification,
- captured page-protection restoration,
- `PAGE_GUARD` restoration,
- debugger-controlled replacement-process staging,
- staging at `CREATE_PROCESS_DEBUG_EVENT`,
- loader-breakpoint staging,
- executable-entry-point staging before the entry instruction executes,
- early address-space fencing,
- staged PRIVATE memory reconstruction,
- checkpoint-specific PE relocation,
- exact main-executable placement across different ASLR epochs,
- verification of required captured IMAGE bases,
- controlled restoration of writable main-executable IMAGE state,
- byte-for-byte verification of the restored writable IMAGE page,
- 10/10 repeatability for the controlled writable IMAGE restoration experiment.

The controlled writable IMAGE experiment restored the main executable's
writable `.data` page at the captured virtual address. This page contains
captured application state such as the controlled target's global sentinel and
counter.

WCRE has **not yet resumed captured execution**.

---

# Phase 4 — Controlled thread resurrection

Phase 4 is the absolute current engineering focus.

The required proof is:

```text
CAPTURE
   |
   v
running controlled target
counter = N
RIP = X
RSP = Y
captured call stack exists
   |
   v
persist .wcr
   |
   v
KILL ORIGINAL PROCESS
   |
   v
create fresh replacement process
   |
   v
reconstruct captured address space
   |
   v
restore captured memory state
   |
   v
reconcile Windows thread/runtime state
   |
   v
install captured CPU context
   |
   v
resume captured RIP/RSP
   |
   v
counter continues from N
```

The replacement must continue captured execution rather than restarting the
program from `main()`.

## M4.1 — Captured application-thread selection

**Complete.**

WCRE deterministically selects the unique captured application thread whose
persisted RIP belongs to the captured main executable and validates its
persisted stack bounds and RSP before destination-thread restoration begins.

Goal:

> Deterministically select the captured application thread whose saved
> instruction pointer belongs to the captured main executable.

Implementation direction:

- keep the selection algorithm in `wcre-image`,
- operate only on persisted `CheckpointModel` state,
- do not hard-code a captured TID,
- require a captured context,
- require `RIP` to belong to the captured main executable,
- require valid captured stack bounds,
- require `stack_limit <= RSP < stack_base`,
- fail if there are zero candidates,
- fail if there are multiple candidates.

Controlled checkpoint expectation:

```text
TID 7032   RIP in ntdll.dll        -> reject
TID 14520  RIP in ntdll.dll        -> reject
TID 16984  RIP in main executable  -> select
```

Acceptance:

- unit tests cover success and ambiguity/failure cases,
- the selector derives the application thread from checkpoint semantics,
- the real controlled checkpoint selects the expected application thread,
- no destination thread is modified yet.

## M4.2 — Destination-thread mapping

**Complete.**

WCRE explicitly maps the selected captured application thread to the fresh
destination primary thread, verifies that the executable-entry breakpoint
belongs to that thread, verifies exact executable bytes at the captured RIP,
and verifies exact reconstructed PRIVATE stack bytes at the captured RSP.

Controlled acceptance passed 5/5 runs. M4.2 does not modify the destination
TEB, install captured CPU context, or resume captured execution.

Goal:

> Explicitly associate the selected captured application thread with the
> replacement process's staged primary thread for the controlled
> single-thread continuation experiment.

Requirements:

- capture-time and destination TIDs are treated as different identities,
- print and verify both captured and destination thread state,
- validate captured RIP ownership,
- validate captured RSP and stack ownership,
- verify that the executable bytes covering the captured RIP are present and
  correct in the reconstructed process,
- keep the destination stopped.

Acceptance:

- one explicit captured-thread -> destination-primary-thread mapping exists,
- all preconditions are verified fail-closed,
- no TEB mutation and no context installation yet.

## M4.3 — TEB reconciliation

**Complete for the current controlled scope.**

WCRE locates the Windows-created destination primary thread's TEB with
`NtQueryInformationThread`, preserves the destination TEB address and `Self`
identity, and reconciles only the public x64 `NT_TIB.StackBase` and
`NT_TIB.StackLimit` fields to the reconstructed captured stack.

The two adjacent 64-bit fields are changed as one 16-byte operation and read
back exactly. The captured RSP is then verified to lie inside the reconciled
stack bounds. In the non-resuming acceptance probe, the original Windows-created
stack metadata is restored before reconstructed PRIVATE memory is released.

Controlled acceptance passed 5/5 runs. WCRE does not copy the captured TEB
wholesale, does not claim restoration of undocumented TEB bookkeeping, does
not install captured CPU context, and does not resume captured execution.

Goal:

> Make the destination Windows-created thread's stack metadata consistent with
> the reconstructed captured stack without replacing the destination TEB.

Working rule:

```text
KEEP
    destination Windows thread identity
    destination Windows-created TEB
    GS/OS-owned thread relationship

RECONCILE
    captured stack-related state required for continuation
```

Research tasks:

- inspect destination `NT_TIB` stack fields at the staged boundary,
- compare them with captured `StackBase`, `StackLimit`, and RSP,
- identify the minimum stack-related state that must change,
- investigate deallocation/stack metadata required for safe continuation,
- preserve OS-owned fields that describe the new thread,
- never copy the old TEB wholesale.

Acceptance:

- destination TEB identity remains destination-owned,
- required stack metadata matches the reconstructed captured stack,
- all modified fields are read back and verified,
- destination remains stopped,
- no captured CPU context is installed yet.

## M4.4 — Captured x64 context installation

**Complete for the current controlled scope.**

Goal:

> Install WCRE's captured integer/control register subset into the staged
> destination thread and verify it without resuming execution.

Implemented behavior:

- obtain the stopped destination primary thread's Windows `CONTEXT`,
- request the x64 control and integer context groups,
- preserve destination-owned state by overlaying only WCRE-owned fields,
- install the captured subset with `SetThreadContext`,
- immediately read the stopped thread back with `GetThreadContext`,
- require all 17 persisted non-EFLAGS fields to match exactly,
- allow only the explicitly modeled Windows normalization of EFLAGS bit `0x2`,
- fail closed on every other EFLAGS difference,
- verify that the reconciled destination TEB remains unchanged,
- restore the original destination CPU context before restoring original
  NT_TIB stack metadata and releasing reconstructed PRIVATE memory.

The native x64 `CONTEXT` storage used at the Win32 boundary is explicitly
16-byte aligned. This was required for reliable `GetThreadContext` and
`SetThreadContext` operation in the controlled experiment.

Current persisted fields are:

```text
RAX RBX RCX RDX
RSI RDI
R8 R9 R10 R11 R12 R13 R14 R15
RIP RSP RBP
EFLAGS
```

This remains intentionally narrower than a complete Win64 execution context.
Floating-point, SIMD/vector, debug-register, and extended XSTATE restoration
are still outside the current claim.

Controlled acceptance passed **5/5 runs**. Across those runs:

- each destination used dynamically discovered process and primary-thread IDs,
- the captured register subset installed successfully,
- all 17 non-EFLAGS fields read back exactly,
- the observed EFLAGS difference was consistently `0x00000002`,
- all non-normalized EFLAGS bits matched,
- context verification passed fail-closed,
- destination TEB identity and reconciled stack metadata remained intact,
- the original destination CPU context was restored for cleanup,
- the original destination NT_TIB stack metadata was restored for cleanup,
- reconstructed PRIVATE allocations were released,
- the destination was terminated cleanly,
- captured execution was never resumed.

M4.4 therefore proves stopped-state installation and verified readback of the
persisted WCRE x64 integer/control subset in the controlled target. It does
**not** prove execution continuation or general Windows process restoration.

## M4.5 — First controlled execution continuation

Goal:

> Resume a fresh replacement process through the captured RIP using the
> reconstructed captured state and prove that execution continues from the
> checkpointed moment.

Before release, verify:

- source process is dead,
- captured executable layout is present,
- captured RIP points into verified executable code,
- captured RSP points into the reconstructed stack,
- captured stack bytes are present,
- controlled stack sentinels are present,
- writable executable state is restored,
- `GLOBAL_SENTINEL == 0x1122334455667788`,
- checkpointed `COUNTER` value is present,
- PRIVATE memory restoration is verified,
- TEB reconciliation is verified,
- captured register subset is installed and read back.

Then release the destination thread.

Success requires:

- destination remains alive,
- execution proceeds from the captured RIP,
- `COUNTER` advances from its checkpointed value rather than restarting,
- the controlled program does not restart `main()`,
- continuation survives repeated acceptance runs.

Target acceptance:

```text
10/10 controlled continuation runs
```

Only after this milestone may WCRE claim:

> WCRE demonstrated controlled single-thread process execution continuation
> from a persisted checkpoint.

This still does not prove general Windows process restoration.

---

# Phase 5 — Complete x64 process state

After first controlled continuation:

- persist a complete restorable Win64 thread context,
- capture and restore floating-point state,
- capture and restore XMM/SIMD state,
- capture and restore MXCSR,
- support applicable extended XSTATE/AVX state,
- clarify segment/debug-register requirements,
- harden TEB/TLS handling,
- reconcile PEB/runtime relationships,
- persist and verify stronger executable identity,
- separate on-disk preferred PE `ImageBase` semantics from captured loaded base,
- classify remaining mutable read-only IMAGE differences,
- generalize mutable IMAGE restoration,
- generalize DLL layout reconstruction,
- add MAPPED-region reconstruction.

---

# Phase 6 — Multi-thread restoration

Goal:

> Restore all required captured application threads rather than mapping one
> captured application thread to one replacement primary thread.

Required work includes:

- recreate or map multiple captured threads,
- restore every required thread stack,
- reconcile each thread's TEB/TLS state,
- restore each thread context,
- understand suspended/waiting states,
- reconstruct synchronization relationships,
- define safe thread release ordering,
- distinguish application threads from runtime/system-created helper threads.

---

# Phase 7 — Windows resource restoration

Kernel-backed resources cannot be restored by copying old numeric handle
values.

WCRE will need semantic resource reconstruction for classes such as:

```text
files
file mappings
sections
events
mutexes
semaphores
pipes
console state
timers
sockets
registry-related state
other supported kernel objects
```

Each resource class needs:

- capture metadata,
- checkpoint representation,
- compatibility validation,
- destination recreation or reconnection,
- mapping from old process semantics to new kernel objects.

---

# Phase 8 — Process trees

Future process-tree work includes:

- parent/child topology,
- multiple process checkpoints,
- shared resources,
- shared mappings,
- IPC relationships,
- coordinated suspend/capture,
- coordinated reconstruction and release.

---

# Phase 9 — Cross-machine migration

Migration begins only after same-machine restore is reliable.

Initial compatibility envelope:

```text
Windows x64 -> Windows x64
same or explicitly compatible Windows build
compatible CPU features
same executable identity
compatible DLL identities
compatible filesystem/resource dependencies
```

A migration-capable checkpoint package will eventually need:

```text
workload.wcr
compatibility manifest
executable hashes
DLL hashes
OS/build metadata
CPU feature requirements
file/resource dependencies
```

Crown-jewel demonstration:

> A long-running computation is checkpointed on Machine A, the original
> process disappears, the checkpoint is transferred to Machine B, and the
> computation continues from the saved point rather than restarting.

---

# Phase 10 — Incremental and production hardening

Long-term work may include:

- incremental checkpoints,
- dirty-page tracking,
- reduced checkpoint pause time,
- live/pre-copy migration research,
- compatibility diagnostics,
- richer checkpoint manifests,
- checkpoint version migration,
- recovery tooling,
- performance profiling,
- stronger corruption handling,
- broader Windows-version testing,
- automated controlled integration tests.

---

# Development rules

Every restoration milestone should follow:

```text
main
  |
  +-- focused branch
        |
        +-- implement
        +-- unit test
        +-- controlled experiment
        +-- inspect diff
        +-- run Windows CI-equivalent local checks
        +-- push
        +-- pull request
        +-- review evidence and claim boundary
        +-- squash and merge
        +-- delete branch
```

Every pull request must state:

- what it proves,
- the evidence supporting that claim,
- what it explicitly does not prove,
- the next milestone.

WCRE should always fail closed when required restore state is missing,
ambiguous, conflicting, or unsupported.

---

# Immediate next task

After repository/GitHub standardization is merged:

```text
M4.1 — Captured application-thread selection
```

Create:

```text
feature/captured-application-thread-selection
```

and implement the model-level selector in `wcre-image`.

No TEB changes, no `SetThreadContext`, and no execution release belong in
M4.1.
