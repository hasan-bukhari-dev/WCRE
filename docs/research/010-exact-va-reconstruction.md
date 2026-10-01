# Research 010 — Exact Virtual-Address Reconstruction

## Status

**PASS — WCRE can derive and execute an exact-address reconstruction plan for an explicitly selected subset of captured PRIVATE Windows x64 allocations in a controlled restore host.**

Three captured allocations were reserved and committed at their exact original addresses, verified through `VirtualQueryEx`, and released cleanly. No checkpoint payload bytes, thread contexts, or execution state were installed.

This is address-space reconstruction evidence. It is not process restoration or execution resumption.

---

## Objective

Features 1–9 established capture, coherent snapshotting, WCRE-owned state, persistent `.wcr` images, integrity verification, parser hardening, offline inspection after process death, and atomic publication.

Research 010 begins the reconstruction half with one narrow question:

> Given a captured WCRE checkpoint, can WCRE reproduce a defined subset of its required virtual-address layout at exactly the same addresses inside a fresh controlled process?

The experiment intentionally excludes memory-payload installation and execution state. Its success condition is exact reservation and commitment of selected ranges, not useful program execution.

---

## Architecture

Feature 010 separates planning from execution:

```text
.wcr checkpoint
    ↓
verified CheckpointModel
    ↓
platform-independent AddressSpacePlan
    ↓
explicit operator selection of allocation bases
    ↓
controlled wcre-restore-host process
    ↓
VirtualAllocEx exact reserve/commit
    ↓
VirtualQueryEx verification
    ↓
VirtualFreeEx cleanup
```

The boundaries are deliberate:

- `wcre-image` owns deterministic planning and classification.
- `wcre-win32` owns unsafe Windows handle, allocation, query, conflict, and cleanup operations.
- `wcre-cli` composes the two for developer-facing planning and controlled experiments.
- `wcre-restore-host` is a separate inert x64 executable and is not the capture target.

No planning code calls Windows. No Win32 structures leak into the persistent checkpoint model.

---

## Planning Model

`AddressSpacePlan` records:

- checkpoint architecture,
- ordered reserve and commit operations,
- complete source metadata for each planned region,
- explicitly skipped regions and reasons,
- candidate-region count,
- total reservation bytes,
- total commit bytes.

Every retained source region includes:

- base address,
- allocation base,
- region size,
- allocation protection,
- memory state,
- memory kind,
- current protection,
- optional payload ID.

The plan groups regions by `allocation_base`. This is essential because `VirtualQueryEx` can split one Windows allocation into several regions when their state or protection differs. Reserving every region independently would destroy the original allocation structure and cause self-conflicts.

For each supported allocation group, the plan emits:

```text
RESERVE allocation_base .. allocation_end
COMMIT  each captured committed PRIVATE subregion
```

Operations are deterministic: allocation groups are ordered by allocation base and commits are ordered by region base.

---

## Initial Reconstruction Envelope

The first supported envelope is deliberately conservative.

### Included

An allocation group is a candidate when:

- the checkpoint architecture is x64,
- the complete allocation begins at its recorded allocation base,
- its non-reserved committed regions are PRIVATE,
- its reserve-only regions are PRIVATE or have no defined kind,
- it contains at least one committed PRIVATE region,
- it does not contain a captured TEB,
- it does not overlap the fixed shared-user-data range,
- all executable request boundaries satisfy the required alignment rules.

Both payload-backed and non-payload committed regions retain their payload-presence metadata. Feature 010 allocates address space only and never writes either kind of content.

### Deferred

The planner explicitly defers:

- IMAGE mappings,
- MAPPED sections,
- captured TEB allocations,
- fixed shared-system mappings including KUSER shared data,
- free address-space descriptions,
- unsupported memory states or kinds,
- incomplete allocation groups,
- reserve-only allocations without committed PRIVATE memory.

PEB, loader, TLS, handles, file mappings, and other OS-managed reconstruction are not inferred from a PRIVATE classification. The controlled CLI therefore requires the operator to choose allocation bases explicitly instead of attempting every candidate automatically.

---

## Structural Validation

Planning rejects malformed or unsafe input before any process is opened:

- non-x64 checkpoints,
- zero-sized regions,
- `base + size` overflow,
- non-page-aligned region bases,
- non-page-aligned region sizes,
- non-allocation-granularity-aligned private reservation bases,
- regions that precede their allocation base,
- overlapping non-free regions,
- checkpoint semantic failures.

Windows x64 constants used by the initial envelope are:

| Constraint | Value |
|---|---:|
| Page size | `0x1000` (4 KiB) |
| Reservation allocation granularity | `0x10000` (64 KiB) |

The real checkpoint exposed one important exception: the fixed shared-user-data mapping reported allocation base `0x000000007FFEA000`, which is page-aligned but not 64 KiB-aligned. Because that mapping is always deferred and is never passed to `VirtualAllocEx`, the planner classifies it as shared-system state before applying private-reservation granularity rules. A deterministic regression test preserves this behavior.

---

## Exact Windows Allocation Primitive

`ExactAddressSpaceSession` opens the target with only the process query and VM-operation rights needed for this phase.

Reservation uses:

```text
VirtualAllocEx(
    requested_exact_base,
    requested_size,
    MEM_RESERVE,
    PAGE_NOACCESS
)
```

Commitment uses:

```text
VirtualAllocEx(
    requested_exact_base,
    requested_size,
    MEM_COMMIT,
    PAGE_READWRITE
)
```

`PAGE_READWRITE` is temporary reconstruction protection. Reapplying captured final protections belongs with payload installation in a later feature.

Every successful call verifies that Windows returned exactly the requested pointer. WCRE does not accept, record, or fall back to an alternative address.

If the requested reservation is occupied, WCRE queries that address and returns a first-class `AddressConflict` containing:

- requested base and size,
- the occupying region's base and size,
- its observed state and kind,
- the original Windows allocation error.

Reservations owned by a session are released with `VirtualFreeEx(..., 0, MEM_RELEASE)`. Drop also attempts cleanup, so an intermediate CLI error does not intentionally leave experiment allocations behind.

---

## Controlled Restore Host

Feature 010 adds a dedicated executable:

```text
wcre-restore-host.exe
```

The host:

- requires Windows x64,
- identifies itself and its PID,
- enters a known inert waiting state,
- performs no capture or restore behavior itself,
- does not receive checkpoint payload bytes,
- does not install contexts or resume captured execution.

The reconstruction CLI rejects a target whose executable name is not `wcre-restore-host`. This reduces the risk of using the experiment command against an arbitrary process.

---

## CLI

### Read-only plan

```text
wcre-cli plan-restore <FILE.wcr>
```

This verifies and reads the checkpoint, derives the plan, prints every reserve/commit operation, summarizes deferred classifications, and performs no target-process operation.

### Controlled reconstruction

```text
wcre-cli reconstruct-address-space <FILE.wcr> \
  --host-pid <PID> \
  --allocation-base <HEX> \
  [--allocation-base <HEX> ...]
```

At least one explicit allocation base is required. The base must correspond to a supported `RESERVE` operation printed by `plan-restore`.

The command:

1. verifies the checkpoint and derives the plan again,
2. verifies that the target is the x64 controlled restore host,
3. reserves each selected allocation at its exact base,
4. commits the selected allocation's planned PRIVATE subregions,
5. verifies every reconstructed range with `VirtualQueryEx`,
6. reports conflicts without relocation,
7. releases successful reservations,
8. verifies cleanup returned each base to `MEM_FREE`.

---

## Deterministic Tests

Feature 010 adds coverage for:

- expected committed PRIVATE planning,
- IMAGE deferral,
- MAPPED deferral,
- TEB allocation deferral,
- shared-user-data deferral with its observed alignment exception,
- zero-size rejection,
- range-overflow rejection,
- explicit misalignment rejection,
- deterministic operation order,
- overlap rejection,
- required explicit CLI allocation selection,
- sorted and duplicate-free allocation selections,
- exact reservation at a discovered free address,
- `MEM_RESERVE` visibility through `VirtualQueryEx`,
- exact commit and `MEM_COMMIT`/`MEM_PRIVATE` visibility,
- occupied-address conflict reporting rather than relocation,
- cleanup returning the range to `MEM_FREE`.

The live allocation test discovers a free 64 KiB-aligned range in the test process rather than relying on a hard-coded ASLR-sensitive address.

---

## Real Checkpoint Plan

The Feature 009 controlled v2 checkpoint was reused:

```text
C:\Users\hasan\WCRE\experiments\live-demo-v2\controlled-demo-v2.wcr
```

The read-only plan reported:

| Metric | Result |
|---|---:|
| Captured regions | 111 |
| PRIVATE regions | 25 |
| IMAGE regions | 41 |
| MAPPED regions | 16 |
| Candidate regions | 19 |
| Planned reservations | 8 |
| Planned commits | 12 |
| Planned reservation bytes | `0x2535000` (37.21 MiB) |
| Planned commit bytes | `0x30000` (192 KiB) |
| Deferred regions | 92 |

Deferred classification was:

| Reason | Regions |
|---|---:|
| Free address space | 29 |
| IMAGE mapping deferred | 41 |
| MAPPED section deferred | 16 |
| TEB allocation deferred | 3 |
| Shared system mapping deferred | 2 |
| No committed PRIVATE memory | 1 |

This output is evidence that the planner does not equate every captured mapping with a safe reconstruction request.

---

## Controlled Reconstruction Evidence

### Single-allocation proof

A fresh controlled restore host was launched for the first proof:

```text
Restore-host PID: 8600
Image: C:\Users\hasan\WCRE\target\debug\wcre-restore-host.exe
```

One payload-backed PRIVATE allocation was selected explicitly:

```text
Requested reservation: 0x00000198EDF60000–0x00000198EDF62000
Requested commit:      0x00000198EDF60000–0x00000198EDF62000
Size:                  0x2000 (8 KiB)
Reservation result:    EXACT
Commit result:         EXACT
Address conflicts:     0
Temporary cleanup:     VERIFIED
Command exit:          0
Host alive afterward:  YES
```

The entire 8 KiB range was observed as committed at the captured address through `VirtualQueryEx`. The command then released it, verified that the address returned to `MEM_FREE`, and left the restore host healthy. The host was terminated after the experiment.

### Three-allocation proof

A second fresh controlled restore host was launched:

```text
Restore-host PID: 21688
Image: C:\Users\hasan\WCRE\target\debug\wcre-restore-host.exe
```

Three payload-backed PRIVATE allocations were selected explicitly from the plan:

| Allocation base | Reserved range | Committed range | Result |
|---|---|---|---|
| `0x00000198EDF60000` | `0x00000198EDF60000–0x00000198EDF62000` | same 8 KiB range | EXACT |
| `0x00000198EE000000` | `0x00000198EE000000–0x00000198EE032000` | `0x00000198EE000000–0x00000198EE002000` | EXACT |
| `0x00000198EE180000` | `0x00000198EE180000–0x00000198EE280000` | `0x00000198EE180000–0x00000198EE194000` | EXACT |

Combined selected scope:

```text
Exact reservations:       3
Exact committed ranges:   3
Selected reserve bytes:   0x134000 (1,261,568 bytes)
Selected commit bytes:    0x18000 (98,304 bytes)
Address conflicts:        0
Temporary cleanup:        VERIFIED
Command exit:             0
Host alive after cleanup: YES
```

The restore host was terminated after the experiment.

No payload data was copied into these ranges. The committed pages therefore contain ordinary zero-initialized Windows allocation contents, not restored process memory.

---

## Conflict Evidence

The selected live subset encountered no conflicts.

Conflict behavior was proven deterministically in the Win32 test: after reserving a discovered free exact range, a second exact reservation request for that same range returned `AddressConflict`. WCRE did not accept a different address. The original reservation remained queryable and was then released successfully.

Future experiments should treat actual restore-host conflicts as useful architectural evidence. They must be reported and classified, never hidden by relocation.

---

## Validation

At Feature 010 completion:

```text
cargo fmt --all -- --check    PASS
cargo check --workspace       PASS
cargo test --workspace        103 passed, 0 failed
git diff --check              PASS
```

Test distribution:

| Component | Passing tests |
|---|---:|
| `wcre-image` | 71 |
| `wcre-cli` | 10 |
| `wcre-win32` | 22 |
| Controlled executable targets | 0 |
| Total | 103 |

---

## What This Proves

Feature 010 proves that WCRE can:

1. derive a deterministic, allocation-aware reconstruction plan from a verified checkpoint,
2. retain the checkpoint metadata needed by later payload and protection phases,
3. explicitly defer unsupported or OS-managed region classes,
4. require operator selection rather than blindly allocating every candidate,
5. reserve selected PRIVATE allocations at their exact captured addresses in a controlled x64 restore host,
6. commit selected subregions at their exact captured addresses,
7. verify reconstructed ranges independently through `VirtualQueryEx`,
8. expose occupied addresses as first-class conflicts without relocation,
9. clean up temporary reconstruction state without terminating or corrupting the host.

The strongest supported claim is:

> WCRE can derive and execute an exact-address reconstruction plan for a defined subset of captured Windows private virtual-memory allocations in a controlled restore host.

---

## What This Does Not Prove

Feature 010 does **not** prove process restoration.

It does not demonstrate:

- copying checkpoint payload bytes into reconstructed ranges,
- restoring captured page protections after payload installation,
- reconstructing executable IMAGE mappings,
- reconstructing MAPPED sections or shared memory,
- restoring PEB, TEB, TLS, loader, or runtime state,
- installing complete CPU or XSTATE contexts,
- setting RIP or RSP,
- recreating threads,
- rebuilding handles, files, synchronization objects, IPC, or process trees,
- resuming captured execution,
- long-running computation recovery,
- machine-to-machine migration.

The reconstructed pages were temporary, zero-initialized address-space structures. They were not restored application memory.

---

## Result and Next Boundary

**PASS — exact VA reconstruction for the defined controlled subset is validated.**

Feature 010 is ready to merge after the final clean repository validation.

The recommended Feature 011 starting point is memory-payload installation into already reconstructed PRIVATE committed ranges, followed by byte-for-byte readback verification and captured-protection application. Feature 011 must continue to exclude context installation and execution resumption until payload identity and protection semantics are independently proven.
