# Research 005 — PSS Thread Inventory and x64 Register Capture

## Question

Can WCRE capture a useful thread inventory and x64 execution-state subset from the same PSS snapshot used for VA-clone memory capture?

This experiment is capture-only. It does not attempt to recreate, resume, or restore threads.

## Scope

This experiment investigates:

- PSS thread enumeration
- thread lifecycle classification
- per-thread TEB and start-address metadata
- per-thread x64 register contexts
- whether live threads consistently receive contexts
- how terminated thread records should be treated

It does not establish complete Windows thread restoration.

## Capture Method

WCRE now creates a single PSS snapshot with:

- `PSS_CAPTURE_VA_CLONE`
- `PSS_CAPTURE_THREADS`
- `PSS_CAPTURE_THREAD_CONTEXT`

The context flags supplied to `PssCaptureSnapshot` are:

- `CONTEXT_ALL_AMD64`

The same PSS snapshot therefore contains both:

1. the VA clone used for memory capture, and
2. thread metadata/context information.

Threads are enumerated with:

- `PssWalkSnapshot`
- `PSS_WALK_THREADS`

## Context Ownership

`PSS_THREAD_ENTRY::ContextRecord` is exposed as a pointer owned by PSS.

WCRE does not retain this pointer.

The relevant register values are copied immediately into WCRE-owned Rust structures while the PSS walk marker is still alive.

This prevents later code from depending on PSS-owned context memory after its documented lifetime.

## Currently Copied x64 Register State

WCRE currently copies:

- RAX
- RBX
- RCX
- RDX
- RSI
- RDI
- R8
- R9
- R10
- R11
- R12
- R13
- R14
- R15
- RIP
- RSP
- RBP
- EFLAGS

This is intentionally not yet treated as complete restorable x64 CPU state.

State not yet persisted into the WCRE register model includes, among other things:

- XMM/SIMD state
- floating-point state
- MXCSR
- segment state
- debug registers
- other architecture-specific CONTEXT fields

Those must be addressed before claiming complete CPU-state reconstruction.

## Captured Thread Metadata

For each PSS thread entry, WCRE records:

- process ID
- thread ID
- TEB base address
- Win32 start address
- PSS thread flags
- exit status
- suspend count
- priority
- base priority
- context-record size
- copied x64 register subset when present

Thread output is sorted by thread ID for deterministic reporting.

## Initial Observation

Early PowerShell captures appeared incomplete.

Example:

- 25 thread entries
- 14–16 context records
- several entries with:
  - TEB = 0
  - no context record

At first this looked like incomplete PSS thread-context capture.

Further lifecycle instrumentation showed that interpreting every PSS thread entry as a live thread was incorrect.

## Thread Lifecycle Classification

WCRE now distinguishes live and terminated thread entries using the PSS thread flags.

Observed live entries had:

- Flags = `0x0000`
- ExitStatus = `259` (`STILL_ACTIVE`)
- nonzero TEB
- captured context

Observed terminated entries had:

- Flags = `0x0001`
- ExitStatus = `0`
- TEB = `0`
- no context

Therefore a terminated historical PSS thread entry should not be treated as a live thread whose execution context is mysteriously missing.

## Thread-Churn Experiment

A repeated-capture experiment produced:

- Thread entries: 16
- Live threads: 14
- Terminated entries: 2
- Contexts captured: 14
- Live contexts: 14
- Missing live contexts: 0
- Complete live contexts: YES
- Lifecycle status: YES

The two terminated records were:

- marked with thread flag `0x0001`
- no longer active
- missing a TEB
- missing a context record

Every live thread in that snapshot had a context.

## Stable Capture Experiment

A separate capture produced:

- Thread entries: 12
- Live threads: 12
- Terminated entries: 0
- Contexts captured: 12
- Live contexts: 12
- Missing live contexts: 0
- Complete live contexts: YES
- Lifecycle status: YES

This shows that the number of PSS thread entries naturally varies as the target process creates and terminates threads.

## Correct Completeness Rule

The useful checkpoint-oriented rule is not:

> every PSS thread entry must contain a context.

Instead:

> every live thread in the captured PSS snapshot must contain a usable execution context.

Terminated historical thread entries may legitimately have no context.

WCRE therefore tracks:

- total thread entries
- live threads
- terminated entries
- total contexts
- live contexts
- missing live contexts

A thread-context capture is considered complete for this experiment when no live thread is missing its captured context.

## Memory Regression

Adding thread and thread-context capture did not change the previously observed VA-clone memory behavior.

The regression experiment reported:

- complete memory reads
- matching VA layout
- mapped-memory fingerprints stable
- image-memory fingerprints stable
- private-memory fingerprint changed only because of the previously classified volatile page

Region-level private diff reported:

- private regions scanned: 120
- stable regions: 119
- changed regions: 1
- changed-region span: 4 KiB
- known volatile changes: 1
- unexpected changes: 0
- checkpoint candidates: STABLE

The only changed region remained:

- `0x000000007FFE0000`
- 4 KiB
- `KUSER_SHARED_DATA`

This is consistent with Research 004.

## Automated Validation

Workspace tests after this feature:

- 18 passed
- 0 failed

New tests include:

- copying x64 control/integer registers out of a Windows `CONTEXT`
- ensuring terminated PSS thread entries do not count as missing live contexts

Existing memory consistency and volatile-state tests continue to pass.

## Result

**PASS WITH EXPLICIT THREAD-LIFECYCLE CLASSIFICATION AND REGISTER-SCOPE LIMITATION**

For the tested PowerShell workload, WCRE successfully captured:

- a PSS VA clone
- thread inventory
- thread lifecycle metadata
- TEB addresses
- thread start addresses
- complete contexts for every observed live thread
- an owned copy of the selected x64 control/integer register state

The experiment also explained the earlier null-context entries as terminated thread records rather than missing contexts from active threads.

This result is workload-specific experimental evidence, not a universal guarantee for arbitrary Windows processes.

## What This Does Not Prove

This experiment does not yet prove:

- complete x64 CPU-state persistence
- stack correctness
- TEB/TLS restoration
- thread recreation
- exact thread identity reconstruction
- synchronization-object restoration
- kernel-resource restoration
- instruction-pointer resume in a newly created process
- successful checkpoint/restart

Capturing execution state is necessary for checkpoint/restart, but it is not sufficient.

## Next Questions

The next experiments should move toward a controlled native x64 target and answer:

1. Does captured RIP point into the expected module/code region?
2. Does captured RSP lie inside the expected thread stack mapping?
3. Can WCRE identify the complete stack allocation associated with each live thread?
4. Can TEB addresses be correlated with captured stack and TLS-related state?
5. Which additional CONTEXT fields must be persisted for deterministic continuation?
6. Can a deliberately simple single-thread native target expose a known counter and nested call stack for later restore experiments?

The next major milestone is not arbitrary-process restoration.

It is building a controlled native x64 workload whose captured memory, stack, and CPU state can be understood precisely enough to prepare for WCRE's first single-thread continuation experiment.
