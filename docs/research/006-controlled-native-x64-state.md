# Research 006 — Controlled Native x64 Execution-State Correlation

## Question

Can WCRE capture a controlled native Windows x64 process and demonstrate that CPU state, process memory, TEB metadata, and thread-stack state are internally coherent within the same PSS snapshot?

This experiment builds on Research 005.

Research 005 established that PSS can provide thread inventory and contexts.

Research 006 asks a stronger question:

> Do the captured registers actually correspond to known program state and known memory inside the same checkpoint observation?

## Controlled Target

A dedicated native x64 test program was added under:

`tests/targets/native-x64`

The target was compiled with:

`x86_64-pc-windows-msvc`

The target deliberately exposes known state so WCRE does not have to infer the meaning of an arbitrary application's memory.

The program contains:

- one intended application thread
- a known global sentinel
- a known heap sentinel
- three nested non-inlined functions
- one recognizable stack-local sentinel in each nested function
- a continuously changing counter
- a hot execution loop

The nested calls are:

`level_one -> level_two -> level_three`

The target remains inside `level_three` during the capture window.

## Known Sentinel Values

The target deliberately stores:

- global: `0x1122334455667788`
- heap: `0x8877665544332211`
- level-one stack local: `0xA1A1A1A1A1A1A1A1`
- level-two stack local: `0xB2B2B2B2B2B2B2B2`
- level-three stack local: `0xC3C3C3C3C3C3C3C3`

These values are intentionally distinctive so accidental matches are unlikely.

## Representative Target Run

One representative run used:

- source PID: 6588
- primary thread ID: 1900

The target reported:

- `level_one`: `0x00007FF76ACB28C0`
- `level_two`: `0x00007FF76ACB2900`
- `level_three`: `0x00007FF76ACB1E60`

Stack-local addresses were:

- level one: `0x000000B07099F808`
- level two: `0x000000B07099F7C0`
- level three: `0x000000B07099F430`

The heap sentinel was located at:

`0x000002964E738F80`

The global sentinel was located at:

`0x00007FF76ACD4000`

These virtual addresses are representative of this run and are not expected to remain identical between launches.

## Same-Snapshot CPU and Memory Correlation

WCRE added a research primitive that:

1. creates one thread-capable PSS snapshot,
2. captures thread CPU contexts from that snapshot,
3. reads exact requested addresses from that snapshot's VA clone.

This is important because CPU state and memory values are therefore derived from the same checkpoint observation rather than separate captures.

For the controlled target, the snapshot reported:

- RIP: `0x00007FF76ACB278C`
- RSP: `0x000000B07099F3D0`
- RBP: `0x000000B07099F890`

The same snapshot returned all five expected sentinel values exactly:

- global: `0x1122334455667788`
- heap: `0x8877665544332211`
- level one: `0xA1A1A1A1A1A1A1A1`
- level two: `0xB2B2B2B2B2B2B2B2`
- level three: `0xC3C3C3C3C3C3C3C3`

No requested eight-byte read failed.

## RIP Correlation

The captured RIP fell within the executable image containing the controlled target.

The automatic validator later classified the RIP mapping as:

- State: Commit
- Type: Image
- Protection: RX

Representative region:

`0x00007FF76ACB1000 - 0x00007FF76ACCA000`

The captured RIP therefore refers to committed executable image memory.

This is substantially stronger evidence than merely observing a nonzero instruction pointer.

## TEB and Stack Metadata

The PSS thread entry exposed the thread's TEB address:

`0x000000B070B1C000`

For native Windows x64, the experiment read the relevant NT_TIB fields from the captured TEB:

- TEB + `0x08`: StackBase
- TEB + `0x10`: StackLimit
- TEB + `0x30`: Self

The same snapshot returned:

- StackBase: `0x000000B0709A0000`
- StackLimit: `0x000000B07099C000`
- Self: `0x000000B070B1C000`

The Self field exactly matched the PSS-reported TEB address.

## Stack Correlation

The captured RSP was:

`0x000000B07099F3D0`

The TIB-reported interval was:

`0x000000B07099C000 <= RSP < 0x000000B0709A0000`

Therefore the captured RSP lies inside the thread's TIB-reported stack bounds.

The deliberately planted nested stack locals also lie inside that interval.

Relative to the captured RSP:

- level-three sentinel: RSP + `0x60`
- level-two sentinel: RSP + `0x3F0`
- level-one sentinel: RSP + `0x438`

Their values were verified from the same PSS VA clone.

This produces the experimentally observed relationship:

PSS thread entry
-> TEB
-> NT_TIB stack metadata
-> captured RSP
-> known nested stack state

## Automatic Thread-State Validator

The experiment was converted from manual address comparison into a reusable WCRE validator.

For each live thread with a context, WCRE now derives:

- process ID
- thread ID
- TEB address
- TEB Self value
- StackLimit
- StackBase
- RIP
- RSP
- RBP
- memory region containing RIP
- memory region containing RSP

It validates:

- TEB Self equals the PSS-reported TEB
- StackLimit is below StackBase
- RSP lies inside the TIB-reported stack interval
- RIP lies in committed executable image memory
- RSP lies in committed private memory

The controlled target produced:

- TEB self valid: YES
- Stack bounds valid: YES
- RSP inside TIB stack: YES
- RIP executable image: YES
- RSP committed private: YES
- Thread validation: YES
- All invariants: YES

The RSP region was classified as:

- State: Commit
- Type: Private
- Protection: RW

Representative region:

`0x000000B07099C000 - 0x000000B0709A0000`

## Capture-Policy Separation

During this feature, WCRE's PSS capture policy was corrected.

Previously, the general `capture_va_clone` helper also requested:

- thread inventory
- thread contexts

even for experiments that only required VA-clone memory.

The capture path is now separated:

- `capture_va_clone` requests only `PSS_CAPTURE_VA_CLONE`
- thread-aware experiments explicitly request VA clone + threads + thread contexts

This preserves the semantics and failure surface of memory-only experiments.

## VA-Only Regression

After separating the capture policies, the controlled target's memory-only regression still reported:

- stable regions: 9
- changed regions: 1
- changed span: 4 KiB
- known volatile changes: 1
- unexpected changes: 0
- checkpoint candidates: STABLE

The only observed changed page remained:

`0x000000007FFE0000`

classified as:

`KUSER_SHARED_DATA`

This is consistent with Research 004.

## Transient Thread Observation

The controlled target is intended to be single-threaded.

Most observations matched that expectation.

One earlier PSS capture contained several additional live-looking entries.

A later capture contained one additional entry whose ProcessId matched the controlled target.

That transient thread executed within `ntdll.dll`.

Its cause was not established.

To characterize the behavior, WCRE performed 20 consecutive captures while also querying the process thread list immediately before and after each snapshot.

All 20 samples reported:

- Windows before capture: 1 thread
- PSS snapshot: 1 thread
- Windows after capture: 1 thread
- thread ID: 1900

A second 12-run validation performed after the final thread-state validator was implemented produced the same result on every run:

- Windows before capture: 1 thread
- PSS snapshot: 1 thread
- Windows after capture: 1 thread
- thread ID: 1900

Therefore the controlled workload is stably single-threaded in the tested steady state.

The earlier additional thread observations remain documented as rare transient behavior of unknown cause.

WCRE does not currently assume that an unexplained transient thread is created by PSS, the Rust runtime, or any other specific subsystem.

## Automated Validation

All existing workspace tests continued to pass throughout the experiment.

Additional unit tests cover:

- half-open StackLimit/StackBase membership semantics
- executable page-protection classification
- virtual-memory-region boundary lookup

## Result

**PASS**

For the controlled native Windows x64 target, WCRE demonstrated that one PSS snapshot can contain mutually consistent:

- thread identity
- selected x64 CPU register state
- TEB identity
- TIB-reported stack metadata
- executable instruction-pointer mapping
- stack-pointer memory mapping
- known global data
- known heap data
- known nested stack-local data

This is WCRE's first controlled demonstration that captured execution state can be correlated with program state whose ground truth was deliberately designed in advance.

## What This Does Not Prove

This experiment does not prove:

- complete x64 CPU-state persistence
- restoration of SIMD/FPU state
- stack unwinding correctness
- restoration of TEB/TLS state
- recreation of a Windows thread
- exact virtual-address reconstruction in a new process
- kernel-resource reconstruction
- instruction-pointer continuation after process recreation
- successful checkpoint/restart

The observed TIB StackLimit/StackBase interval should also not yet be treated as a complete description of the thread's full reserved stack allocation.

Guard pages, reservation boundaries, and stack-growth behavior require separate analysis.

## Significance for WCRE

Previous experiments established increasingly stronger capture properties:

1. process inspection
2. virtual-memory enumeration
3. live memory reading
4. PSS VA-clone memory consistency
5. PSS thread inventory and x64 context capture
6. controlled execution-state correlation

Research 006 crosses an important boundary.

WCRE is no longer only collecting opaque process state.

For a controlled native x64 workload, it can now validate relationships between captured CPU state and captured memory state.

That is necessary groundwork for eventually determining whether a captured thread can be reconstructed and resumed correctly.

## Next Direction

The next phase should stop expanding ad-hoc diagnostics and begin shaping captured state into an explicit checkpoint representation.

Before attempting continuation, WCRE still needs to define and preserve:

- complete memory-region metadata
- memory payloads
- module/image identity
- complete required CPU context
- per-thread stack metadata
- TEB/TLS-related state
- checkpoint format versioning and integrity
- explicit restore ordering and compatibility checks

The eventual existential milestone remains:

> recreate a controlled single-thread native x64 process from captured state and continue execution from its saved instruction pointer with its captured stack intact.

Research 006 does not achieve that milestone.

It makes that milestone substantially more concrete.

