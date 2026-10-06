# Research 012 — Restore Staging and Executable Image Layout Reconstruction

## Status

**PASS — WCRE can stage a controlled Windows x64 restore target through the
Windows loader, fence required checkpoint address ranges before loader
initialization consumes them, reconstruct supported PRIVATE memory, and
recreate the captured main-executable image base across different ASLR
placements.**

The strongest demonstrated path now reaches the executable entry-point
breakpoint with:

- the application entry instruction still unexecuted,
- the captured main executable loaded at its checkpoint address,
- all captured image bases required by the controlled test reproduced,
- supported PRIVATE allocations reconstructed at exact addresses,
- captured PRIVATE payload bytes installed and byte-for-byte verified,
- captured supported protections restored and verified,
- temporary restore bootstrap files cleaned up correctly.

WCRE still does **not** install the captured TEB, captured CPU context, RIP/RSP,
or resume captured execution.

This research therefore establishes a controlled restore **staging** pipeline,
not completed process restoration.

---

## Objective

Research 011 established that WCRE could restore selected PRIVATE memory
contents and protections inside another process.

The next problem was substantially harder:

> Can WCRE create a legitimate replacement Windows process, stop it at useful
> loader boundaries, protect checkpoint address ranges before the loader
> consumes them, reconstruct the captured memory state, and ensure that code is
> present at the virtual addresses referenced by the checkpoint?

This required solving several related problems:

```text
replacement process creation
        |
        v
loader staging
        |
        v
early address-space control
        |
        v
integrated PRIVATE reconstruction
        |
        v
ASLR / executable-address mismatch
        |
        v
captured executable-layout recreation
```

These steps form the bridge between memory restoration and future thread
resurrection.

---

## 1. Why a Replacement Process Is Needed

A checkpoint contains state from a process that may no longer exist.

WCRE therefore cannot restore into the original process object.

A new Windows process must be created and used as the restore carrier.

The first controlled scaffold used:

```text
CreateProcessW(..., CREATE_SUSPENDED, ...)
```

This provided:

- a real Windows process object,
- a real primary thread,
- a real process handle,
- a real thread handle,
- a destination whose application code had not been allowed to run.

The initial scaffold was implemented in:

```text
1969d73 — Add suspended process restore scaffold
```

A CLI probe followed:

```text
2deab6c — Add suspended restore scaffold probe
```

The probe verified that WCRE could inspect the new process, inspect its virtual
address space, inspect loaded images, capture its initial thread state, and
terminate it without ever calling `ResumeThread`.

This established a safe first destination process.

---

## 2. Why `CREATE_SUSPENDED` Alone Was Not Enough

A process created with `CREATE_SUSPENDED` is stopped too early for the eventual
restore strategy.

At that point, Windows has not necessarily completed the loader work required
to establish the normal runtime structures WCRE wants to preserve rather than
reimplement immediately.

WCRE therefore needed finer control over **how far Windows initialization is
allowed to proceed**.

The chosen mechanism was the Windows debugger event model.

Conceptually:

```text
CreateProcess
    |
    v
CREATE_PROCESS_DEBUG_EVENT
    |
    v
loader initialization
    |
    v
initial loader breakpoint
    |
    v
more loader work
    |
    v
executable entry point
    |
    v
application instructions
```

WCRE's goal became:

> Allow legitimate Windows initialization, but stop before the first
> application instruction executes.

---

## 3. Loader-Breakpoint Staging

WCRE introduced `LoaderDebugSession` to create and control a debugged
destination process.

The first milestone stopped the process at the Windows loader's initial
breakpoint.

Relevant implementation:

```text
76fbf24 — Stage restore process at loader breakpoint
```

This established that WCRE could:

- create the replacement under debugger control,
- observe `CREATE_PROCESS_DEBUG_EVENT`,
- advance Windows initialization,
- detect the initial breakpoint,
- keep the process stopped,
- terminate the destination without releasing incomplete restored execution.

This was the first useful loader-controlled restoration boundary.

---

## 4. Executable Entry-Point Staging

The next experiment allowed the loader to advance further and placed a
breakpoint at the executable's entry point.

Relevant implementation:

```text
985d2e2 — Stage restore process at executable entry point
```

WCRE reads the PE entry-point RVA, derives the loaded entry address, places a
software breakpoint there, allows loader execution to proceed, and stops when
the breakpoint is reached.

At this boundary:

```text
Windows loader initialization      completed far enough for the experiment
application entry address          reached
application entry instruction      NOT executed
```

That distinction is essential.

Restarting the target normally and allowing `main()` to execute would destroy
the meaning of later checkpoint continuation experiments.

---

## 5. Staging at `CREATE_PROCESS_DEBUG_EVENT`

By the time the executable entry point is reached, Windows may already have
consumed portions of the virtual address space that a checkpoint expects WCRE
to reconstruct.

The restore pipeline therefore needed an even earlier control point.

WCRE added the ability to return control while
`CREATE_PROCESS_DEBUG_EVENT` itself is still pending.

Relevant implementation:

```text
ca05189 — Stage restore process at create-process debug event
```

At this point WCRE has:

- a new process,
- a new primary thread,
- Windows-created process/thread runtime state,
- the executable mapping,
- debugger control,

while still being early enough to inspect and reserve important checkpoint
addresses before later loader activity.

---

## 6. Checkpoint Address Availability

WCRE then tested whether planned checkpoint addresses were actually free at the
create-process event.

Relevant implementation:

```text
c7bb0b0 — Probe checkpoint address availability at process creation
```

This converted an architectural assumption into something observable.

The important question was:

```text
captured allocation base
        |
        v
is this exact VA still available
before loader initialization advances?
```

If not, exact checkpoint reconstruction cannot succeed at that address.

---

## 7. Early Address-Space Fencing

The next step reserved checkpoint-required PRIVATE address ranges while the
create-process debug event was still pending.

Relevant implementation:

```text
abbdaff — Fence checkpoint address space before loader initialization
```

These reservations act as **fences**:

```text
checkpoint requires address X
        |
        v
reserve X early
        |
        v
loader cannot allocate something else there
        |
        v
advance Windows initialization
        |
        v
later use X for checkpoint reconstruction
```

This was a major improvement over waiting until the entry-point boundary and
then discovering that Windows had already occupied required address ranges.

The fencing path remains deliberately limited to supported restore-plan
PRIVATE allocations.

TEB-containing allocations, IMAGE mappings, MAPPED sections, shared system
mappings, and unsupported groups remain separately handled or deferred.

---

## 8. Integrated Staged PRIVATE-Memory Restoration

The independent pieces were then integrated into a single controlled pipeline.

Relevant implementation:

```text
8a01f19 — Integrate staged private memory restoration
23aa73a — Merge staged private memory restoration
```

The resulting `staged-memory-probe` performs the following sequence:

```text
read .wcr
    |
    v
validate checkpoint
    |
    v
derive deterministic AddressSpacePlan
    |
    v
create destination at CREATE_PROCESS_DEBUG_EVENT
    |
    v
reserve exact PRIVATE fences
    |
    v
advance through loader initialization
    |
    v
stop at executable entry point
    |
    v
verify required IMAGE bases
    |
    v
commit planned PRIVATE subregions
    |
    v
install captured payload bytes
    |
    v
read payloads back and verify
    |
    v
restore captured protections
    |
    v
query protections and verify
    |
    v
terminate destination
```

No captured thread context is installed.

No captured execution is resumed.

---

## 9. Fresh-Layout Staged-Memory Result

A fresh checkpoint using the then-current executable layout demonstrated the
integrated path successfully.

Checkpoint:

```text
experiments/research-013/staged-memory-current-layout.wcr
```

Observed checkpoint/model scale included:

```text
Images:          6
Memory regions:  107
Payloads:        61
Live threads:    3
Payload bytes:   about 10.50 MiB
```

The restore plan contained:

```text
Reservations:    7
Commits:         10
Reserved bytes:  about 36.21 MiB
Committed bytes: 180 KiB
```

The staged restore produced:

```text
PRIVATE fences:              7 / 7 exact
Captured IMAGE bases:        6 / 6 exact
Committed PRIVATE ranges:    10
Verified payload ranges:     7
Verified payload bytes:      135168
Payloadless guard ranges:    3
Verified protections:        10
Cleanup:                     successful
```

This proved the integrated staging path for a checkpoint whose captured
executable layout matched the current launch epoch.

It did not yet solve checkpoint durability across a changed ASLR layout.

---

## 10. The ASLR Problem

The older persistent checkpoint in `experiments/research-012/` had captured the
controlled target's main executable at:

```text
0x00007FF71BF20000
```

A later normal launch of the rebuilt executable consistently loaded it at:

```text
0x00007FF786BD0000
```

The other captured system DLLs could reproduce their earlier addresses, but the
main executable did not.

This meant that a captured instruction pointer such as:

```text
RIP = 0x00007FF71BF2278C
```

would point into the old executable layout, while the current executable code
would exist somewhere else.

Simply rebasing RIP was rejected as a restoration strategy because captured
memory can contain many additional code addresses:

- return addresses,
- function pointers,
- callbacks,
- vtable entries,
- pointers stored on the stack,
- pointers stored on the heap.

The correct requirement remained:

> Recreate the captured executable layout rather than rewriting arbitrary
> captured pointers.

---

## 11. Image Metadata Investigation

The investigation exposed an important checkpoint-model caveat.

The current `ImageRecord` contains:

```text
loaded_base
preferred_image_base
```

but the PSS-derived `preferred_image_base` was observed, for the controlled
loaded executable, to reflect the loader-adjusted in-memory image base rather
than the executable's original on-disk PE preferred base.

For the controlled target, the current file's real on-disk PE metadata showed:

```text
PE ImageBase:       0x0000000140000000
Entry-point RVA:    0x00017810
SizeOfImage:        0x00028000
Relocations:        present
DYNAMIC_BASE:       enabled
HIGH_ENTROPY_VA:    enabled
```

The loaded checkpoint images instead contained their ASLR-selected addresses
in the relevant PSS metadata.

This means future checkpoint-model work should distinguish:

```text
on-disk preferred ImageBase
captured loaded base
in-memory loader-adjusted ImageBase
```

instead of treating them as one concept.

---

## 12. Failed Experiment — Changing `ImageBase` Alone

The first reconstruction attempt made a temporary executable copy with:

- PE `ImageBase` changed to the old captured executable base,
- ASLR-related flags cleared,
- relocation entries left unapplied.

The image did map at the requested old base.

However, the process failed very early with:

```text
0xC0000005
```

and did not survive normal initialization.

This experiment established:

> Placement alone is insufficient.

The raw executable still contained absolute values corresponding to its
original preferred base.

If Windows believes it loaded the image at its preferred base, it has no reason
to apply the relocation delta needed to convert those values to the captured
address.

The failure eliminated the simple "change ImageBase and disable ASLR" design.

---

## 13. Successful Experiment — Pre-Relocating the PE

The next experiment modified a temporary executable copy more completely.

For every supported base-relocation entry, WCRE's research script applied:

```text
captured_base - original_preferred_base
```

directly to the file-backed relocation target.

For the controlled executable:

```text
Original ImageBase:           0x0000000140000000
Captured ImageBase:           0x00007FF71BF20000
DIR64 relocations applied:    282
ABSOLUTE entries skipped:     2
DllCharacteristics:           0x8160 -> 0x8100
```

The experiment then:

- set the PE `ImageBase` to the captured base,
- cleared `DYNAMIC_BASE`,
- cleared `HIGH_ENTROPY_VA`,
- left the relocation directory structurally present,
- launched the modified copy normally.

Result:

```text
Main EXE base:      exact captured base
Captured DLL bases: exact for the controlled captured set
Application thread: survived loader initialization
```

An additional `apphelp.dll` mapping could appear because the temporary
bootstrap lived at a different filesystem path. This did not invalidate the
captured-module base requirement for the controlled experiment.

The important result was that the executable could survive normal Windows
loader initialization at the old checkpoint address.

---

## 14. Old Checkpoint + Pre-Relocated Bootstrap

The pre-relocated executable was then used with the old persistent checkpoint
through the staged-memory pipeline.

The controlled result included:

```text
PRIVATE fences:              8 / 8 exact
Executable entry:            0x00007FF71BF37810
Captured IMAGE bases:        6 / 6 exact
Committed PRIVATE ranges:    12
Verified payload ranges:     8
Verified payload bytes:      139264
Payloadless guard ranges:    4
Verified protections:        12
Cleanup:                     successful
```

This was the first demonstration that WCRE could combine:

```text
old persisted checkpoint
        +
different current ASLR epoch
        +
captured executable address recreation
        +
staged PRIVATE memory restoration
```

Still:

```text
TEB installation:       NO
captured context:       NO
captured RIP/RSP:       NO
execution resumed:      NO
```

---

## 15. Production Rust PE Relocation Primitive

The successful research transformation was then implemented in Rust as a real
WCRE Win32 primitive:

```text
crates/wcre-win32/src/pe_relocation.rs
```

Public API:

```rust
pub fn prepare_relocated_pe_image(
    source: impl AsRef<Path>,
    captured_base: u64,
    output: impl AsRef<Path>,
) -> Result<RelocatedPeImage, PeRelocationError>
```

The implementation:

- reads a PE file without modifying the source,
- validates DOS and PE signatures,
- currently supports PE32+,
- parses section metadata,
- parses the base-relocation directory,
- converts relocation RVAs to file offsets safely,
- skips `IMAGE_REL_BASED_ABSOLUTE`,
- applies `IMAGE_REL_BASED_DIR64`,
- rejects unknown relocation types,
- rejects malformed relocation blocks,
- rejects non-file-backed relocation targets,
- detects range and arithmetic overflow,
- writes the captured `ImageBase`,
- clears `DYNAMIC_BASE`,
- clears `HIGH_ENTROPY_VA`,
- writes a temporary relocated output image.

Arithmetic tests cover:

```text
positive relocation delta
negative relocation delta
underflow rejection
```

The Rust primitive reproduced the successful experimental transformation:

```text
DIR64 applied:       282
ABSOLUTE skipped:    2
DllCharacteristics:  0x8160 -> 0x8100
```

The resulting Rust-generated executable also survived loader initialization at
the captured base.

---

## 16. Automatic Restore Bootstrap

The PE relocation primitive was integrated into the CLI restore-staging path.

Relevant implementation:

```text
18c7e04 — Restore executable image layout across ASLR epochs
4e3f9c5 — Merge executable image layout restoration
```

The integrated pipeline now creates a temporary checkpoint-specific bootstrap
automatically.

Conceptually:

```text
checkpoint
    |
    v
identify captured main image
    |
    v
read current executable
    |
    v
pre-relocate to captured base
    |
    v
write temporary bootstrap
    |
    v
launch bootstrap under LoaderDebugSession
    |
    v
verify captured image bases
```

The original executable is not modified.

The temporary bootstrap is deleted after the staged restore experiment.

---

## 17. Debugger-Termination Cleanup Bug

During bootstrap integration, WCRE discovered that calling
`TerminateProcess` was not by itself sufficient to release every resource
associated with a debugged destination process.

The temporary executable could remain locked, causing bootstrap-directory
cleanup to fail with an access-denied error.

The cause was debugger lifecycle ownership.

A debugged process must also have its final debugger events handled correctly.

`LoaderDebugSession::terminate()` was therefore hardened to:

```text
TerminateProcess
    |
    v
continue currently pending debug event
    |
    v
wait for further debugger events
    |
    v
close debugger-provided file handles where required
    |
    v
observe EXIT_PROCESS_DEBUG_EVENT
    |
    v
continue final exit event
    |
    v
Windows releases debugger-owned process resources
```

Only after this sequence does WCRE consider the debug session inactive.

A retrying temporary-directory removal remains as additional cleanup defense.

This fix made automatic restore-bootstrap deletion reliable.

---

## 18. Acceptance Test Across ASLR Epochs

The final acceptance run exercised both:

1. the old `research-012` checkpoint whose executable was captured at the old
   ASLR address, and
2. the newer checkpoint whose executable used the current layout.

The automated acceptance sequence ran:

```text
10 restores using old-layout checkpoint
10 restores using current-layout checkpoint
```

For every run WCRE required:

- successful command exit,
- expected captured executable base,
- exact planned PRIVATE reservations,
- exact planned commits,
- exact verified payload-byte totals,
- `Captured image bases: 6/6 EXACT`,
- successful restore-bootstrap deletion,
- no TEB installation,
- no captured context installation,
- no execution resume.

Result:

```text
old checkpoint:       10 / 10 PASS
current checkpoint:   10 / 10 PASS

IMAGE LAYOUT RESTORATION: 20 / 20 PASS
```

This demonstrated repeatability rather than a one-off successful launch.

---

## 19. What Research 012 Proves

For the controlled Windows x64 target, WCRE can now:

- create a legitimate Windows replacement process,
- control that process through debugger events,
- stop at the create-process boundary,
- protect exact checkpoint PRIVATE addresses before later loader activity,
- advance the Windows loader without releasing application execution,
- stop immediately before the executable entry instruction,
- derive a deterministic PRIVATE reconstruction plan,
- reconstruct supported PRIVATE allocations at their captured addresses,
- install and byte-verify captured PRIVATE payloads,
- restore and verify supported page protections,
- detect when a fresh ASLR layout differs from the checkpoint,
- generate a temporary PE32+ executable bootstrap relocated to the checkpoint's
  captured executable base,
- allow that relocated executable to survive normal loader initialization,
- verify the captured image-base requirements before continuing restoration,
- perform the complete staged sequence repeatably across different executable
  ASLR epochs,
- terminate the debugged destination and remove the temporary bootstrap
  cleanly.

The strongest defensible statement is:

> WCRE can automatically recreate the controlled target's captured main
> executable placement across ASLR epochs and combine that layout with exact,
> verified reconstruction of the supported PRIVATE checkpoint address space,
> while keeping application execution stopped.

---

## 20. What Research 012 Does Not Prove

Research 012 does **not** yet prove:

- restoration of mutable checkpoint bytes inside general IMAGE mappings,
- arbitrary DLL placement,
- strong cryptographic identity of old checkpoint image files,
- reconstruction of MAPPED sections,
- restoration of the captured PEB,
- restoration of a captured TEB,
- TLS restoration,
- restoration of the complete Windows x64 `CONTEXT`,
- XMM/AVX/XSTATE restoration,
- `SetThreadContext` installation,
- captured RIP/RSP installation,
- thread recreation,
- multithread restoration,
- HANDLE reconstruction,
- file/resource reconstruction,
- synchronization-object reconstruction,
- IPC or socket restoration,
- execution continuation.

Most importantly:

```text
Captured execution resumed: NO
```

Therefore Research 012 is not a completed process-restore claim.

---

## 21. Important Technical Debt Exposed

This research intentionally leaves several correctness questions visible.

### Image identity

Old `.wcr` checkpoints do not contain a strong cryptographic hash identifying
the executable bytes from which they were captured.

Current bootstrap selection can therefore use weaker evidence such as path or
basename plus PE metadata.

Future checkpoint revisions should record a strong executable identity.

### Image-base semantics

The current `preferred_image_base` checkpoint field does not yet cleanly
distinguish the executable's original on-disk preferred base from its
loader-adjusted in-memory value.

The model should eventually represent those meanings explicitly.

### Mutable IMAGE state

Exact executable placement does not imply that mutable image-backed state has
been restored.

For example, a global variable in the executable's `.data` section may contain
a checkpoint value different from the freshly initialized bootstrap value.

That is the next major state-restoration problem before captured execution is
released.

### Additional modules

The controlled test verifies the captured module bases that Windows naturally
reproduces.

WCRE does not yet forcibly place every arbitrary captured DLL.

### Temporary bootstrap path

The restore bootstrap has a different filesystem path from the original
executable.

Windows may therefore load additional compatibility infrastructure such as
`apphelp.dll`.

The controlled acceptance requirement concerns captured image-base
reproduction, not exact equality of the complete destination module set.

---

## 22. Next Boundary

The next restoration frontier is no longer basic address-space placement.

WCRE must now reconcile **captured execution state** with the legitimate
runtime state of the new Windows process.

The immediate sequence is:

```text
restore mutable application IMAGE state
        |
        v
choose captured application thread
        |
        v
inspect destination TEB
        |
        v
reconcile captured stack with destination TEB metadata
        |
        v
install captured CPU context
        |
        v
read context back and verify
        |
        v
release one controlled instruction path
```

The most important rule remains:

> Restarting at `main()` is not checkpoint restoration.

The next decisive milestone will occur only when WCRE installs captured
execution state and continues through the preexisting captured call stack.

---

## Conclusion

Research 011 proved that WCRE could reconstruct the contents of selected
PRIVATE memory.

Research 012 constructs the environment in which that restored memory can
eventually become a live process again.

WCRE now has a repeatable controlled pipeline that:

```text
loads a persisted checkpoint
        |
        v
creates a new Windows process
        |
        v
controls Windows loader progress
        |
        v
protects checkpoint virtual addresses
        |
        v
recreates the captured executable placement
        |
        v
reconstructs supported PRIVATE state
        |
        v
verifies the reconstructed state
        |
        v
stops before captured execution is released
```

The process is structurally much closer to its captured form.

But the decisive transition still remains ahead:

```text
restored state
    ->
captured CPU context
    ->
captured RIP/RSP
    ->
resume
```

Until that succeeds, WCRE remains a checkpoint/reconstruction research engine
rather than a completed Windows process-restoration system.
