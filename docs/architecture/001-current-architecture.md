# WCRE Current Architecture

## Purpose

This document describes the architecture WCRE actually implements today.

WCRE is an experimental Windows x64 checkpoint/restore engine whose long-term
goal is CRIU-style execution continuation:

```text
running process
    |
    v
capture
    |
    v
persistent checkpoint
    |
    v
original process terminates
    |
    v
reconstruct process state
    |
    v
restore captured execution state
    |
    v
continue from captured RIP
```

The final continuation step has not yet been demonstrated.

The current architecture is deliberately split so that:

- platform-independent checkpoint state remains independent of Win32,
- unsafe Windows operations stay inside one crate,
- orchestration remains separate from both the model and the platform layer.

---

# 1. Top-Level Architecture

WCRE consists of three primary crates:

```text
                         WCRE
                          |
          +---------------+---------------+
          |               |               |
          v               v               v
     wcre-image        wcre-win32      wcre-cli
          |               |               |
          |               |               |
 checkpoint model     Windows APIs      orchestration
 persistence          PSS               experiments
 validation           memory            CLI commands
 planning             debugger
                      PE relocation
```

The rule is:

```text
wcre-image
    must not know Windows API objects

wcre-win32
    owns Windows-specific mechanisms

wcre-cli
    composes both layers
```

---

# 2. `wcre-image`

`wcre-image` is the platform-independent state layer.

It contains no Win32 handles, PSS structures, Windows `CONTEXT` structures, or
other operating-system-owned objects.

The crate forbids unsafe Rust.

Its responsibilities are:

- checkpoint data modeling,
- checkpoint validation,
- `.wcr` serialization,
- `.wcr` deserialization,
- checkpoint integrity,
- deterministic restore planning.

## 2.1 `CheckpointModel`

The main in-memory checkpoint representation is:

```text
CheckpointModel
|
+-- ProcessRecord
|
+-- Vec<ImageRecord>
|
+-- Vec<MemoryRegionRecord>
|
+-- Vec<MemoryPayload>
|
+-- Vec<ThreadRecord>
```

### `ProcessRecord`

Contains capture-time process provenance:

```text
captured PID
architecture
executable path
```

The captured PID is provenance only. A restored process receives a new Windows
process identity.

### `ImageRecord`

Represents a loaded PE image observed during capture.

Current fields include:

```text
loaded_base
preferred_image_base
size_of_image
time_date_stamp
checksum
mapped_path
```

`loaded_base` is the virtual address at which the image existed in the captured
process.

There is currently a modeling caveat around `preferred_image_base`: the value
originates from PSS image metadata and should not yet be treated as a
cryptographically or semantically authoritative copy of the original on-disk
PE `ImageBase`.

Future image-model work should distinguish clearly between:

```text
on-disk preferred ImageBase

captured loaded address

in-memory loader-adjusted ImageBase
```

### `MemoryRegionRecord`

Describes virtual-memory metadata independently from the bytes stored there.

Important fields include:

```text
base address
allocation base
region size
allocation protection
state
kind
current protection
optional payload ID
```

Memory kinds include:

```text
PRIVATE
MAPPED
IMAGE
NONE
UNKNOWN
```

Separating region metadata from payload bytes allows the restore planner to
reason about address-space structure without embedding large byte buffers in
every region record.

### `MemoryPayload`

Contains captured bytes:

```text
payload ID
base address
byte vector
```

A `MemoryRegionRecord` can refer to a payload through `payload_id`.

Checkpoint validation verifies that these links are internally consistent.

### `ThreadRecord`

Currently preserves:

```text
capture-time PID
capture-time TID
TEB base address
TEB-reported StackBase
TEB-reported StackLimit
optional x64 context subset
```

The persisted x64 subset currently contains:

```text
RAX RBX RCX RDX
RSI RDI
R8  R9  R10 R11
R12 R13 R14 R15
RIP RSP RBP
EFLAGS
```

This is intentionally not yet described as a complete restorable Windows x64
CPU context.

---

# 3. `.wcr` Persistence

WCRE checkpoint files are owned by `wcre-image`.

The current default format is `.wcr` v2.

Conceptually:

```text
CheckpointModel
      |
      v
semantic validation
      |
      v
binary encoding
      |
      v
integrity-protected .wcr
```

Version 2 adds SHA-256 integrity protection around the serialized checkpoint
contents.

The decoder applies structural limits to untrusted fields such as:

```text
collection counts
string lengths
single payload sizes
total payload bytes
```

A `.wcr` file represents captured state.

A valid `.wcr` file does not by itself prove that WCRE can restore every state
class stored inside it.

---

# 4. `wcre-win32`

`wcre-win32` owns the platform boundary.

Unsafe Windows API interaction belongs here instead of leaking into
`wcre-image` or higher-level orchestration.

Current major modules include:

```text
process.rs
memory.rs
memory_read.rs
snapshot.rs
exact_allocation.rs
restore_memory.rs
suspended_process.rs
loader_debug.rs
pe_relocation.rs
```

---

# 5. Process Inspection

`process.rs` provides basic Windows process inspection.

This establishes:

```text
PID
executable path
process architecture
native architecture
```

These values form the basic provenance used when constructing a checkpoint.

---

# 6. Virtual Address-Space Inspection

`memory.rs` walks the process virtual address space using Windows memory
queries.

The resulting map classifies ranges by:

```text
state
    COMMIT
    RESERVE
    FREE

kind
    PRIVATE
    MAPPED
    IMAGE

protection
    Windows page-protection flags
```

This memory map becomes the structural foundation for checkpoint capture and
restore planning.

---

# 7. PSS Snapshot Capture

`snapshot.rs` uses Windows Process Snapshotting APIs.

The important architectural decision is that WCRE captures related state from
one coherent PSS snapshot rather than independently sampling a process at
unrelated times.

The checkpoint-capable snapshot collects:

```text
VA clone
thread inventory
thread contexts
virtual-address metadata
image metadata
```

Memory payloads are then read from the PSS VA clone associated with that same
snapshot.

Conceptually:

```text
live process
     |
     v
PssCaptureSnapshot
     |
     +----------------+
     |                |
     v                v
thread/image state   VA clone
                      |
                      v
                payload reads
```

This reduces the risk of combining thread state from one moment with memory
bytes from a different moment.

---

# 8. Captured Memory Payloads

WCRE currently captures bytes from committed readable checkpoint-candidate
regions.

This includes readable regions classified as:

```text
PRIVATE
MAPPED
IMAGE
```

Known Windows-managed volatile ranges are deliberately excluded.

This means capture currently preserves more memory state than the restoration
pipeline knows how to reinstall safely.

That distinction is intentional.

---

# 9. Restore Planning

`wcre-image::restore_plan` converts a validated checkpoint into a deterministic
address-space reconstruction plan.

The first reconstruction envelope is intentionally conservative.

Supported planning currently focuses on complete PRIVATE allocation groups.

The planner explicitly defers state classes such as:

```text
IMAGE mappings
MAPPED sections
TEB-containing allocations
shared system mappings
unsupported or incomplete allocations
```

This prevents WCRE from silently pretending that all Windows memory mappings
have equivalent reconstruction semantics.

The current restore-plan operations are essentially:

```text
Reserve
Commit
```

with enough checkpoint metadata retained to restore payload bytes and page
protection afterward.

---

# 10. Exact PRIVATE Address Reconstruction

`exact_allocation.rs` owns exact remote virtual-address reconstruction.

The goal is not merely to allocate equivalent memory somewhere.

The goal is:

```text
captured virtual address
        ==
reconstructed virtual address
```

This matters because process state contains raw pointers.

If an object was captured at:

```text
0x0000013E7EC29680
```

then another captured pointer may contain exactly that number.

Moving the object elsewhere would invalidate that pointer.

WCRE therefore reserves complete supported PRIVATE allocation groups at their
original captured addresses and commits the required subregions exactly.

Address conflicts fail closed.

---

# 11. Remote Memory Restoration

`restore_memory.rs` installs payload bytes into already reconstructed remote
memory.

For a planned region:

```text
payload_id
    |
    v
MemoryPayload
    |
    v
WriteProcessMemory
    |
    v
ReadProcessMemory
    |
    v
byte-for-byte comparison
```

WCRE rejects:

```text
missing payload links
incorrect payload bases
incorrect payload sizes
partial writes
partial reads
verification mismatches
```

A successful installation therefore means WCRE has written and independently
read back the exact checkpoint bytes for that region.

---

# 12. Page-Protection Restoration

Reconstructed committed memory is initially writable so WCRE can install
captured bytes.

After installation, WCRE restores the captured supported protection.

Examples include:

```text
PAGE_READONLY
PAGE_READWRITE
PAGE_EXECUTE
PAGE_EXECUTE_READ
PAGE_EXECUTE_READWRITE
PAGE_GUARD combinations supported by the current envelope
```

The final protection is queried again and must match the expected checkpoint
state.

---

# 13. Restore Process Staging

Simply creating another copy of the executable and suspending its initial
thread is insufficient for the current reconstruction strategy.

WCRE therefore developed a debugger-controlled loader staging path.

`loader_debug.rs` can hold the process at progressively later Windows loader
boundaries:

```text
CreateProcess
      |
      v
CREATE_PROCESS_DEBUG_EVENT
      |
      v
initial loader breakpoint
      |
      v
executable entry-point breakpoint
      |
      v
application instruction would execute
```

WCRE stops before that final transition.

The process can therefore receive enough normal Windows loader initialization
to establish legitimate runtime structures while application code remains
unexecuted.

---

# 14. Early Address-Space Fencing

Some captured PRIVATE addresses must be protected before Windows finishes
initializing the destination process.

At `CREATE_PROCESS_DEBUG_EVENT`, WCRE can reserve required checkpoint address
ranges before advancing the loader.

These reservations act as fences:

```text
captured address range
      |
      v
reserve immediately
      |
      v
Windows loader cannot consume it
      |
      v
later convert/use it for reconstruction
```

This solved address-space collisions that occurred when reconstruction waited
until after loader initialization.

---

# 15. Executable IMAGE Layout Reconstruction

ASLR creates another problem.

A checkpoint can contain:

```text
captured RIP = old executable address
```

but a fresh launch may map the executable somewhere else.

Simply changing the PE `ImageBase` is not sufficient because absolute addresses
inside the image may still contain relocation-adjusted values from the original
preferred base.

WCRE's controlled x64 solution is implemented in `pe_relocation.rs`.

For a supported PE32+ executable:

```text
source executable
      |
      v
read relocation table
      |
      v
apply IMAGE_REL_BASED_DIR64 delta
      |
      v
set captured ImageBase
      |
      v
clear DYNAMIC_BASE / HIGH_ENTROPY_VA
      |
      v
temporary restore bootstrap
```

The original executable is not modified.

The transformed temporary executable is then launched through the normal
Windows loader.

WCRE verifies the resulting captured image-base requirements before continuing
with PRIVATE-memory reconstruction.

This technique currently supports the controlled WCRE x64 target.

It is not yet a general arbitrary-module placement system.

---

# 16. Integrated Restore-Staging Pipeline

The current strongest end-to-end path is:

```text
.wcr
 |
 v
read and validate checkpoint
 |
 v
derive AddressSpacePlan
 |
 v
identify captured main executable base
 |
 v
prepare relocated PE bootstrap
 |
 v
CREATE_PROCESS_DEBUG_EVENT
 |
 v
reserve PRIVATE fences
 |
 v
advance Windows loader
 |
 v
initial loader breakpoint
 |
 v
advance toward executable entry
 |
 v
entry-point breakpoint
 |
 +--> executable entry instruction has NOT executed
 |
 +--> verify captured IMAGE bases
 |
 v
commit supported PRIVATE ranges
 |
 v
install captured payload bytes
 |
 v
verify payload bytes
 |
 v
restore captured protections
 |
 v
verify protections
 |
 v
STOP
```

The destination is then terminated deliberately.

No captured thread context is installed and no captured execution is resumed.

---

# 17. Resource Ownership and Fail-Closed Cleanup

Restore experimentation creates real Windows resources:

```text
process handles
thread handles
debug events
remote allocations
temporary executable files
PSS snapshots
```

The Win32 layer uses owned Rust session types to make cleanup explicit.

Examples include:

```text
VaCloneSnapshot
ExactAddressSpaceSession
RemoteMemorySession
SuspendedProcessSession
LoaderDebugSession
```

Incomplete restore experiments terminate their destination instead of allowing a
partially reconstructed process to escape and continue execution.

The debugger-controlled process shutdown also drains the final
`EXIT_PROCESS_DEBUG_EVENT` before temporary bootstrap cleanup.

---

# 18. Current Thread-Restoration Boundary

Capture already contains:

```text
captured TEB address
captured stack bounds
captured stack bytes
captured RIP
captured RSP
captured RBP
captured general-purpose registers
captured EFLAGS
```

But none of that captured execution state is currently installed into the
destination thread.

There is intentionally no `SetThreadContext` restoration path yet.

The destination thread still owns a newly created Windows TEB and a newly
created loader stack.

Before WCRE can safely switch to a captured RSP, it must determine the minimum
runtime reconciliation required between:

```text
new Windows thread
new TEB
new loader/runtime state
```

and:

```text
captured stack
captured execution context
captured process memory
```

The current planned research sequence is:

```text
IMAGE mutable-state restoration
        |
        v
captured-thread selection
        |
        v
TEB stack/runtime reconciliation
        |
        v
context installation without resume
        |
        v
context read-back verification
        |
        v
first controlled execution release
```

---

# 19. Important Current Boundaries

WCRE does not currently reconstruct:

```text
arbitrary DLL placement
general IMAGE mutable state
MAPPED sections
complete Windows x64 CONTEXT
XMM/AVX/XSTATE
TEB wholesale state
TLS
PEB/runtime ownership relationships
multiple captured threads
kernel HANDLEs
files
synchronization objects
pipes
IPC
sockets
process trees
```

These are not silently approximated.

They are explicit research boundaries.

---

# 20. Architectural Principle

The central architectural rule of WCRE is:

> Capturing a state class is not the same as proving it can be restored.

WCRE therefore separates:

```text
CAPTURE
what state can be observed coherently?

MODEL
how can WCRE represent it independently?

PERSIST
how can that state survive process termination?

PLAN
which parts are safe to reconstruct?

RECONSTRUCT
can they be recreated exactly?

VERIFY
can WCRE prove the result matches the checkpoint?

RESUME
can execution safely continue from captured state?
```

WCRE currently reaches the `VERIFY` stage for substantial portions of the
controlled address space.

The next major frontier is `RESUME`.
