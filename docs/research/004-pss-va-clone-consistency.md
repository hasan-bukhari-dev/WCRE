# Research 004 — PSS VA Clone Consistency

## Question

Can a Windows Process Snapshotting (PSS) VA clone provide WCRE with a
sufficiently stable memory view to serve as a foundation for checkpointing?

## Scope

This experiment evaluates observed memory consistency only.

It does not establish a complete process checkpoint. WCRE has not yet combined
memory, thread execution state, modules, handles/resources, and other external
state into one formal checkpoint barrier.

## Method

WCRE captures a target using `PSS_CAPTURE_VA_CLONE`, obtains the VA-clone
process handle, and repeatedly reads the same clone.

The experiment compared:

- readable memory layout,
- readable byte totals,
- complete read coverage,
- whole-memory fingerprints,
- Private / Mapped / Image fingerprints,
- individual readable committed `MEM_PRIVATE` regions.

FNV-1a is currently used only as an experimental change detector. It is not a
cryptographic integrity mechanism.

## Initial result

Two complete reads of the same PSS VA clone showed:

- identical readable-region layout,
- identical readable-byte totals,
- 100 percent selected-readable coverage,
- different whole-memory fingerprints.

Breaking the result down by type showed:

- `MEM_MAPPED`: stable in the observed run,
- `MEM_IMAGE`: stable in the observed run,
- `MEM_PRIVATE`: contained a difference.

## Private-region investigation

WCRE then fingerprinted every readable committed `MEM_PRIVATE` region
individually.

The changing region was:

```text
Base:       0x000000007FFE0000
Size:       4 KiB
Protection: read-only
```

This address corresponds to Windows `KUSER_SHARED_DATA`, an OS-maintained
shared user-mode data page containing values that may change while Windows is
running.

WCRE therefore classifies this page as known OS-managed volatile state rather
than ordinary process-owned checkpoint payload.

## Reproduction

The experiment was repeated across independent PSS captures.

### Windows PowerShell

Five consecutive captures showed:

- approximately 115–116 readable private regions,
- exactly one changed region,
- a changed-region span of 4 KiB,
- the changed region at `0x000000007FFE0000` every time.

### Windows Notepad

Three consecutive captures showed:

- 684 readable private regions,
- exactly one changed region,
- a changed-region span of 4 KiB,
- the changed region at `0x000000007FFE0000` every time.

## WCRE consistency model

WCRE now distinguishes:

```text
raw readable private memory
|
+-- known OS-managed volatile state
|   |
|   +-- KUSER_SHARED_DATA
|
+-- checkpoint-candidate private state
    |
    +-- no unexpected changes observed
```

A known volatile page changing does not make checkpoint-candidate private
memory inconsistent.

Any unexpected change in another private region does.

## Result

**PASS WITH EXPLICIT VOLATILE-STATE CLASSIFICATION**

For the PowerShell and Notepad workloads tested, WCRE observed no unexpected
changes in readable private checkpoint-candidate memory across repeated reads
of the same PSS VA clone.

This is an experimental observation, not a universal guarantee for every
Windows build, workload, or process.

## Engineering consequence

Checkpoint correctness cannot simply mean:

> every readable byte in the process address space must remain identical.

WCRE must classify memory according to ownership and restoration semantics.

OS-managed volatile state must remain distinct from state WCRE intends to
serialize and reconstruct.

## Next questions

1. Does the result hold for a controlled native x64 WCRE target?
2. Can thread inventory and CPU execution context be captured from the same PSS
   snapshot?
3. What constitutes WCRE's formal checkpoint barrier?
4. How does PSS VA-space metadata compare with the `VirtualQueryEx` view?
5. Which mapped and image-backed regions should be stored versus reconstructed?
6. What additional Windows-owned mappings require explicit classification?
