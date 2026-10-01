# WCRE

### Windows Checkpoint/Restore Engine

**WCRE** is an experimental user-space checkpoint/restart engine for Windows x64.

The long-term goal is to capture the execution state of a supported running Windows process, terminate it, and later reconstruct that process so execution can continue from the saved state rather than restarting from program entry.

WCRE is currently an early-stage systems research project.

## Current milestone

**M2 - Memory Restoration Research**

WCRE has now demonstrated:

- Windows process inspection
- virtual-address-space enumeration
- coherent PSS-backed checkpoint capture
- thread and x64 register-subset capture
- mapped-image inventory
- WCRE-owned checkpoint modeling
- persistent `.wcr` checkpoint files
- integrity-protected `.wcr` v2 checkpoints
- offline checkpoint inspection after source-process termination
- deterministic restore planning
- exact virtual-address reservation and commitment for a controlled subset of PRIVATE memory

The next milestone is to install captured memory payload bytes into those reconstructed ranges, verify them byte-for-byte, and restore their captured memory protections.

WCRE has **not** yet demonstrated process restoration or execution resumption.

## Project principles

- correctness before features
- evidence before architecture
- no restore claim until execution actually resumes
- explicit compatibility boundaries
- automated verification wherever possible
- documented failed experiments as well as successful ones

## Current architecture

```text
Capture
-------
Windows process
    ->
PSS snapshot
    ->
CheckpointModel
    ->
.wcr v2

Reconstruction
--------------
.wcr v2
    ->
verified CheckpointModel
    ->
AddressSpacePlan
    ->
controlled restore host
    ->
exact virtual-address reconstruction
```

The project deliberately separates:

- `wcre-image` - platform-independent checkpoint model, persistence, validation, and restore planning
- `wcre-win32` - Windows-specific process, PSS, memory, and reconstruction primitives
- `wcre-cli` - developer-facing orchestration and experiments

## Planned research progression

1. Process-state inspection
2. PSS-backed process snapshots
3. Persistent checkpoint images
4. Exact virtual-address reconstruction
5. Memory payload restoration
6. Single-thread execution continuation
7. Multithreading, TEB, and TLS
8. Kernel-resource reconstruction
9. Supported real-world applications
10. Machine-to-machine migration

## Status

Experimental. Not ready for production use.
