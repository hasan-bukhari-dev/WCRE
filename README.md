# WCRE

### Windows Checkpoint/Restore Engine

**WCRE** is an experimental user-space checkpoint/restart engine for Windows x64.

The long-term goal is to capture the execution state of a supported running Windows process, terminate it, and later reconstruct that process so execution can continue from the saved state rather than restarting from program entry.

WCRE is currently an early-stage systems research project.

## Current milestone

**M0 - Process State Capture**

The immediate goal is to reliably inspect and capture the observable state of a controlled Windows x64 process, including:

- virtual memory regions
- thread metadata
- CPU contexts
- process metadata
- mapped images
- handle metadata

No process restoration capability is claimed yet.

## Project principles

- correctness before features
- evidence before architecture
- no unsupported checkpoint claims
- explicit compatibility boundaries
- automated verification wherever possible
- documented failed experiments as well as successful ones

## Planned research progression

1. Process-state inspection
2. PSS-backed process snapshots
3. Persistent checkpoint images
4. Exact virtual-address reconstruction
5. Single-thread execution continuation
6. Multithreading and TLS
7. Kernel-resource reconstruction
8. Supported real-world applications

## Status

Experimental. Not ready for production use.
