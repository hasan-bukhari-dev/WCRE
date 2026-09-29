# WCRE Research Scope

## Core question

Can a Windows x64 user-mode process be checkpointed, completely terminated,
and later reconstructed such that execution continues from the saved CPU and
memory state without restarting the application?

## Initial platform

- Windows 11
- x86-64
- user-mode applications
- single process initially
- native test executables initially

## Initial non-goals

WCRE does not initially attempt to preserve:

- GPU contexts
- kernel drivers
- protected processes
- DRM or anti-cheat systems
- arbitrary hardware devices
- active network connections
- arbitrary GUI applications

These may be investigated later but are not required to prove the fundamental
checkpoint/restart mechanism.

## First major proof

WCRE must eventually demonstrate the following:

1. Start an unmodified native x64 test program.
2. Allow it to enter a nested call stack.
3. Capture its memory and CPU state.
4. Terminate the original process completely.
5. Reconstruct the required virtual address space.
6. Restore its execution state.
7. Continue from the saved instruction.
8. Successfully return through the captured stack frames.

The program must not restart from `main()`.
