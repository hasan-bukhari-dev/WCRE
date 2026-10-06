# Research 011 — PRIVATE Memory Restoration

## Status

**PASS — WCRE can restore captured payload bytes and supported page protections for an explicitly selected PRIVATE Windows x64 allocation inside a controlled restore host.**

A real persisted `.wcr` checkpoint was used to reconstruct an 8 KiB PRIVATE range at its exact captured virtual address. WCRE installed the captured checkpoint payload, read the remote bytes back, verified all 8192 bytes byte-for-byte, restored the captured page protection, verified that protection through `VirtualQueryEx`, and then released the temporary reconstruction cleanly.

This is controlled PRIVATE-memory restoration evidence.

It is **not yet process restoration or execution resumption**.

---

## Objective

Research 010 proved that WCRE could reconstruct selected PRIVATE address-space ranges at their exact captured virtual addresses.

Research 011 asks the next question:

> Given an exact reconstructed PRIVATE range, can WCRE install the actual captured checkpoint bytes and restore the captured memory protection while verifying both against the remote process?

The required sequence is:

```text
.wcr checkpoint
    ↓
CheckpointModel
    ↓
AddressSpacePlan
    ↓
exact PRIVATE reservation
    ↓
exact temporary PAGE_READWRITE commit
    ↓
install captured payload
    ↓
read remote payload back
    ↓
byte-for-byte verification
    ↓
restore supported captured protection
    ↓
VirtualQueryEx verification
    ↓
temporary cleanup
```

---

## Architecture

Memory reconstruction remains split across two responsibilities.

### `ExactAddressSpaceSession`

Owns:

- exact reservations,
- exact commits,
- page-protection restoration,
- memory queries,
- cleanup.

Committed regions initially use `PAGE_READWRITE` so payload bytes can be installed safely.

After payload verification, `VirtualProtectEx` applies the supported captured protection.

### `RemoteMemorySession`

Owns:

- remote memory writes,
- remote memory reads,
- checkpoint payload resolution,
- byte-for-byte verification.

This separation keeps address-space ownership distinct from payload transfer.

---

## Payload Restoration

`RemoteMemorySession::install_region_payload_verified()` resolves:

```text
PlannedRegion.payload_id
        ↓
MemoryPayload.id
        ↓
captured bytes
```

Before writing, WCRE verifies that:

- a payload link exists,
- the payload ID exists,
- the payload base matches the planned region base,
- the payload length matches the planned region size.

It then performs:

```text
WriteProcessMemory
        ↓
ReadProcessMemory
        ↓
full byte comparison
```

Partial writes and partial reads are rejected.

A region with no captured payload is explicitly reported as:

```text
PAYLOAD ... NOT CAPTURED
```

WCRE does not invent zero-filled contents and call them restored.

---

## Protection Restoration

Reconstructed committed memory begins temporarily as:

```text
PAGE_READWRITE
```

After payload installation and verification, WCRE can apply a supported captured protection using:

```text
VirtualProtectEx
```

The initial PRIVATE restoration envelope accepted:

- `PAGE_NOACCESS`
- `PAGE_READONLY`
- `PAGE_READWRITE`
- `PAGE_EXECUTE`
- `PAGE_EXECUTE_READ`
- `PAGE_EXECUTE_READWRITE`

At the time of the initial Research 011 experiment, the following remained deliberately unsupported:

- `PAGE_WRITECOPY`
- `PAGE_EXECUTE_WRITECOPY`
- `PAGE_GUARD`
- `PAGE_NOCACHE`
- `PAGE_WRITECOMBINE`
- other unknown or compound protection values

Unsupported protection semantics are rejected explicitly rather than silently approximated.

After `VirtualProtectEx`, WCRE queries the region through `VirtualQueryEx` and requires the observed protection to equal the captured protection.

---

## Primitive Validation

The Win32 exact-allocation test verifies a real protection transition:

```text
PAGE_READWRITE
    ↓
VirtualProtectEx
    ↓
PAGE_READONLY
    ↓
VirtualQueryEx
    ↓
VERIFIED
```

The same test verifies that unsupported `PAGE_WRITECOPY` is rejected by the first PRIVATE restoration envelope.

The payload-restoration tests independently verify:

- direct remote write/read round trips,
- checkpoint-backed payload installation,
- byte-for-byte verification,
- missing payload-link rejection,
- empty-operation rejection.

---

## Follow-up — Guard-Page Protection Restoration

After the initial Research 011 result, WCRE extended the PRIVATE protection
restoration envelope to support `PAGE_GUARD` as a modifier on supported base
protections.

This work is represented by commit:

```text
4cd51ac — Support guard-page protection restoration
```

The implementation separates the guard modifier from the base protection:

```text
captured protection
        |
        +--> PAGE_GUARD present?
        |
        v
base protection
```

WCRE then validates the base protection against the already supported PRIVATE
protection set.

The follow-up accepts combinations such as:

```text
PAGE_READWRITE | PAGE_GUARD
```

and verifies the resulting remote protection through `VirtualQueryEx`.

The Win32 test also verifies a real transition:

```text
PAGE_READONLY
    ↓
VirtualProtectEx
    ↓
PAGE_READWRITE | PAGE_GUARD
    ↓
VirtualQueryEx
    ↓
VERIFIED
```

The invalid combination:

```text
PAGE_NOACCESS | PAGE_GUARD
```

is rejected explicitly.

`PAGE_WRITECOPY`, `PAGE_EXECUTE_WRITECOPY`, `PAGE_NOCACHE`,
`PAGE_WRITECOMBINE`, and unsupported or unknown compound protection semantics
remain outside the current controlled PRIVATE restoration envelope.

This follow-up extends Research 011 rather than establishing a new restoration
stage: WCRE is still restoring the same PRIVATE memory state class, but with a
more complete representation of captured page-protection semantics.

---

## Real `.wcr` Experiment

Checkpoint:

```text
experiments/live-demo-v2/controlled-demo-v2.wcr
```

Selected captured allocation:

```text
0x00000198EDF60000
```

Selected committed range:

```text
0x00000198EDF60000
-
0x00000198EDF62000
```

Size:

```text
0x2000
8192 bytes
8 KiB
```

Observed execution:

```text
RESERVE 0x00000198EDF60000 size=0x2000 ... EXACT

  COMMIT 0x00000198EDF60000-0x00000198EDF62000 ... EXACT

    PAYLOAD 0x00000198EDF60000-0x00000198EDF62000
    bytes=8192 ... VERIFIED

    PROTECT 0x00000198EDF60000-0x00000198EDF62000
    0x00000004 -> 0x00000004 ... VERIFIED
```

Result:

```text
Exact reservations:          1
Exact committed ranges:      1
Verified payload ranges:     1
Verified payload bytes:      8192
Payloadless ranges:          0
Verified protection ranges:  1
Address conflicts:           0
Temporary cleanup:           VERIFIED
```

The reconstruction command exited successfully.

The restore host was then terminated.

---

## Interpreting the Protection Result

The real checkpoint region had captured protection:

```text
0x00000004
```

which corresponds to:

```text
PAGE_READWRITE
```

The reconstruction therefore reported:

```text
0x00000004 -> 0x00000004
```

This specific end-to-end experiment does not demonstrate a visible protection transition because the temporary reconstruction protection already matched the captured protection.

However:

1. the real checkpoint path still executed `VirtualProtectEx`,
2. WCRE independently queried the resulting remote region,
3. the observed protection matched the captured checkpoint value,
4. the unit-level Win32 experiment separately demonstrates an actual `PAGE_READWRITE -> PAGE_READONLY` transition.

Together these establish the restoration mechanism without overstating what the single checkpoint happened to contain.

---

## What Research 011 Proves

WCRE can now, for the supported controlled PRIVATE-memory envelope:

- load a persisted checkpoint,
- derive the reconstruction plan,
- reserve memory at the exact captured virtual address,
- commit the captured PRIVATE range,
- resolve the captured payload,
- install those bytes into another process,
- read those bytes back,
- verify them byte-for-byte,
- apply a supported captured page protection,
- verify the protection through Windows,
- restore supported `PAGE_GUARD` combinations,
- release the temporary reconstruction cleanly.

The strongest defensible statement is:

> WCRE can reconstruct a selected supported PRIVATE Windows x64 memory range at its original virtual address, restore its captured payload byte-for-byte, and restore and verify its supported captured page protection inside a controlled restore host.

---

## What Research 011 Does Not Prove

It does not yet restore:

- IMAGE mappings,
- MAPPED sections,
- PEB state,
- TEB state,
- TLS,
- loader state,
- thread objects,
- complete stack/runtime dependencies,
- full x64 CPU state,
- floating-point state,
- XMM/AVX/XSTATE,
- RIP,
- RSP,
- handles,
- files,
- synchronization state,
- IPC,
- process trees.

It does not resume captured execution.

Therefore WCRE must still **not** claim general process restoration.

---

## Next Boundary

The next major research area is process runtime reconstruction.

Before restoring a captured instruction pointer, WCRE must determine the minimum runtime state required for a controlled single-thread native x64 target.

The eventual proof remains:

```text
capture
    ↓
kill original
    ↓
reconstruct exact VA
    ↓
restore PRIVATE memory
    ↓
restore required runtime/thread state
    ↓
install CPU context
    ↓
restore RIP/RSP
    ↓
resume
    ↓
continue through the preexisting captured call stack
```

Restarting execution at `main` does not count as restoration.

---

## Conclusion

Research 011 moves WCRE from address-space reconstruction to verified memory-state reconstruction.

Research 010 showed that WCRE could recreate **where** selected captured PRIVATE memory existed.

Research 011 shows that WCRE can also recreate **what bytes were there** and **how supported pages were protected**.

The later guard-page follow-up extends that protection fidelity to supported
`PAGE_GUARD` combinations while preserving explicit rejection of unsupported
semantics.

The process is still not alive again.

But substantially more of its captured memory state now exists correctly inside a new process.
