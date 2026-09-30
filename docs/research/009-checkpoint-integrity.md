# Research 009 — Checkpoint Integrity and Parser Hardening

## Status

**PASS — WCRE now has a backward-compatible, integrity-protected `.wcr` v2 default, a verified dual-version reader, deterministic parser-hardening coverage, a permanent v1 compatibility fixture, and atomic checkpoint publication.**

This result establishes a substantially stronger persistence boundary. It does not establish process restoration or execution resumption.

---

## Objective

Research 008 proved that WCRE could persist a captured `CheckpointModel`, terminate the source process, and reconstruct and inspect the captured state from disk.

Research 009 asks the next safety question:

> Can WCRE detect checkpoint corruption before interpreting untrusted state, reject authenticated but malformed checkpoints deterministically, retain v1 compatibility, and publish completed checkpoints without exposing partial final files?

The work deliberately remains restore-oriented. A future restore engine must not reconstruct virtual memory or thread state from bytes that have not first passed integrity, structural, and semantic validation.

---

## Version Strategy

WCRE currently supports both persistent formats:

| Format | Reader | Writer | Integrity trailer | Compatibility role |
|---|---|---|---|---|
| v1 | Supported | Explicit opt-in | None | Established wire format and permanent compatibility anchor |
| v2 | Supported | Default and explicit | SHA-256 | Integrity-protected current format |

The public library writer and CLI default to v2. Callers can still select either version explicitly.

The in-memory `CheckpointModel` version remains independent of the persistent `.wcr` format version.

No v1 field, encoding, ordering rule, or byte sequence was silently changed.

### Default-format decision

v2 became the default only after all of the following were in place:

- streaming v2 encoding,
- integrity verification before body deserialization,
- dual-version reader dispatch,
- authenticated malformed-input coverage,
- deterministic property-style parser tests,
- a byte-exact golden v1 fixture,
- successful live v2 creation and post-mortem inspection,
- demonstrated corruption rejection,
- atomic final-file publication.

The transition is an API default change, not a v1 wire-format change. The explicit `write_checkpoint_v1` and `write_checkpoint_v1_file` APIs preserve intentional v1 output. `write_checkpoint_v2` and `write_checkpoint_v2_file` remain available when explicitness is useful, while `write_checkpoint` and `write_checkpoint_file` now select v2.

This makes new checkpoints integrity-protected by default without weakening old-checkpoint readability or byte-for-byte v1 reproducibility.

---

## v2 Wire Contract

Every v2 file has this shape:

```text
56-byte v2 header
    +
declared checkpoint body
    +
32-byte SHA-256 digest
```

The fixed header is exactly 56 bytes:

| Field | Width |
|---|---:|
| Magic (`WCREWCR\0`) | 8 bytes |
| Persistent format version | 4 bytes |
| Header size | 4 bytes |
| Checkpoint model version | 4 bytes |
| Architecture | 4 bytes |
| Flags | 4 bytes |
| Image count | 4 bytes |
| Memory-region count | 4 bytes |
| Memory-payload count | 4 bytes |
| Thread count | 4 bytes |
| Body length | 8 bytes |
| Integrity algorithm | 4 bytes |

All fixed-width integers use little-endian encoding. The only currently supported integrity algorithm identifier is `1`, meaning SHA-256. No v2 flags are currently defined, so nonzero flags are rejected.

The digest domain is exact:

```text
SHA-256(v2 header bytes || declared body bytes)
```

The digest trailer itself is not part of the digest domain.

The declared body length determines exactly how many body bytes are streamed into the hash. A truncated body, truncated digest, mismatched body consumption, or any byte after the digest is rejected.

---

## Verified Reader Ordering

The v2 reader performs these operations in order:

```text
read magic and format discriminator
    ↓
read raw v2 header fields while hashing them
    ↓
stream exactly body_length bytes into an anonymous temporary file
while updating SHA-256
    ↓
read the stored digest and reject trailing bytes
    ↓
compare computed and stored digests
    ↓
only after a match:
decode architecture, validate flags/counts, rewind the body,
deserialize records, and validate checkpoint semantics
```

The body is not buffered as one large in-memory allocation. It is streamed to an anonymous temporary file, hashed during the copy, rewound after successful verification, and only then deserialized.

Header fields that influence interpretation remain raw until the digest comparison succeeds. For example, changing authenticated architecture metadata without replacing the digest produces `IntegrityMismatch` before architecture decoding.

The reader must inspect the magic, version, fixed header size, declared body boundary, algorithm identifier, digest trailer, and end of input to establish the integrity envelope. All remaining interpretation is deferred until after digest verification.

---

## Two Distinct Rejection Classes

Research 009 separates two security-relevant cases.

### Unauthenticated corruption

If a v2 header, body, or digest byte is changed without recomputing the digest, the reader rejects the file with `IntegrityMismatch`.

This demonstrates corruption detection. It does not exercise the body parser because untrusted bytes are rejected before deserialization.

### Authenticated but malformed input

Parser-hardening tests deliberately mutate a valid v2 checkpoint and then recompute its digest. The integrity check succeeds, allowing the structural and semantic validators to reject the malformed content with a bounded `WcrError`.

Covered cases include:

- mismatched declared body length,
- trailing bytes after the digest,
- collection counts above the parser limit,
- nonzero flags,
- invalid memory-state encoding,
- invalid memory-kind encoding,
- invalid boolean encoding,
- malformed UTF-8,
- oversized string length,
- oversized individual payload length,
- semantically invalid checkpoint relationships.

The resulting guarantee is:

```text
unauthenticated mutation
    → integrity rejection before body interpretation

authenticated malformed checkpoint
    → structural or semantic rejection
```

SHA-256 here provides corruption detection and content integrity. It does not provide authenticity: there is no secret key, signature, signer identity, or trust policy. An attacker who can replace a checkpoint can also compute a new SHA-256 digest, so the parser and semantic validator remain security-critical.

---

## Parser Limits

Both format paths enforce defensive parser budgets:

| Limit | Value |
|---|---:|
| Maximum items in one declared collection | 1,000,000 |
| Maximum encoded string length | 16 MiB |
| Maximum individual memory payload | 4 GiB |
| Maximum cumulative memory payload data | 64 GiB |

These are parser-safety limits, not promises about WCRE's eventual workload or migration envelope.

Lengths, counts, address ranges, payload ownership, stack bounds, and other relationships also undergo checked arithmetic and semantic validation. Decoder success means the file satisfied the implemented model invariants; it does not mean every captured operating-system resource required for restore is present.

---

## Deterministic Property-Style Coverage

The normal test suite now exercises broad parser properties without requiring a separate fuzzing tool installation:

- arbitrary deterministic byte slices never panic,
- every truncation of valid v1 and v2 samples returns an error rather than panicking,
- deterministic single- and multi-byte v2 mutations never panic and do not decode successfully,
- declared counts and lengths near defensive boundaries are rejected,
- repeated decoding of identical input returns the same success value or error class.

The central invariant is:

```text
any input
    → CheckpointModel or WcrError
    → never panic
```

The `cargo-fuzz` extension was not installed in the validation environment, so Feature #9 does not claim coverage from a coverage-guided fuzzing campaign. The deterministic suite gives a stable baseline and a small future fuzz surface centered on:

```text
read_checkpoint(Cursor::new(data))
```

---

## Permanent v1 Compatibility Anchor

The repository contains a checked-in golden v1 byte fixture.

Two directions are tested:

```text
known CheckpointModel
    → explicit v1 writer
    → byte-for-byte equality with the golden fixture

golden v1 fixture
    → current dual-version reader
    → exact expected CheckpointModel
```

This makes accidental mutation of the established v1 wire format a test failure. Continued v1 readability is a release invariant even if a newer format later becomes the default.

---

## Atomic Checkpoint Publication

File-writing entry points no longer create or truncate the final destination before encoding completes.

Publication now follows this sequence:

```text
create named temporary file in destination directory
    ↓
encode checkpoint through the existing streaming writer
    ↓
flush buffered bytes
    ↓
sync temporary file contents
    ↓
atomically persist/replace the destination on Windows
```

Using the destination directory keeps the temporary file and final file on the same filesystem, which is required for the intended atomic rename/replace behavior. The Windows persistence implementation uses replacement semantics for an existing destination.

Validated publication behavior includes:

- successful v1 file publication and decode,
- successful v2 file publication and decode,
- atomic replacement of an existing destination,
- preservation of an existing valid checkpoint when replacement encoding fails,
- no partial final artifact when initial encoding fails,
- cleanup of temporary artifacts after success and failure.

This protects readers from observing a partially encoded checkpoint at the requested final path. It does not by itself guarantee directory-entry durability across every power-loss scenario because the parent directory is not separately synchronized by this Windows implementation.

---

## CLI Integration

The checkpoint command accepts an explicit format:

```text
wcre-cli checkpoint --pid <PID> --output <FILE.wcr> [--format <v1|v2>]
```

Omission selects v2. Explicit examples are:

```text
wcre-cli checkpoint --pid 1234 --output checkpoint-v1.wcr --format v1
wcre-cli checkpoint --pid 1234 --output checkpoint-v2.wcr --format v2
```

The following two commands therefore both create v2 checkpoints:

```text
wcre-cli checkpoint --pid 1234 --output checkpoint-default.wcr
wcre-cli checkpoint --pid 1234 --output checkpoint-explicit-v2.wcr --format v2
```

The inspector auto-detects both versions:

```text
wcre-cli inspect-checkpoint checkpoint-v1.wcr
wcre-cli inspect-checkpoint checkpoint-v2.wcr
```

No reader flag is required. The file's magic and persistent format version drive dispatch.

---

## Controlled Live v2 Demonstration

A fresh controlled native x64 target was captured through the CLI as v2:

```text
wcre-cli checkpoint --pid 12476 \
  --output .\experiments\live-demo-v2\controlled-demo-v2.wcr \
  --format v2
```

Observed artifact facts:

```text
Persistent format:  2
Header size:        56 bytes
File size:          11,027,070 bytes
SHA-256:            FEC97764BFA72755A23641D65F2D0B3A85CDC61F360978AE55B12B223D1EB11F
```

Before source termination, the v2 reader successfully inspected the checkpoint and recovered all five controlled sentinels:

| Captured state | Expected and observed value |
|---|---|
| Global sentinel | `0x1122334455667788` |
| Heap sentinel | `0x8877665544332211` |
| Level-one stack local | `0xA1A1A1A1A1A1A1A1` |
| Level-two stack local | `0xB2B2B2B2B2B2B2B2` |
| Level-three stack local | `0xC3C3C3C3C3C3C3C3` |

PID 12476 was then terminated. The artifact's SHA-256 remained exactly unchanged, the dual-version reader reopened it without access to the source process, and all five sentinels matched again.

A copy was modified by one byte:

```text
Corrupt artifact SHA-256:
C69FF44578232A3CDBC9BF7335CE3F4EA4EB9BDC50C4C2124B7B1F72C3C8F634
```

The CLI rejected that copy with:

```text
.wcr integrity verification failed
```

and returned exit code `1`.

This demonstrates live CLI creation, independent post-mortem inspection, and corruption rejection for a real v2 artifact.

---

## Validation Evidence

At the end of Feature #9, including the v2-default transition:

```text
cargo fmt --all -- --check    PASS
cargo check --workspace       PASS
cargo test -p wcre-image      61 passed, 0 failed
cargo test --workspace        87 passed, 0 failed
git diff --check              PASS
```

Workspace test distribution:

| Component | Passing tests |
|---|---:|
| `wcre-image` | 61 |
| `wcre-cli` | 5 |
| `wcre-win32` | 21 |
| Total | 87 |

---

## Security and Privacy Boundary

A `.wcr` checkpoint can contain process paths, module metadata, virtual addresses, thread/register state, stack content, heap content, and other captured memory. That memory may include credentials, tokens, personal data, cryptographic material, document contents, or application secrets.

Operationally, checkpoint artifacts should therefore be treated as sensitive process-memory dumps:

- restrict filesystem access,
- avoid publishing artifacts or hashes as proof of confidentiality,
- use protected transport and storage for migration or archival,
- delete demonstrations only under an explicit retention policy,
- do not decode untrusted files with elevated privileges merely because they pass SHA-256 verification.

SHA-256 detects accidental or unauthenticated modification relative to the stored digest. It does not encrypt checkpoint contents and does not identify who created them.

---

## What This Demonstrates

Research 009 demonstrates that WCRE can:

1. continue reading the established v1 wire format,
2. write and read an integrity-protected v2 format,
3. stream large v2 bodies without one whole-body RAM allocation in the verification path,
4. verify header and body bytes before deserializing the body,
5. distinguish unauthenticated corruption from authenticated malformed input,
6. enforce explicit structural and semantic limits,
7. reject a deterministic range of malformed inputs without panicking,
8. detect accidental v1 wire-format drift through a golden fixture,
9. expose intentional v1/v2 selection through the CLI,
10. publish completed checkpoint files atomically without destroying a prior valid destination on encoding failure,
11. inspect a real v2 checkpoint after the source process has terminated,
12. reject a corrupted real v2 artifact.

---

## What This Does Not Demonstrate

Research 009 does **not** demonstrate process restoration.

WCRE has not yet demonstrated:

- creation of a replacement process,
- exact reconstruction of captured virtual addresses,
- installation of memory payloads into a replacement address space,
- executable-image reconstruction,
- complete x64 context or XSTATE restoration,
- TEB or TLS reconstruction,
- kernel-handle or synchronization-object reconstruction,
- file or IPC resource restoration,
- process-tree restoration,
- continuation of execution from the captured instruction pointer,
- machine-to-machine migration.

The current proof is checkpoint capture, durable publication, integrity validation, reconstruction of the WCRE-owned model, and offline inspection after process death. Calling that restore would be incorrect.

---

## Result

**PASS — checkpoint persistence hardening validated.**

The evidence supported making v2 the default writer format while preserving an explicit v1 writer, the golden v1 bytes, and dual-reader compatibility.

The final clean validation run passed, so Feature #9 can close. The next architectural experiment is exact virtual-address reconstruction, but it is not part of this research slice.
