# Research 003 - Live Process Memory Reading

## Question

Can WCRE read the contents of every committed region that Windows reports
as readable in a live Windows x64 process?

## Mechanism

WCRE combines its VirtualQueryEx address-space map with ReadProcessMemory.

Only committed regions with readable, non-guarded protections are selected.

Large regions are read in chunks.

For experimental verification, WCRE computes an FNV-1a fingerprint over
the observed addresses and bytes.

The fingerprint is not intended as a cryptographic integrity mechanism.

## Experiment

Target: Windows PowerShell x64

Command:

    wcre-cli memory-read --pid <PID>

First observed run:

    Readable regions:       1612
    Fully read regions:     1612
    Regions with failures:  0
    Readable bytes:         258.23 MiB
    Bytes read:             258.23 MiB
    Coverage:               100.0000%
    Failed chunks:          0

Second observed run:

    Readable regions:       1595
    Fully read regions:     1595
    Regions with failures:  0
    Readable bytes:         258.34 MiB
    Bytes read:             258.34 MiB
    Coverage:               100.0000%
    Failed chunks:          0

## Observation

Both runs achieved complete coverage of all regions classified as readable.

The region count, readable-byte total, and fingerprint changed between
runs because the target process remained live during enumeration and
reading.

This confirms that the current mechanism can read live process memory, but
does not provide a point-in-time consistent checkpoint.

## Result

PASS.

WCRE can enumerate readable committed memory and copy the corresponding
bytes from a live Windows x64 process with complete observed coverage.

## Next questions

- Can a PSS VA clone provide a stable point-in-time memory view?
- Can repeated reads from a PSS clone produce identical fingerprints?
- Which process-memory regions are omitted or altered by PSS?
- How should persistent checkpoint images encode memory-region metadata and bytes?
