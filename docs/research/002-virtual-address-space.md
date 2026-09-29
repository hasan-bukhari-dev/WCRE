# Research 002 - Windows Virtual Address Space Enumeration

## Question

Can WCRE reliably enumerate the observable user-mode virtual address space
of a live Windows x64 process?

## Mechanism

WCRE uses `VirtualQueryEx` to walk the process address space region by region.

For each region it records:

- base address
- allocation base
- region size
- allocation protection
- state
- type
- current protection

## Access requirements

The process is opened with `PROCESS_QUERY_INFORMATION`.

## Experiment

Target: Windows PowerShell x64

Command:

    wcre-cli memory-map --pid <PID>

Observed result:

    Regions:    2011
    Committed:  313.31 MiB
    Reserved:   2052.37 GiB
    Private:    37.49 MiB
    Mapped:     71.20 MiB
    Image:      204.61 MiB

The committed type totals agree with the total committed memory after
display rounding.

The address-space walk reached the upper user-mode range without looping,
moving backward, or crashing.

An invalid PID was also tested and produced a normal Windows error rather
than a panic.

## Notes

Large reserved address ranges are expected in 64-bit processes and do not
represent equivalent physical-memory consumption.

WCRE normalizes fields that Windows documents as undefined for free or
reserved regions rather than interpreting their raw values.

## Result

PASS.

WCRE can enumerate and classify the virtual-memory regions of a live x64
Windows process.

## Next questions

- Can WCRE reliably read the contents of every committed readable region?
- Which regions change while the target continues executing?
- How does this live view compare with a PSS VA clone?
- Which allocation boundaries must be preserved during reconstruction?
