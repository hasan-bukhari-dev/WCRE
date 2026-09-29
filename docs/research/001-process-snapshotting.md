# Research 001 - Windows Process Snapshotting

## Question

What process state can Windows expose consistently enough to serve as the
capture foundation for WCRE?

## Candidate mechanism

Windows Process Snapshotting API (PSS).

## State of interest

- process information
- virtual address space
- VA clone
- threads
- thread contexts
- handles
- mapped sections

## Questions to answer experimentally

1. Which PSS capture flags are required?
2. Can WCRE obtain a complete virtual-address map?
3. Can memory be read consistently from the VA clone?
4. Which thread context fields are available?
5. What handle information is recoverable?
6. What state exists outside the PSS snapshot?
7. How does snapshot capture behave while the original process continues?

## Experiment

Not implemented yet.

## Result

Pending.
