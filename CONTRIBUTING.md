# Contributing to WCRE

WCRE ("Waker") is an experimental Windows x64 checkpoint/restore research
project.

Its long-term goal is CRIU-style process checkpoint/restore for Windows:
capture a running process, persist enough execution state to a `.wcr`
checkpoint, allow the original process to terminate, reconstruct a new process,
and eventually continue execution from the captured instruction rather than
restarting from `main()`.

WCRE is research software. Changes should favor correctness, reproducibility,
and explicit failure over unsupported best-effort behavior.

## Development workflow

`main` should always represent a tested and defensible research state.

Do not develop directly on `main`.

Use this workflow:

```text
main
  |
  +-- branch
        |
        +-- implement
        +-- test
        +-- run relevant controlled experiment
        +-- commit
        +-- push branch
        +-- open pull request
        +-- review evidence
        +-- squash and merge
        +-- delete branch
```

### Branch naming

Use:

```text
feature/...   new supported capability
fix/...       bug fix
research/...  isolated research experiment
docs/...      documentation-only change
chore/...     repository or development infrastructure
```

Examples:

```text
feature/captured-application-thread-selection
feature/teb-reconciliation
research/image-state-classification
docs/restore-architecture
chore/github-standardization
```

## Required local checks

Before opening a pull request, run:

```powershell
cargo fmt --all -- --check
cargo test --workspace
cargo build --workspace
```

The GitHub Windows CI workflow runs the same checks.

When working on the CLI after previous builds, do not assume an existing
`target\debug\wcre-cli.exe` is current. For important restore experiments,
remove the stale executable before rebuilding when appropriate:

```powershell
Remove-Item ".\target\debug\wcre-cli.exe" -Force -ErrorAction SilentlyContinue
cargo build --workspace
```

## Reviewing changes

Inspect changes before committing.

Prefer:

```powershell
git diff --check
git --no-pager diff
git status --short
```

Avoid relying on a large unreviewed change set.

WCRE development should proceed in small, reviewable milestones with a clear
acceptance condition.

## Pull requests

Each pull request should deliver one coherent capability, fix, research result,
documentation update, or infrastructure change.

The pull request template requires:

- Goal
- What changed
- Evidence
- Acceptance criteria
- What this does NOT prove
- Next step

Research claims must match the evidence actually demonstrated.

For example, reconstructing memory does not prove process restoration, and
installing a saved CPU context does not prove execution continuation unless
captured execution is actually resumed successfully.

## Research discipline

WCRE should fail closed.

If required process state is missing, ambiguous, conflicting, or unsupported,
stop rather than guessing.

Examples:

```text
zero valid restore candidates       -> fail
multiple ambiguous candidates       -> fail
unknown occupied address range      -> fail
payload metadata mismatch           -> fail
restore readback mismatch           -> fail
unsupported state                   -> report explicitly
```

Never silently approximate unsupported restoration behavior.

Controlled targets and instrumentation may be used to prove correctness, but
the long-term restoration mechanism must not require application cooperation.

## Acceptance experiments

A feature is not considered demonstrated merely because it compiles.

Where appropriate, use a controlled experiment that verifies the capability
inside an actual Windows process.

Important restore milestones should be repeated enough to establish
repeatability. WCRE has used 10/10 controlled acceptance runs for major restore
experiments.

Preserve the distinction between:

```text
implemented
tested
demonstrated
generalized
```

These are not equivalent claims.

## Architecture boundaries

WCRE has three primary layers.

### `wcre-image`

Platform-independent checkpoint state.

Responsibilities include:

- `CheckpointModel`
- `.wcr` encoding and decoding
- checkpoint integrity
- semantic validation
- deterministic restore planning
- model-level restore decisions that do not require Win32

`wcre-image` must not depend on Windows handles, PSS objects, or Windows
`CONTEXT` structures.

Unsafe Rust is forbidden in this crate.

### `wcre-win32`

Windows-specific mechanisms.

Responsibilities include:

- process inspection
- virtual-memory operations
- PSS snapshot capture
- thread and TEB observation
- remote memory access
- debugger-controlled process staging
- exact-address reconstruction
- PE relocation
- future TEB and CPU-context manipulation

Unsafe Windows API interaction belongs here.

### `wcre-cli`

Orchestration and research interface.

Responsibilities include:

- parsing commands
- composing `wcre-image` and `wcre-win32`
- running controlled research probes
- presenting diagnostics and verification results

The CLI should not become the permanent home for model logic or reusable
Windows primitives.

## Checkpoint and experiment artifacts

Do not casually commit large generated checkpoint files, build outputs, or
temporary experiment data.

Keep controlled experiment artifacts separate from source code.

Before staging changes, inspect:

```powershell
git status --short
```

Do not use broad staging commands when they could accidentally include
untracked research artifacts.

Prefer explicitly staging intended files:

```powershell
git add -- path\to\file
```

## Restore claims

Until WCRE actually resumes captured execution successfully, documentation and
CLI output must not claim successful process restoration.

The current north-star proof is:

```text
capture running process
        |
        v
persist .wcr
        |
        v
terminate original
        |
        v
create replacement process
        |
        v
reconstruct captured state
        |
        v
reconcile Windows thread/runtime state
        |
        v
install captured CPU context
        |
        v
resume captured RIP/RSP
        |
        v
continue through captured call stack
```

Only after that controlled continuation succeeds should WCRE claim execution
continuation.

General Windows process restoration, multi-thread restoration, resource
restoration, and cross-machine migration require additional evidence beyond
that milestone.

## Documentation

Architecture documentation should describe what the repository actually
implements.

Generated diagrams may be useful for visualization, but the maintained WCRE
architecture and research documentation are authoritative.

When a pull request materially changes the demonstrated project boundary,
update the relevant documentation in the same milestone or an immediately
following documentation pull request.
