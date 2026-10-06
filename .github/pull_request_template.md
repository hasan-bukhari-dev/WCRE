## Goal

What single capability, fix, research result, or documentation change does this PR deliver?

## What changed

Describe the implementation at a high level.

## Evidence

List the tests, experiments, logs, or reproducible observations that support this PR.

Examples:
- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo build --workspace`
- controlled WCRE experiment results
- repeatability runs such as 10/10 acceptance

## Acceptance criteria

What must be true for this PR to be considered successful?

- [ ] Scope is limited to the stated goal.
- [ ] Formatting passes.
- [ ] Workspace tests pass.
- [ ] Workspace build passes.
- [ ] Relevant controlled experiment passes, when applicable.
- [ ] Failure paths remain fail-closed.
- [ ] Documentation is updated when the public project state changes.

## What this does NOT prove

Explicitly state the claims that would be premature after this PR.

For restore research, examples include:
- does not prove general Windows process restoration
- does not prove multi-thread restoration
- does not prove cross-machine migration
- does not prove execution continuation unless captured execution was actually resumed

## Next step

What is the next concrete milestone after this PR?
