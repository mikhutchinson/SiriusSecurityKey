# `.plan/` — implementation plans

Plans are design and acceptance contracts, not shipped behavior or evidence.
Every plan lives in `.plan/<Name> Plan/`, begins with a `PLAN ONLY` marker, and
contains independently reviewable numbered parts.

The plan entry point defines its thesis, scope, non-goals, read order,
dependency graph, build order, invariants, and overall exit gate. Numbered parts
cite current source exactly, define security and compatibility consequences,
state acceptance evidence, and end with an exit checklist.

Observed results belong in `EXPERIMENTS.md`; defects and risks belong in
`bugfix.md`; notable retained changes belong in `changelog.md`. A plan never
turns an unimplemented capability into a current claim.

## Active plans

- [Chromium Passkey Parity Plan](Chromium%20Passkey%20Parity%20Plan/README.md)
