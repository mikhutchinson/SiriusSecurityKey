> **Status: PLAN ONLY.**

# 01 — Parity matrix and source provenance

Affected invariants: `INV-SK1`, `INV-SK3`, `INV-SK8`, `INV-SK13`,
`INV-SK14`, `INV-SK15`.

Current source anchors: `References/upstream-lock.json:4-26` pins the initial
authorities, while `PARITY.md:3-50` pins the baseline and marks every initial
comparison row unimplemented.

## Baseline authority

The initial comparison revision and hybrid subtree are pinned in
`References/upstream-lock.json`. Before implementation, expand that lock into a
reviewed inventory of relevant Chromium `device/fido` sources, build
dependencies, licenses, tests, fuzzers, feature flags, and macOS adapters.

Every upstream refresh is a new experiment. It records old/new revisions, the
subtree diff, matrix changes, retained compatibility modes, licenses, and
whether existing parity claims still hold.

## Required matrix families

The versioned matrix must enumerate at least:

1. WebAuthn option parsing, origin/RP validation, client data, timeouts,
   abort/cancel, attestation, and error mapping.
2. Creation, assertion, discoverable credentials, resident-key preferences,
   user presence, user verification, and account selection.
3. CTAP versions, `getInfo`, make credential, get assertion, next assertion,
   client PIN/UV, reset/management where exposed, keepalive, cancellation, and
   status mapping.
4. WebAuthn and CTAP extensions supported by the pinned Chromium baseline,
   including input/output direction and authenticator capability conditions.
5. Platform, USB HID, NFC, Bluetooth, and hybrid discovery/transport behavior.
6. Hybrid QR bootstrap, assigned/custom tunnel domains, BLE proximity, Noise,
   encrypted framing, linking/pairing, recovery, and version negotiation.
7. Conditional mediation, autofill-facing APIs, credential enumeration, and UI
   state events without imposing consumer UI.
8. Privacy, logging, enterprise policy, attestation filtering, and permission
   behavior.

Each row has one status: `unimplemented`, `development`, `supported`,
`unsupported`, or `not-applicable`. `supported` requires linked evidence.

## Provenance modes

- **Specification implementation:** built from normative prose and vectors;
  record exact sections and specification version.
- **Behavioral reimplementation:** derived from black-box/differential behavior;
  record exact upstream binary/source revision and test inputs.
- **Source-derived port:** translated or structurally derived from named files;
  record paths, blob hashes, destination mapping, copyright, license, and
  notices before merge.

Do not blur these modes. No source-derived file lands under a generic project
header that erases its origin.

## Exit checklist

- [ ] The full pinned Chromium surface has been inventoried.
- [ ] Every feature belongs to a matrix row with a literal status.
- [ ] Required build-time flags and platform conditions are recorded.
- [ ] Every planned source-derived port has file/blob/license mapping.
- [ ] No parity claim relies on mutable upstream `HEAD`.
- [ ] Matrix and upstream-refresh commands/results are in `EXPERIMENTS.md`.
