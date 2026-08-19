> **Status: PLAN ONLY.**

# 00 — Current truth, boundaries, and invariants

## Current source-backed truth

- `Package.swift:5-23` declares one Swift-only library product and one test
  target for macOS and iOS.
- `Sources/SiriusSecurityKey/AuthenticatorTransport.swift:3-77` defines only
  raw CTAP framing, transport kinds, and a transport protocol.
- `README.md:8-22` explicitly states that no authenticator operation,
  interoperability, or parity exists yet.
- `README.md:24-37` fixes the Swift-only, general-purpose product boundary.
- `PARITY.md:3-17` pins the comparison revision and defines evidence-bearing
  row statuses; `PARITY.md:19-50` marks every initial row unimplemented.
- `References/upstream-lock.json:4-26` pins the initial Chromium and
  specification authorities.

## Problem

Applications can issue standards-compliant WebAuthn requests yet still lack an
available platform route to a passkey. Chromium demonstrates that cross-device
authentication can be implemented through public protocol components: a QR
bootstrap, Bluetooth proximity proof, network tunnel, encrypted handshake, and
CTAP/WebAuthn client. This project implements that complete route directly in
Swift and expands outward until the declared Chromium feature matrix has no
unsupported rows.

## Boundaries

- The package owns protocol correctness and transport state, not consumer UI.
- The package accepts trusted origin, RP, gesture, policy, and lifecycle inputs
  through explicit APIs; it does not infer them from arbitrary page strings.
- Native platform APIs are adapters, not protocol authorities.
- Chromium is a pinned implementation reference, not a dependency graph.
- Normative specs override accidental implementation behavior unless deployed
  compatibility requires an explicit, versioned mode.

## Invariants

The normative invariants are `INV-SK1` through `INV-SK15` in `AGENTS.md`.
Plan parts cite those IDs rather than inventing weaker local variants.

Additional first-slice consequences:

- QR and handshake secrets are ephemeral, zeroized where practical, and never
  rendered into diagnostics.
- Bluetooth discovery has a bounded lifetime and accepts only advertisements
  cryptographically tied to the active bootstrap.
- Tunnel connection alone is not success; encrypted handshake and CTAP response
  are separate states.
- A failed or cancelled mutating CTAP request is never automatically replayed.
- Pairing and persistent credential storage are deferred until one-shot flow is
  correct.

## Exit checklist

- [x] Current-source claims have exact, current file and line references.
- [ ] Every later part cites affected invariant IDs.
- [ ] No consumer-specific behavior enters the package boundary.
- [ ] Deployed compatibility and normative conformance remain separately
      versioned.
- [ ] Root ledgers agree with the plan's current-truth section.
