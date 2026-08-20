> **Status: PLAN ONLY.**

# 00 — Current truth, boundaries, and invariants

## Current source-backed truth

- `Package.swift:5-24` declares one Swift-only library product and one resource-
  backed test target for macOS and iOS.
- `Sources/SiriusSecurityKey/HybridSession.swift:22-224` composes the retained
  one-shot QR, proximity, tunnel, Noise, and explicit CTAP `getInfo` route.
- `Sources/SiriusSecurityKey/CanonicalCBOR.swift:3-125` and
  `Sources/SiriusSecurityKey/AuthenticatorTransport.swift:3-80` provide the
  bounded canonical byte and CTAP framing boundaries used by that route.
- `README.md:8-12` and `README.md:60-89` state that the first slice has local
  development evidence but no real-phone interoperability, passkey ceremony,
  parity, or release claim.
- `PARITY.md:3-54` pins the comparison revision and marks only the retained
  first-slice rows `development`; no row is `supported`.
- `References/upstream-lock.json:4-30` and
  `References/upstream-inventory.json:5-155` pin exact authorities, file hashes,
  license, and first-slice mappings.

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
- [x] Every later part cites affected invariant IDs.
- [x] No consumer-specific behavior enters the package boundary.
- [x] Deployed compatibility and normative conformance remain separately
      versioned.
- [x] Root ledgers agree with the plan's current-truth section.
