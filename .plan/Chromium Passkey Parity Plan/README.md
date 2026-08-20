> **Status: PLAN ONLY.**

# Chromium Passkey Parity Plan

## Thesis

Build a 100% Swift, general-purpose WebAuthn/CTAP client whose observable
passkey behavior reaches versioned feature parity with Chromium, beginning with
the independent cross-device hybrid path: canonical `FIDO:/` QR bootstrap,
Bluetooth proximity, tunnel rendezvous, Noise-protected transport, and CTAP
exchange. Parity is accepted row-by-row against exact upstream and
specification locks; it is never inferred from common source ancestry or one
successful demonstration.

## Scope

- WebAuthn creation and assertion ceremonies.
- CTAP encoding, commands, PIN/UV, extensions, and authenticator discovery.
- Platform, USB, NFC, Bluetooth, and hybrid transport adapters.
- QR/bootstrap, proximity, tunnel, Noise, pairing, cancellation, and recovery.
- Conditional mediation and discoverable-credential APIs without embedding a
  consumer UI.
- Differential, vector, fuzz, real-device, and release evidence.

## Non-goals

- A browser engine or HTML renderer.
- Consumer-specific UI or relying-party exceptions.
- A required Python runtime, sidecar process, daemon, or hosted API.
- Private frameworks, undocumented APIs, or selectively granted entitlements.
- Wholesale vendoring of Chromium infrastructure.
- Claiming parity before every claimed matrix row has evidence.

## Read order

| Part | Purpose |
|---|---|
| [00](00-overview-and-invariants.md) | Lock current truth, boundaries, invariants, and parity semantics. |
| [01](01-parity-matrix-and-provenance.md) | Define the Chromium/specification lock, provenance, and feature matrix. |
| [02](02-first-implementation-slice.md) | Sequence QR → BLE → tunnel → Noise → `authenticatorGetInfo`. |
| [03](03-test-and-release-plan.md) | Define negative, differential, interoperability, security, and release gates. |
| [04](04-trust-bound-assertion-slice.md) | Bind origin, RP ID, intent, and exact client data to one typed hybrid assertion. |

## Dependency graph

```text
00 current truth and invariants
        ↓
01 parity matrix and provenance
        ↓
02 first hybrid implementation slice
        ↓
04 trust-bound assertion slice
        ↓
03 test, interoperability, and release gates
        ↺ evidence updates 01 and the root ledgers
```

## Build order

1. Freeze the feature matrix and source/specification revision.
2. Land bounded canonical CBOR and QR bootstrap vectors.
3. Land dependency-injected Bluetooth advertisement matching.
4. Land tunnel-domain derivation and cancellable WebSocket rendezvous.
5. Land Noise transcript and encrypted framing vectors.
6. Exchange `authenticatorGetInfo` with a real phone.
7. Compile one immutable trust-bound assertion plan and execute it through the
   one-shot hybrid owner against controlled relying-party evidence.
8. Connect creation, extensions, and additional transports to the same
   ceremony compiler and typed execution boundary.
9. Certify parity per matrix row and separately certify release bytes.

## Hard invariants

All work preserves `INV-SK1` through `INV-SK15` from `AGENTS.md`. The first
slice especially depends on `INV-SK6` through `INV-SK12` and cannot weaken
origin, intent, or terminal-cancellation behavior to obtain interoperability.

## Overall exit gate

- The versioned matrix covers Chromium's passkey surface and contains no
  unclassified rows.
- Every supported row points to exact source, vector/differential, negative,
  and applicable real-device evidence.
- Hybrid assertion and creation work with declared iPhone and Android peers
  through independent QR/Bluetooth/tunnel operation.
- Platform and roaming-authenticator rows pass their declared matrices.
- The released SwiftPM tag resolves in a clean external consumer and matches
  the tested revision and license inventory.
- Unsupported or platform-limited rows are literal; “100% parity” is not used
  until none remain in the claimed baseline.
