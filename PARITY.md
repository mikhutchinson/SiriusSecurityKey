# Chromium Passkey Parity Matrix

Baseline Chromium revision:
`535b82484305ec03127bbe951212f6afdec72a43`.

> **Current status: first slice in development.** Nine bounded CTAP, hybrid,
> and security rows have retained source and local evidence. None is supported:
> the Chromium inventory and every real-device/release gate remain incomplete.

Status vocabulary:

- `unimplemented` — no retained implementation or supporting claim.
- `development` — implementation exists, but required evidence is incomplete.
- `supported` — every declared vector, negative, differential, interoperability,
  and release-byte gate for the row passed.
- `unsupported` — reviewed and deliberately unavailable, with a linked reason.
- `not-applicable` — outside the versioned comparison surface, with rationale.

| Family | Capability | Status | Evidence |
|---|---|---|---|
| WebAuthn | Origin and RP ID validation | unimplemented | — |
| WebAuthn | `clientDataJSON` construction and verification | unimplemented | — |
| WebAuthn | Credential creation | unimplemented | — |
| WebAuthn | Credential assertion | unimplemented | — |
| WebAuthn | Discoverable credentials and account selection | unimplemented | — |
| WebAuthn | User presence and user verification policy | unimplemented | — |
| WebAuthn | Conditional mediation and autofill-facing events | unimplemented | — |
| WebAuthn | Timeout, abort, cancellation, and error mapping | unimplemented | — |
| WebAuthn | Attestation policy and formats | unimplemented | — |
| WebAuthn | Chromium-baseline extension inventory | unimplemented | — |
| CTAP | Bounded canonical CBOR | development | [EXP-007](EXPERIMENTS.md#exp-007--first-hybrid-slice-and-independent-vectors) |
| CTAP | Authenticator discovery and `authenticatorGetInfo` | development | [EXP-007](EXPERIMENTS.md#exp-007--first-hybrid-slice-and-independent-vectors) |
| CTAP | Make credential | unimplemented | — |
| CTAP | Get assertion and next assertion | unimplemented | — |
| CTAP | Client PIN and PIN/UV auth protocols | unimplemented | — |
| CTAP | Keepalive, cancellation, and status mapping | unimplemented | — |
| Platform | Platform authenticator adapter | unimplemented | — |
| Roaming | USB HID transport | unimplemented | — |
| Roaming | NFC transport | unimplemented | — |
| Roaming | Bluetooth transport | unimplemented | — |
| Hybrid | Canonical `FIDO:/` QR bootstrap | development | [EXP-007](EXPERIMENTS.md#exp-007--first-hybrid-slice-and-independent-vectors) |
| Hybrid | Bluetooth proximity advertisement | development | [EXP-007](EXPERIMENTS.md#exp-007--first-hybrid-slice-and-independent-vectors) |
| Hybrid | Tunnel-domain derivation and WebSocket rendezvous | development | [EXP-008](EXPERIMENTS.md#exp-008--fail-closed-negative-and-cancellation-gates) |
| Hybrid | Noise handshake and encrypted framing | development | [EXP-007](EXPERIMENTS.md#exp-007--first-hybrid-slice-and-independent-vectors) |
| Hybrid | CTAP exchange over hybrid transport | development | [EXP-008](EXPERIMENTS.md#exp-008--fail-closed-negative-and-cancellation-gates) |
| Hybrid | Linking, pairing, revocation, and recovery | unimplemented | — |
| Security | Secret-safe diagnostics | development | [EXP-008](EXPERIMENTS.md#exp-008--fail-closed-negative-and-cancellation-gates) |
| Security | Parser, protocol, and state-machine fuzzing | development | [EXP-008](EXPERIMENTS.md#exp-008--fail-closed-negative-and-cancellation-gates) |
| Release | Clean external SwiftPM consumer | unimplemented | — |
| Release | Declared real-device/browser matrix | unimplemented | — |

`development` here means local implementation evidence only. A row cannot move
to `supported` until its declared differential, real-device, and release-byte
gates pass. All other rows remain unimplemented until independently evidenced.
