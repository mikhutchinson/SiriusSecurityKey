# Chromium Passkey Parity Matrix

Baseline Chromium revision:
`535b82484305ec03127bbe951212f6afdec72a43`.

> **Current status: inventory scaffold.** Every row is unimplemented. This is
> not yet a complete inventory of the pinned Chromium surface and makes no
> parity claim.

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
| CTAP | Bounded canonical CBOR | unimplemented | — |
| CTAP | Authenticator discovery and `authenticatorGetInfo` | unimplemented | — |
| CTAP | Make credential | unimplemented | — |
| CTAP | Get assertion and next assertion | unimplemented | — |
| CTAP | Client PIN and PIN/UV auth protocols | unimplemented | — |
| CTAP | Keepalive, cancellation, and status mapping | unimplemented | — |
| Platform | Platform authenticator adapter | unimplemented | — |
| Roaming | USB HID transport | unimplemented | — |
| Roaming | NFC transport | unimplemented | — |
| Roaming | Bluetooth transport | unimplemented | — |
| Hybrid | Canonical `FIDO:/` QR bootstrap | unimplemented | — |
| Hybrid | Bluetooth proximity advertisement | unimplemented | — |
| Hybrid | Tunnel-domain derivation and WebSocket rendezvous | unimplemented | — |
| Hybrid | Noise handshake and encrypted framing | unimplemented | — |
| Hybrid | CTAP exchange over hybrid transport | unimplemented | — |
| Hybrid | Linking, pairing, revocation, and recovery | unimplemented | — |
| Security | Secret-safe diagnostics | unimplemented | — |
| Security | Parser, protocol, and state-machine fuzzing | unimplemented | — |
| Release | Clean external SwiftPM consumer | unimplemented | — |
| Release | Declared real-device/browser matrix | unimplemented | — |

The first implementation milestone may advance only the five hybrid/CTAP rows
needed for QR → proximity → tunnel → Noise → `authenticatorGetInfo`. All other
rows remain unimplemented until independently evidenced.
