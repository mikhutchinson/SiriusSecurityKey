# SiriusSecurityKey

SiriusSecurityKey is a general-purpose, 100% Swift implementation of passkey,
WebAuthn, CTAP, and FIDO hybrid transports for applications that need a real
browser-grade authenticator client without depending on a privileged browser
or a private platform API.

> **Status: first hybrid slice in development.** The package now implements the
> bounded QR → Bluetooth proximity → WebSocket tunnel → Noise → CTAP
> `authenticatorGetInfo` route. Independent vectors and injected end-to-end
> tests pass; no real-phone run, passkey ceremony, parity, production-support,
> or release claim has been made.

## Goal

The project targets observable feature parity with Chromium's passkey stack,
including cross-device QR and Bluetooth proximity flows, tunnel transport,
encrypted hybrid sessions, roaming authenticators, platform authenticators,
WebAuthn request semantics, extensions, cancellation, and conditional flows.

Parity is an evidence claim. A feature becomes supported only after the
corresponding row in the versioned parity matrix passes protocol vectors,
differential checks where possible, and declared real-device interoperability
gates. Compiling code or completing a single demonstration is not parity.

## Product boundary

- The distributed package is SwiftPM and contains Swift only.
- It does not embed Python, a Python runtime, a browser engine, or an HTTP
  service.
- Public APIs describe WebAuthn, CTAP, authenticators, transports, ceremonies,
  and security policy—not any consuming application's UI or data model.
- Public Apple frameworks may provide Bluetooth, cryptography, networking,
  secure storage, and optional platform adapters. The core protocol may not
  depend on undocumented APIs or an entitlement granted only to selected
  applications.
- Chromium and FIDO specifications are implementation references and
  interoperability authorities. Provenance and license obligations are tracked
  before derived code lands.

## Intended architecture

```text
Consumer WebAuthn request
        ↓
Origin, RP ID, gesture, policy, and ceremony validation
        ↓
Authenticator selection
   ├─ platform credential store
   ├─ USB / NFC / Bluetooth roaming authenticator
   └─ hybrid authenticator
        ├─ FIDO:/ QR bootstrap
        ├─ Bluetooth proximity proof
        ├─ WebSocket tunnel
        └─ Noise-protected CTAP exchange
        ↓
Verified WebAuthn response
```

The retained implementation slice is deliberately narrower: QR bootstrap →
phone proximity → tunnel → Noise handshake → `authenticatorGetInfo`. See the
[Chromium Passkey Parity Plan](.plan/Chromium%20Passkey%20Parity%20Plan/README.md).

## Development API

```swift
let session = try HybridSession(
  qrConfiguration: HybridQRConfiguration(requestType: .getAssertion),
  wireProfile: .pxp20260717
)

// The consumer owns QR rendering and explicit user intent.
renderQRCode(session.qrURI)

let info = try await session.getInfo(
  scanner: CoreBluetoothHybridScanner()
)
```

`HybridWireProfile` must be selected explicitly before I/O. A failed PXP parse
is never retried as Chromium revision-zero framing, or vice versa. The one-shot
session also rejects pairing and BLE data-channel advertisements, unknown
assigned-domain counts, and non-getAssertion hints until those capabilities
exist.

Consumer apps must provide the applicable Apple Bluetooth usage description
and own presentation, lifecycle, consent, and cancellation. The package emits
no protocol payloads or secrets to logs. This API currently stops after a
validated `getInfo`; it does not create or assert a credential.

## Build

```bash
swift build
swift test
swift build -c release
```

## Evidence and changes

- [`EXPERIMENTS.md`](EXPERIMENTS.md) records commands, inputs, results,
  artifacts, and keep/discard/defer decisions.
- [`bugfix.md`](bugfix.md) records defects, risks, root causes, fixes, and
  verification.
- [`changelog.md`](changelog.md) records notable repository and behavior
  changes.
- [`PARITY.md`](PARITY.md) records the versioned Chromium comparison matrix.
- [`.plan/`](.plan/) contains plan-only implementation contracts.

Those records are mandatory parts of the repository contract. See
[`AGENTS.md`](AGENTS.md) before making changes.

## License

SiriusSecurityKey is licensed under the BSD 3-Clause License. Files derived
from another project must retain the original notices required by that
project's license. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and
[`References/upstream-inventory.json`](References/upstream-inventory.json).
