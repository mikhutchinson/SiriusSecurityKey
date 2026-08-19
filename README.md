# SiriusSecurityKey

SiriusSecurityKey is a general-purpose, 100% Swift implementation of passkey,
WebAuthn, CTAP, and FIDO hybrid transports for applications that need a real
browser-grade authenticator client without depending on a privileged browser
or a private platform API.

> **Status: pre-implementation scaffold.** The package currently defines and
> tests the raw CTAP transport boundary. It does not yet authenticate, create a
> passkey, display a QR code, discover a phone, or claim interoperability.

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

The first implementation slice is deliberately narrower: QR bootstrap → phone
proximity → tunnel → Noise handshake → `authenticatorGetInfo`. See the
[Chromium Passkey Parity Plan](.plan/Chromium%20Passkey%20Parity%20Plan/README.md).

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
project's license.
