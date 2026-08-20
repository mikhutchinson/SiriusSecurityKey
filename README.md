# SiriusSecurityKey

SiriusSecurityKey is a general-purpose, 100% Swift implementation of passkey,
WebAuthn, CTAP, and FIDO hybrid transports for applications that need a real
browser-grade authenticator client without depending on a privileged browser
or a private platform API.

> **Status: trust-bound assertion slice in development.** The package now binds
> a normalized origin, validated RP ID, exact client data, explicit intent,
> credential policy, authenticator capabilities, hybrid transport, strict CTAP
> assertion parsing, and independent RP verification. Local vectors, mutation,
> sanitizer, and injected end-to-end tests pass. Physical iPhone/Android rows,
> Chromium parity, production support, and release certification remain
> separate evidence gates.

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

The retained implementation slice is deliberately narrower than the complete
architecture: a trust-bound `webauthn.get` ceremony over the QR → proximity →
tunnel → Noise → CTAP hybrid path. See the [Chromium Passkey Parity Plan](.plan/Chromium%20Passkey%20Parity%20Plan/README.md).

## Development API

```swift
let request = try WebAuthnAssertionRequest(
  origin: WebAuthnOrigin("https://login.example.com"),
  relyingPartyID: "example.com",
  challenge: challengeFromServer,
  allowCredentials: [
    try WebAuthnCredentialDescriptor(
      id: credentialIDFromServer,
      transports: [.hybrid]
    )
  ],
  userVerification: .required
)
let ceremony = try await ValidatedWebAuthnAssertionCeremony.authorize(
  request,
  using: applicationIntentAuthorizer
)

let session = try HybridSession(
  qrConfiguration: HybridQRConfiguration(requestType: .getAssertion),
  wireProfile: explicitlySelectedProfile
)
renderQRCode(session.qrURI) // Consumer-owned presentation.

let assertion = try await session.getAssertion(
  ceremony: ceremony,
  scanner: CoreBluetoothHybridScanner()
)
```

`HybridWireProfile` must be selected explicitly before I/O. A failed PXP parse
is never retried as Chromium revision-zero framing, or vice versa. The one-shot
session also rejects pairing and BLE data-channel advertisements, unknown
assigned-domain counts, and non-getAssertion hints until those capabilities
exist.

Consumer apps must provide the applicable Apple Bluetooth usage description
and own presentation, lifecycle, consent, account selection, and cancellation.
The package supplies no permissive intent authorizer and emits no protocol
payloads or secrets to logs. The returned assertion can be checked against
server-retained ceremony and credential state with
`WebAuthnServerAssertionVerifier`.

## Controlled RP harness

`Tools/ControlledRP` is a separate Swift-only live gate, not a distributed
library dependency. It serves a bounded in-memory HTTPS relying party through a
consumer-provided TLS endpoint, verifies required-UV discoverable ES256 browser
registrations, renders a one-shot hybrid QR, and accepts an assertion only after
independent server-side challenge, origin, RP hash, signature, user-handle, and
counter verification.

Build the app before starting either process. App assembly stages a complete
bundle, moves the previous bundle aside, and publishes the staged directory, so
a rebuild never overwrites an executable mapped by an active ceremony or
server.

```bash
Tools/ControlledRP/build-app.sh

Tools/ControlledRP/.build/SiriusSecurityKeyControlledRP.app/Contents/MacOS/SiriusSecurityKeyControlledRP \
  serve --origin https://rp.example.test --port 8019

Tools/ControlledRP/.build/SiriusSecurityKeyControlledRP.app/Contents/MacOS/SiriusSecurityKeyControlledRP \
  assert --server https://rp.example.test --mode allow-list \
  --device iPhone --profile pxp-20260717
```

The wire profile is mandatory; the harness never probes a second profile. RP
state is memory-only and logs contain stage names and opaque receipt IDs, not
credential IDs, assertions, challenges, user handles, or QR material.

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
