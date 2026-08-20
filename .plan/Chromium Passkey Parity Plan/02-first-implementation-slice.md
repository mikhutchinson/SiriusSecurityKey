> **Status: PLAN ONLY.**

# 02 — First implementation slice

Affected invariants: `INV-SK2`, `INV-SK3`, `INV-SK6` through `INV-SK12`, and
`INV-SK14`.

Current source anchors: `Sources/SiriusSecurityKey/HybridSession.swift:22-224`
composes the first route; `CanonicalCBOR.swift:3-125`,
`HybridQRCode.swift:23-123`, `HybridProximity.swift:68-198`,
`HybridTunnel.swift:37-80`, `HybridNoise.swift:14-246`, and
`AuthenticatorInfo.swift:7-76` own its explicit layers; and `PARITY.md:31-48`
classifies those rows as development rather than supported.

## Slice thesis

Prove the independent transport route before building broad WebAuthn UI or
credential-store behavior. The first retained milestone ends only when a real
phone scans a package-generated QR code, proves proximity over Bluetooth,
meets the client through the tunnel, completes the correct Noise handshake, and
returns a valid `authenticatorGetInfo` CTAP response.

## Step 1 — Bounded canonical CBOR and QR bootstrap

- Implement only the CBOR subset required by the hybrid bootstrap, with
  canonical map ordering, integer bounds, depth/size limits, and duplicate-key
  rejection.
- Generate ephemeral P-256 material and the exact QR secret size from injectable
  CSPRNG/cryptography interfaces.
- Encode and decode `FIDO:/` payloads against normative and Chromium-derived
  vectors.
- Provide QR payload data; presentation/rendering remains a consumer concern.

Acceptance: byte-identical positive vectors plus malformed, non-canonical,
truncated, duplicate, oversized, and invalid-point rejection.

## Step 2 — Bluetooth proximity adapter

- Add an actor-owned discovery state machine over an injected Bluetooth
  central abstraction.
- Derive the expected advertisement match from the active bootstrap.
- Bound scan duration, callbacks, retained advertisements, and retries.
- Separate permission-denied, unavailable, powered-off, timeout, mismatch, and
  cancellation outcomes.

Acceptance: deterministic adapter tests and one real-phone advertisement
receipt tied to the active bootstrap; raw advertisement secrets are not logged.

## Step 3 — Tunnel rendezvous

- Implement versioned assigned/custom tunnel-domain derivation.
- Use an injected WebSocket transport with bounded messages, explicit timeouts,
  no implicit mutating replay, and deterministic cancellation.
- Validate every URL, scheme, host, response, frame type, and maximum size.

Acceptance: local conformance server tests plus a real peer connection. A socket
open without handshake completion is not success.

## Step 4 — Noise and encrypted framing

- Implement the pinned hybrid handshake pattern with reviewed P-256, SHA-256,
  HKDF/HMAC, and AEAD primitives.
- Make transcript transitions explicit and single-use.
- Enforce direction/counter monotonicity and terminal failure on authentication
  error, replay, truncation, or unexpected message order.
- Verify positive and negative transcripts against authoritative vectors and a
  differential implementation.

Acceptance: byte-exact transcript vectors, tamper/replay/counter tests, and no
secret-bearing diagnostics.

## Step 5 — CTAP `authenticatorGetInfo`

- Adapt the established `AuthenticatorTransport` seam to the encrypted hybrid
  session.
- Send one bounded `authenticatorGetInfo` request and parse a bounded response.
- Preserve CTAP status and unknown capability fields without weakening required
  validation.
- Cancel every session resource on completion or failure.

Acceptance: package-generated QR through a real phone yields a validated
`getInfo` receipt; Bluetooth, tunnel, handshake, and CTAP states are separately
recorded.

## Explicitly deferred

- Make credential and get assertion.
- Persistent pairing/linking.
- Platform credential storage and conditional mediation.
- USB/NFC roaming transports.
- A Chromium-parity claim.

## Retained development evidence

- Canonical CBOR and QR pass exact bytes, malformed/truncated/bounded cases, and
  a deterministic 10,000-input mutation campaign.
- EID, tunnel, Noise transcript/traffic keys, and the first encrypted frame
  match an independently generated Python/Cryptography fixture.
- Injected end-to-end tests complete both explicit post-handshake profiles and
  prove that a profile mismatch never triggers a retry under another profile.
- Cancellation interrupts discovery and tunnel-open waits, and Noise failures
  are terminal for tamper, replay, truncation, bad padding, and counter
  exhaustion.
- Real phone, live tunnel, and relying-party gates remain unrun and therefore
  prevent every `supported` or interoperability claim.

## Exit checklist

- [x] QR bootstrap passes byte and negative vectors.
- [x] Bluetooth match is tied to the active secret and bounded in injected
      tests.
- [ ] Tunnel connection and cancellation pass local and real-peer gates.
- [x] Noise passes transcript, tamper, replay, truncation, padding, and counter
      gates.
- [ ] A real phone returns a validated CTAP `getInfo` response.
- [x] Live session secrets are absent from logs and retained artifacts;
      deterministic nonproduction vector material is explicitly labeled.
- [x] Ledgers state exact development and deferred behavior.
