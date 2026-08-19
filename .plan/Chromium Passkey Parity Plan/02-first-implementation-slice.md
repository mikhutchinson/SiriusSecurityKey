> **Status: PLAN ONLY.**

# 02 — First implementation slice

Affected invariants: `INV-SK2`, `INV-SK3`, `INV-SK6` through `INV-SK12`, and
`INV-SK14`.

Current source anchors: `Sources/SiriusSecurityKey/AuthenticatorTransport.swift:3-77`
is the complete retained protocol surface, and `PARITY.md:31-45` shows that the
required CTAP and hybrid capabilities remain unimplemented.

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

## Exit checklist

- [ ] QR bootstrap passes byte and negative vectors.
- [ ] Bluetooth match is tied to the active secret and bounded.
- [ ] Tunnel connection and cancellation pass local and real-peer gates.
- [ ] Noise passes transcript, tamper, replay, and counter gates.
- [ ] A real phone returns a validated CTAP `getInfo` response.
- [ ] Secrets are absent from logs and retained experiment artifacts.
- [ ] Ledgers state exact supported and deferred behavior.
