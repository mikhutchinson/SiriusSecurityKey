# Changelog

All notable repository, public API, behavior, documentation, and release
changes are recorded here. `EXPERIMENTS.md` owns reproducible evidence;
`bugfix.md` owns defects and risks.

## Unreleased

### Added

- Created the standalone SwiftPM package for macOS 13+ and iOS 16+.
- Added the byte-preserving `CTAPRequest`, `CTAPResponse`, and
  `AuthenticatorTransport` public seam.
- Added Swift Testing coverage for CTAP request/response framing and empty-frame
  rejection.
- Added the Chromium passkey parity plan and its first QR-to-`getInfo` vertical
  slice.
- Added the versioned Chromium comparison matrix with every initial capability
  explicitly marked unimplemented.
- Added mandatory experiment, bugfix/risk, changelog, and plan ledgers.
- Added the exact initial Chromium and specification reference lock.
- Added BSD 3-Clause licensing, security reporting guidance, and CI source
  gates.
- Added bounded CTAP2 canonical CBOR with strict decoding, duplicate-key and
  noncanonical-order rejection, and explicit allocation limits.
- Added session-owned canonical `FIDO:/` bootstrap generation, authenticated
  Bluetooth proximity discovery, assigned/hashed tunnel routing, a strict
  binary WebSocket adapter, Noise KNpsk0, encrypted transport framing, and a
  validated CTAP `authenticatorGetInfo` exchange.
- Added explicit current-PXP and Chromium caBLE revision-zero wire profiles;
  profile mismatch fails terminally and never triggers compatibility retry.
- Added independent Python/Cryptography byte vectors for QR, HKDF, EID, Noise,
  traffic keys, and encrypted framing, plus malformed/truncated/bounded,
  deterministic mutation, tamper, replay, counter, and cancellation tests.
- Added exact Chromium file hashes and source-to-destination mapping, dated
  specification hashes, retained third-party notices, and vector provenance.
- Added CoreBluetooth and URLSession production adapters while preserving
  injectable scanner, clock, randomness, channel, and connector boundaries.
- Added exact-version WHATWG/UTS #46 URL and IDNA parsing plus Chromium's pinned
  ICANN/private public-suffix snapshot for fail-closed origin and RP binding.
- Added immutable assertion requests, explicit user-intent authorization,
  exact WebAuthn Level 3 collected-client-data bytes, and opaque CTAP plan
  compilation against validated authenticator capabilities.
- Added strict `authenticatorGetAssertion`/bounded
  `authenticatorGetNextAssertion`, authenticator-data and extension parsing,
  credential/account selection, RP-hash, UP/UV, backup-state, and counter
  handling without U2F, profile, UV, probing, or replay fallback.
- Added an independent ES256 RP verifier for server-retained challenge, origin,
  RP, credential, user-handle, signature, and counter state.
- Added a separate Swift-only controlled-RP harness with bounded in-memory HTTPS
  registration/assertion endpoints, strict `fmt=none` ES256 registration,
  explicit wire-profile selection, QR presentation, and secret-free receipts.
- Added 60 package tests and two controlled-RP tests covering exact bytes,
  malformed/truncated responses, signed-boundary mutation, capability mismatch,
  account-selection timeout, single-dispatch ambiguity, and server verification.

### Current limitations

- Credential creation in the package, persistent pairing, BLE data transport,
  USB/NFC/platform authenticators, and conditional mediation are not
  implemented.
- Physical iPhone and Android controlled-RP assertion receipts remain unpassed;
  local source, mock transport, public-ingress smoke, and server-state tests do
  not satisfy those rows.
- No passkey or Chromium-parity claim is made.
- No version has been released.

### Changed

- Updated GitHub Actions checkout from v4 to v5 after the first hosted run
  exposed the former action's deprecated Node.js 20 runtime.
- Expanded hosted CI with format, JSON provenance/vector, and generic iOS build
  gates in addition to debug tests and the release build.
- Made explicit session cancellation terminal across discovery, tunnel-open,
  and active channel waits; it no longer waits for the proximity timeout.
- Replaced the hard-coded hybrid `getInfo` endpoint with one private actor-owned
  authenticator transport used by both capability diagnostics and typed
  assertion execution; every ambiguous post-dispatch failure closes it.
- Corrected established revision-zero framing to raw encrypted CTAP with no
  shutdown frame; current PXP retains typed CTAP/update/shutdown messages.
- Added exact `swift-url` 0.4.2 and its resolved `swift-system` 1.8.1 transitive
  dependency, with version, revision, license, and notice locks.
- Expanded hosted CI to run AddressSanitizer, ThreadSanitizer, and the separate
  controlled-RP build/test gate.
