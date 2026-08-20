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

### Current limitations

- No WebAuthn ceremony, credential creation/assertion, persistent pairing, BLE
  data transport, USB/NFC/platform authenticator, or conditional mediation is
  implemented.
- No live phone, live tunnel, or real relying-party interoperability gate has
  been run.
- No passkey or Chromium-parity claim is made.
- No version has been released.

### Changed

- Updated GitHub Actions checkout from v4 to v5 after the first hosted run
  exposed the former action's deprecated Node.js 20 runtime.
- Expanded hosted CI with format, JSON provenance/vector, and generic iOS build
  gates in addition to debug tests and the release build.
- Made explicit session cancellation terminal across discovery, tunnel-open,
  and active channel waits; it no longer waits for the proximity timeout.
