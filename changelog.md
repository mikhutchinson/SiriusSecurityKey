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

### Current limitations

- No authenticator transport or WebAuthn ceremony is implemented.
- No passkey or Chromium-parity claim is made.
- No version has been released.
