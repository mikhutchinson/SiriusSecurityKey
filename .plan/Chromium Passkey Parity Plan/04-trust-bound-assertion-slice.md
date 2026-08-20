> **Status: PLAN ONLY.**

# 04 — Trust-bound cross-device assertion slice

Affected invariants: `INV-SK1` through `INV-SK11`, `INV-SK13`, `INV-SK14`,
and `INV-SK15`.

## Current source-backed truth

- `WebAuthnTrust.swift`, `PublicSuffixDatabase.swift`, and the exact-version
  `swift-url` dependency now bind WHATWG/UTS #46 origin normalization to the
  pinned Chromium ICANN/private public-suffix snapshot.
- `WebAuthnAssertion.swift`, `WebAuthnClientData.swift`,
  `CTAPAssertion.swift`, and `AuthenticatorData.swift` now retain immutable
  intent-authorized ceremony input, exact collected-client-data bytes, opaque
  compiled plans, strict assertion parsing, and bounded next-assertion state.
- `HybridSession.swift` now owns one private
  `HybridAuthenticatorTransport`; typed assertion execution is public while
  the live hybrid CTAP channel and encoded plan remain inaccessible.
- `WebAuthnServerAssertionVerifier.swift` and `Tools/ControlledRP` independently
  verify ES256 signatures, user handles, RP hashes, UV, and signature counters.
  The public HTTPS ingress and local server-state tests have passed; physical
  iPhone and Android assertion receipts remain unpassed.
- `PARITY.md` classifies the retained WebAuthn and CTAP rows only as
  `development`, pending physical-device and release-byte evidence.

## Thesis

The next retained capability is one real cross-device WebAuthn assertion, not
another transport. A caller supplies untrusted assertion options and an
explicit intent authority. The package normalizes and validates the origin and
RP ID, freezes all ceremony inputs, serializes exact `clientDataJSON`, compiles
the validated ceremony plus authenticator capabilities into one immutable CTAP
plan, and lets a single hybrid actor dispatch that plan exactly once.

The reusable boundary is:

```text
untrusted assertion options + explicit intent authority
        ↓
ValidatedWebAuthnAssertionCeremony (immutable)
        +
AuthenticatorInfo (validated capabilities)
        ↓
ImmutableCTAPPlan (opaque, typed, non-replayable by public API)
        ↓
single-owner HybridSession
        ↓
validated WebAuthnAssertion
```

## Scope

- WHATWG/UTS #46 IDNA normalization pinned to immutable Swift source bytes.
- A versioned Public Suffix List snapshot including private rules.
- Trustworthy HTTP-localhost and HTTPS origin parsing without caller bypass.
- Registrable-suffix RP ID validation and immutable origin/RP binding.
- Exact `webauthn.get` collected-client-data bytes and SHA-256 hash.
- Bounded public-key credential descriptors and explicit UV policy.
- Capability compilation for allow-list and discoverable assertions.
- Canonical CTAP `authenticatorGetAssertion` and stateful, bounded
  `authenticatorGetNextAssertion`.
- Authenticator-data, credential, user, signature, counter, extension, UP, UV,
  backup-state, and RP-ID-hash validation.
- One-shot hybrid execution and terminal cancellation at every phase.
- A controlled-RP interoperability harness that renders the QR, records only
  secret-free stages, and verifies the returned assertion server-side.

## Non-goals

- `authenticatorMakeCredential`, attestation, pairing, U2F, PIN entry, platform,
  USB, NFC, BLE data transport, conditional mediation, payment credentials,
  AppID, related-origin remote validation, or extension families beyond the
  explicitly retained assertion response map.
- Site-specific request rewriting or relying-party exceptions.
- Treating local fixtures, one phone, or one relying party as parity.

## Hard prohibitions

- No U2F downgrade or CTAP-version retry.
- No wire-profile guessing or parsing under a second profile.
- No silent allow-list probing or batching.
- No UV downgrade after the immutable plan is compiled.
- No replay after a CTAP dispatch has an ambiguous outcome.
- No public initializer or flag that asserts an origin or RP ID is trusted.
- No public raw-CTAP path from the WebAuthn ceremony API.
- No default intent authorizer and no manufactured consent receipt.

## Protocol and public-API impact

- Add immutable WebAuthn origin, request, credential-descriptor, user-intent,
  validated-ceremony, plan-summary, account-selection, and assertion result
  types.
- Keep raw `AuthenticatorTransport` as the lower-layer adapter contract, but do
  not expose the live hybrid channel or encoded CTAP plan through the WebAuthn
  API.
- Add a typed assertion operation to `HybridSession`; retain `getInfo` only as
  a development diagnostic that follows the same single-owner connection
  machinery.
- Version every accepted normalization dataset and wire profile explicitly.

## Implementation sequence

1. Pin and inventory the exact IDNA implementation, public-suffix dataset,
   WebAuthn/CTAP sections, and Chromium source files before derived work lands.
2. Implement bounded origin parsing, RP validation, intent authorization, and
   exact collected-client-data serialization.
3. Implement assertion request/response and authenticator-data codecs with
   negative and differential vectors.
4. Compile each validated ceremony and `AuthenticatorInfo` into one immutable
   plan or a pre-dispatch terminal error.
5. Refactor `HybridSession` so one actor owns discovery, tunnel, Noise, CTAP
   sequencing, shutdown, and cancellation through completion.
6. Add the controlled-RP harness and run the applicable live iPhone and Android
   allow-list/discoverable matrix without retaining credentials or assertions.
7. Reconcile all ledgers, run local/sanitizer/iOS/hosted gates, commit, push,
   and verify the exact pushed SHA.

Steps 1 through 5 are implemented and source-verified. Step 6 has a live HTTPS
controlled RP and registration/assertion harness but no retained physical-phone
receipt yet. Step 7 has local debug, release, sanitizer, formatting, provenance,
and harness evidence; the local iOS SDK remains unavailable and hosted exact-SHA
CI is pending the final commit.

## Security and privacy consequences

- Credential IDs, user handles, client data, signatures, authenticator data,
  QR material, and decrypted CTAP payloads remain absent from logs and crash
  metadata.
- RP ID validation uses canonical ASCII hostnames and a pinned suffix dataset;
  an OS URL parser or caller assertion cannot alter authorization semantics.
- Account selection is consumer-owned and explicit. The package never chooses
  the first credential as a convenience fallback.
- `getNextAssertion` is allowed only as the bounded continuation of a successful
  discoverable request on the same live channel and never as a retry.
- Cancellation, origin/lifecycle invalidation, tunnel loss, malformed response,
  and ambiguous dispatch permanently close the session.

## Acceptance evidence

- W3C collected-client-data and origin/RP cases match exact bytes and outcomes.
- IDNA and public-suffix normative test corpora cover Unicode, Punycode,
  wildcard, exception, private, unknown, public-suffix, IP, and localhost cases.
- CTAP request and response bytes match the pinned specification and Chromium
  differential fixtures.
- Malformed, noncanonical, truncated, oversized, duplicate, conflicting,
  privacy-invalid, RP-hash, UP/UV, backup-flag, counter, and state-sequence
  negatives fail before returning an assertion.
- No-fallback tests prove no profile retry, U2F downgrade, silent probe, UV
  weakening, implicit account choice, or post-dispatch replay.
- Debug, release, AddressSanitizer, ThreadSanitizer, format, JSON/provenance,
  generic iOS, and exact-head hosted CI gates pass.
- A controlled RP verifies allow-list and discoverable assertions from one
  declared iPhone and one declared Android device. Any unavailable device row
  remains literally unpassed.

## Explicit failure conditions

- Origin or RP authorization depends on a caller-provided trust Boolean.
- Accepted Unicode host behavior is not tied to immutable IDNA bytes.
- A public suffix can be claimed as a parent RP ID.
- User intent, UV policy, origin, RP ID, challenge, or credential list can
  change after authorization.
- A CTAP request is resent after any send or receive outcome is ambiguous.
- Multiple discoverable accounts cause an implicit first-item choice.
- Source evidence is described as live-phone or server verification.

## Rollback or discard conditions

- Discard an origin/IDNA/PSL implementation that cannot pass the authoritative
  corpora without permissive repair.
- Discard a session refactor that creates a second channel owner or weakens
  terminal cancellation.
- Discard device-specific request rewriting; record the incompatibility and
  keep the affected row unsupported.

## Exit checklist

- [x] Immutable origin, RP ID, challenge, policy, intent, and credential binding.
- [x] Exact collected-client-data bytes and hash.
- [x] Opaque immutable plan with pre-dispatch capability rejection.
- [x] Strict assertion and bounded next-assertion codecs and sequencing.
- [x] Single-owner hybrid execution with terminal ambiguous outcomes.
- [ ] Full vector, differential, negative, mutation, and cancellation evidence.
- [ ] Controlled-RP iPhone allow-list and discoverable receipts.
- [ ] Controlled-RP Android allow-list and discoverable receipts.
- [ ] All ledgers, provenance, plan, and parity rows reconciled.
- [ ] Local and exact-head hosted gates pass; skipped gates are literal.
