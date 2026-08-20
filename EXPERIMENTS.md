# Experiment and Verification Ledger

This append-only ledger records experiments, implementation attempts,
verification runs, artifacts, results, and keep/discard/defer decisions. Read
`AGENTS.md` before adding entries. Never delete a failed result or reuse an ID.

## EXP-001 — Bootstrap upstream inventory

Date: 2026-08-19

Question:

What exact Chromium hybrid implementation is the initial behavioral reference,
and can it be inventoried without importing Chromium's dependency graph?

Inputs:

- Chromium source repository.
- `device/fido/cable` at Chromium revision
  `535b82484305ec03127bbe951212f6afdec72a43`.

Commands:

```bash
git ls-remote https://chromium.googlesource.com/chromium/src.git HEAD
curl -fsSL 'https://chromium.googlesource.com/chromium/src/+/HEAD/device/fido/cable/?format=JSON'
curl -fsSL 'https://chromium.googlesource.com/chromium/src/+/HEAD/LICENSE?format=TEXT' | base64 --decode
```

Result:

- Chromium `HEAD` resolved to
  `535b82484305ec03127bbe951212f6afdec72a43`.
- The `device/fido/cable` tree resolved to
  `e19c50264422f60b8daa136e0fb2212448427dff` and contains 26 source/test files
  covering BLE UUIDs, tunnel device, Noise, pairing, v2 authenticator,
  discovery, handshake, registration, WebSocket adaptation, tests, and fuzzing.
- Chromium's repository license is BSD 3-Clause.
- No Chromium code was copied into this repository during bootstrap.

Decision: keep.

Pin the exact revision in `References/upstream-lock.json`. Treat Chromium as a
behavioral and selective source reference, not a vendored dependency. Any
future derived code requires file-level provenance and notices.

## EXP-002 — Initial SwiftPM source gate

Date: 2026-08-19

Question:

Does the standalone Swift-only package scaffold build in debug and release,
and do the initial CTAP framing tests pass?

Inputs:

- Initial `Package.swift`.
- `Sources/SiriusSecurityKey/AuthenticatorTransport.swift`.
- `Tests/SiriusSecurityKeyTests/AuthenticatorTransportTests.swift`.

Commands:

```bash
swift --version
sw_vers
uname -m
swift format lint --recursive Sources Tests Package.swift
swift format format --in-place --recursive Sources Tests Package.swift
swift format lint --recursive Sources Tests Package.swift
swift build
swift test
swift build -c release
```

Environment:

- Apple Swift 6.3.3 (`swiftlang-6.3.3.1.3`, `clang-2100.1.1.101`).
- macOS 26.2 build `25C56` on arm64.

Result:

- The initial format lint reported 81 diagnostics. Applying the toolchain
  formatter and rerunning the same lint produced no diagnostics.
- Debug build completed successfully.
- Swift Testing executed three CTAP framing tests with zero failures.
- Release build completed successfully.

Decision: keep.

The scaffold is a valid SwiftPM source baseline. This result does not establish
an authenticator transport, a WebAuthn ceremony, real-device interoperability,
Chromium parity, or release certification.

## EXP-003 — Bootstrap governance audit and public repository creation

Date: 2026-08-19

Question:

Are the package, plan-only markers, reference lock, staged repository contents,
and public repository boundary internally consistent before the first push?

Commands:

```bash
swift format lint --recursive Sources Tests Package.swift
swift build
swift test
swift build -c release
find '.plan/Chromium Passkey Parity Plan' -type f -name '*.md' -print0
jq empty References/upstream-lock.json
git diff --cached --check
gh repo create mikhutchinson/SiriusSecurityKey --public --source . --remote origin --description '100% Swift WebAuthn, CTAP, security-key, and FIDO hybrid transports.'
gh repo view mikhutchinson/SiriusSecurityKey --json name,url,visibility,defaultBranchRef,description
```

Result:

- Format lint produced no diagnostics.
- Debug and release builds completed successfully; all three Swift tests passed.
- Every numbered plan and plan entry point begins with the required `PLAN ONLY`
  marker.
- `jq` accepted `References/upstream-lock.json` as valid JSON.
- The staged diff check produced no diagnostics.
- The public GitHub repository was created at
  `https://github.com/mikhutchinson/SiriusSecurityKey` with the intended
  description. Its default branch remained unset until the first push.
- A separate prohibited consumer-identifier scan returned no matches; its
  literal search terms are intentionally absent from repository content.
- The host `plutil -lint -- References/upstream-lock.json` command rejected the
  valid JSON with `Unexpected character { at line 1`; it is not retained as the
  JSON gate because `jq` parsed the same bytes successfully.

Decision: keep.

Publish the reviewed `main` history. Do not create a version tag or GitHub
release because no authenticator behavior or release claim exists.

## EXP-004 — First hosted CI run

Date: 2026-08-19

Question:

Does the first public `main` revision pass the hosted SwiftPM source gates
without runner or action warnings?

Inputs:

- Public commit `4a7e4d9889e64fae991bac8f37d377a15c60f82e`.
- GitHub Actions run `32312889613` on `macos-15`.

Command:

```bash
gh run watch 32312889613 --repo mikhutchinson/SiriusSecurityKey --exit-status
```

Result:

- Debug build, all three tests, and release build passed.
- The job completed successfully in 29 seconds.
- GitHub warned that Node.js 20 is deprecated and that
  `actions/checkout@v4` was being forced onto Node.js 24.

Decision: keep the source evidence; replace the deprecated checkout action and
rerun hosted CI. A successful workflow with a dependency deprecation warning is
not the clean bootstrap gate.

## EXP-005 — Hosted CI checkout-runtime verification

Date: 2026-08-19

Question:

Does the checkout v5 workflow pass the complete hosted source gate without the
Node.js 20 deprecation annotation?

Inputs:

- Public commit `ddebb95906af451a5f2e2bac6b261c72638bd43e`.
- GitHub Actions run `32312963821` on `macos-15`.

Command:

```bash
gh run watch 32312963821 --repo mikhutchinson/SiriusSecurityKey --exit-status
```

Result:

- `actions/checkout@v5` setup and post-run steps passed.
- Debug build, all three tests, and release build passed.
- The job completed successfully in 45 seconds.
- The prior Node.js 20 deprecation annotation did not recur.

Decision: keep. Hosted bootstrap CI is clean for this revision. This remains a
source gate, not passkey interoperability, parity, or release certification.

## EXP-006 — Pinned first-slice provenance and license inventory

Date: 2026-08-19

Question:

Can the first hybrid slice be based on immutable Chromium/specification bytes
with exact build, feature, source, license, and destination mappings rather than
mutable documentation or remembered behavior?

Commands:

```bash
git clone --filter=blob:none --no-checkout https://chromium.googlesource.com/chromium/src.git /private/tmp/siriussecuritykey-chromium.J91er6
git -C /private/tmp/siriussecuritykey-chromium.J91er6 sparse-checkout init --cone
git -C /private/tmp/siriussecuritykey-chromium.J91er6 sparse-checkout set device/fido
git -C /private/tmp/siriussecuritykey-chromium.J91er6 checkout 535b82484305ec03127bbe951212f6afdec72a43
git -C /private/tmp/siriussecuritykey-chromium.J91er6 rev-parse '535b82484305ec03127bbe951212f6afdec72a43:device/fido'
git -C /private/tmp/siriussecuritykey-chromium.J91er6 rev-parse '535b82484305ec03127bbe951212f6afdec72a43:device/fido/cable'
git -C /private/tmp/siriussecuritykey-chromium.J91er6 ls-tree -r --name-only 535b82484305ec03127bbe951212f6afdec72a43 device/fido | wc -l
curl -fsSLo /private/tmp/siriussecuritykey-chromium.J91er6/ctap.html 'https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html'
curl -fsSLo /private/tmp/siriussecuritykey-chromium.J91er6/pxp.html 'https://fidoalliance.org/specs/hybrid/proximity-exchange-protocol-v1.0-wd-20260717.html'
curl -fsSLo /private/tmp/siriussecuritykey-chromium.J91er6/webauthn.html 'https://www.w3.org/TR/2026/CR-webauthn-3-20260526/'
shasum -a 256 /private/tmp/siriussecuritykey-chromium.J91er6/{ctap,pxp,webauthn}.html
jq empty References/upstream-lock.json References/upstream-inventory.json
```

Inputs:

- Chromium revision `535b82484305ec03127bbe951212f6afdec72a43`.
- CTAP 2.3 Review Draft dated 2025-10-23.
- PXP 1.0 Working Draft dated 2026-07-17.
- WebAuthn Level 3 Candidate Recommendation Snapshot dated 2026-05-26.

Result:

- `device/fido` resolved to tree
  `3a42c514171665162c9f4ef44b5b3c05b32afe17` with 402 files.
- `device/fido/cable` resolved to tree
  `e19c50264422f60b8daa136e0fb2212448427dff` with 26 files.
- CTAP, PXP, and WebAuthn HTML SHA-256 values were respectively
  `f3cccea113a57ae4cc139e26648b1670548e0cdfed1944aed3e93f5faa762fd1`,
  `a809b124b393b643edb4a97658c4c08de390ad9f13db33bd921a908206115114`,
  and `cd9be6587c6560ffe6f2b7175324d0bc4cd33963cf752ad414160affd7f8e163`.
- Chromium's BSD-3-Clause license blob, relevant build conditions, feature
  flags, direct source/test/fuzzer hashes, unported dependency graph, and exact
  source-to-Swift mappings are retained in
  `References/upstream-inventory.json`.
- Source-derived files retain Chromium's header and
  `THIRD_PARTY_NOTICES.md` retains the complete notice. Canonical CBOR and the
  CoreBluetooth boundary are classified as specification implementations.
- `jq` accepted both inventories.

Decision: keep.

The reviewed inventory is complete for the retained first slice only. The full
pinned Chromium passkey surface remains an open plan gate.

## EXP-007 — First hybrid slice and independent vectors

Date: 2026-08-19

Question:

Can a Swift-only, dependency-injected route implement canonical QR bootstrap,
authenticated proximity, tunnel routing, Noise KNpsk0, encrypted framing, and
an explicit CTAP `authenticatorGetInfo` round trip with byte-exact independent
evidence?

Inputs:

- The immutable authorities and source mappings from EXP-006.
- Deterministic private scalars `01`, `02`, and `03` repeated to 32 bytes, a
  16-byte `a5` QR secret, fixed advertisement plaintext, and fixed getInfo
  response fields. These are public test values, not captured session secrets.
- Python 3 with `cryptography` 48.0.0 as an implementation independent of the
  Swift/CryptoKit code under test.

Commands:

```bash
python3 -c 'import cryptography; print(cryptography.__version__)'
shasum -a 256 Tests/SiriusSecurityKeyTests/Vectors/hybrid-vectors.json
swift test --filter generatedQRCodeRoundTrips
swift test --filter proximityMatchesActiveBootstrap
swift test --filter noiseKNpsk0RoundTrip
swift test --filter completeHybridSession
```

Result:

- The independently generated fixture has SHA-256
  `e40d68f2011853236600f8bc191eaedf772a67f918d717b667dea9a449515293`.
- Swift matched the fixture's compressed and uncompressed P-256 points,
  canonical QR CBOR/decimal URI, all three HKDF purpose outputs, authenticated
  EID advertisement, tunnel ID, Noise initiator/response messages, handshake
  hash, directional traffic keys, and first encrypted transport frame.
- The composed injected integration reached a validated post-handshake getInfo,
  then sent an explicit encrypted `[type=CTAP, command=0x04]`, parsed the
  response with status/unknown fields preserved, sent shutdown, and closed.
- Both `.pxp20260717` and `.chromiumCableV2Revision0` passed as separately
  selected profiles. The implementation contains no profile auto-detection or
  retry under a different profile.
- The independent generator was an ephemeral experiment tool and was discarded;
  Python is not a package dependency or distributed protocol component. Its
  exact public inputs and outputs remain in the fixture and Swift tests.

Decision: keep the Swift implementation and immutable vector fixture; discard
the ephemeral Python generator.

This is source/vector/local-integration evidence only. It does not prove a real
phone, public tunnel, relying party, passkey ceremony, or parity.

## EXP-008 — Fail-closed negative and cancellation gates

Date: 2026-08-19

Question:

Does the first slice reject malformed, ambiguous, unsupported, replayed, and
cancelled work without compatibility retry or secret-bearing diagnostics?

Commands:

```bash
swift test --filter canonicalCBOR
swift test --filter qrParser
swift test --filter proximityTimeoutAndCancellation
swift test --filter noiseHandshakeNegativeCases
swift test --filter noiseTransportTamperIsTerminal
swift test --filter noiseTransportNegativeStateCases
swift test --filter hybridSessionDoesNotFallbackProfiles
swift test --filter hybridSessionExplicitCancellation
swift test --filter hybridSessionCancelsTunnelConnection
swift test --filter tunnelOpenWaitIsCancellable
rg -n 'print\(|debugPrint|NSLog|os_log|Logger' Sources Tests
rg -n 'fatalError|try!|as!|Task\.detached|DispatchSemaphore|Process\(' Sources Tests
```

Result:

- Canonical CBOR rejected non-shortest forms, duplicate/out-of-order keys,
  indefinite values, tags, invalid UTF-8, forbidden keys, truncation, trailing
  data, and every explicit resource limit. A deterministic 10,000-input
  mutation campaign required every accepted value to re-encode byte-identically.
- QR tests rejected every truncation of the retained vector, invalid decimal
  widths/values, non-ASCII numerals, over-limit decimal input, lowercase or
  malformed schemes, invalid points, wrong field types, and duplicate/empty
  channel lists.
- Proximity rejected HMAC mismatch, reserved bits, and unknown assigned domains;
  timeout and caller cancellation were terminal.
- Noise rejected wrong PSK, malformed point/message size, handshake state reuse,
  ciphertext tamper/replay/truncation, authenticated bad padding, and exhausted
  counters. Authentication/padding/counter failure permanently closed the
  cipher state.
- The composed session rejected a mismatched explicit wire profile and refused
  to advertise unsupported ceremony hints, linking, an unknown assigned-domain
  count, or BLE data transport.
- The first explicit session-cancellation run passed semantically but took
  63.700 seconds. It exposed an actor-queue race recorded as BUG-007. After the
  structured cancellation-signal fix, discovery, tunnel-open, and delegate-wait
  cancellation tests each completed in 0.001 seconds.
- An earlier focused tamper run terminated with signal 5 because a Foundation
  `Data` slice retained a nonzero index. BUG-006 records the normalization fix
  and zero-based public payload assertions.
- Intermediate compilation also exposed and fixed overlapping CommonCrypto
  output access, test-only `fileprivate` visibility, and direct `NSLock` use in
  an async test helper. The failed attempts were discarded only after the same
  focused gates passed.
- The two source scans returned no matches. No production source logs payloads,
  QR data, keys, advertisements, tunnel identifiers, or decrypted CTAP bytes.

Decision: keep the fail-closed implementation and regression tests. Real-device
and sustained sanitizer/fuzzer campaigns remain unrun.

## EXP-009 — First-slice local source and sanitizer gate

Date: 2026-08-19

Question:

Does the reconciled first-slice tree pass formatting, provenance, debug, test,
release, memory-safety, race, dependency, and platform checks on the development
host?

Commands:

```bash
swift --version
sw_vers
uname -m
swift format lint --recursive Sources Tests Package.swift
jq empty References/upstream-lock.json References/upstream-inventory.json Tests/SiriusSecurityKeyTests/Vectors/hybrid-vectors.json
swift package show-dependencies
swift package dump-package | jq '{name, platforms, products: [.products[].name], dependencies}'
swift build
swift test
swift build -c release
swift test --sanitize=address
swift test --sanitize=thread
xcodebuild -scheme SiriusSecurityKey -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
git diff --check
```

Environment:

- Apple Swift 6.3.3 (`swiftlang-6.3.3.1.3`, `clang-2100.1.1.101`).
- macOS 26.2 build `25C56` on arm64.

Result:

- Format lint, all three JSON parses, debug build, release build, and diff check
  completed with no diagnostics.
- Swift Testing executed 33 tests with zero failures. The suite includes exact
  vectors, 10,000 deterministic CBOR mutations, malformed/truncated/oversized
  parser cases, both explicit wire profiles, a no-fallback profile mismatch,
  EID/tunnel/Noise negatives, and discovery/tunnel/caller cancellation.
- The same 33 tests passed under AddressSanitizer in 0.194 seconds and
  ThreadSanitizer in 0.365 seconds with no reported issue.
- SwiftPM reported no external dependencies. The only source-target files are
  Swift; Python was used only for the discarded independent vector experiment.
- The package manifest resolved macOS 13 and iOS 16 deployment declarations.
- The local generic iOS build was unavailable before compilation: Xcode reported
  that iOS 26.5 is not installed and that local CoreSimulator 1051.54.0 is older
  than required 1051.55.0. This gate is skipped locally, not passed. The hosted
  workflow retains the generic iOS command for an independent runner result.

Decision: keep. The local source and sanitizer gates pass. Await hosted macOS
and iOS source results; real-device, live-tunnel, ceremony, external-consumer,
and release-byte gates remain unrun.

## EXP-010 — Exact-SHA hosted macOS and iOS source gate

Date: 2026-08-19

Question:

Do the committed and pushed first-slice bytes pass the expanded hosted source
workflow, including the iOS compile unavailable on the development host?

Inputs:

- Public commit `4bf6a9d7db426d6e887953f9cfcd83edbd627831`.
- GitHub Actions run `32326554230`, job `96298887496`, on `macos-15`.

Commands:

```bash
git push origin main
gh run watch 32326554230 --repo mikhutchinson/SiriusSecurityKey --exit-status
gh run view 32326554230 --repo mikhutchinson/SiriusSecurityKey --json databaseId,headSha,status,conclusion,createdAt,updatedAt,url,jobs
gh run view 32326554230 --repo mikhutchinson/SiriusSecurityKey --log | rg 'warning:|error:'
gh run view 32326554230 --repo mikhutchinson/SiriusSecurityKey --log | rg 'Test run with [0-9]+ tests|\*\* BUILD SUCCEEDED \*\*'
```

Result:

- Checkout v5, format/provenance, debug build, all 33 tests, release build,
  generic iOS build, and post-checkout steps passed.
- The job completed successfully in 1 minute 7 seconds.
- Hosted tests reported `33 tests passed after 0.200 seconds`.
- Xcode 16.4 compiled every source for `arm64-apple-ios16.0` against the iOS
  18.5 SDK and reported `BUILD SUCCEEDED`.
- The warning/error log scan returned no matches.

Decision: keep. Exact pushed source bytes are green for the declared hosted
macOS source tests and iOS compile. This is not real-device interoperability,
a passkey ceremony, an external tagged consumer, or release certification.

## EXP-011 — Pinned trust and assertion architecture

Date: 2026-08-20

Question:

Can origin/RP trust and assertion planning be made immutable and independent of
OS parser drift, caller trust flags, U2F fallback, and raw hybrid CTAP access?

Inputs:

- WebAuthn Level 3 CR snapshot dated 2026-05-26.
- CTAP 2.3 review draft dated 2025-10-23.
- Chromium revision `535b82484305ec03127bbe951212f6afdec72a43`.
- `swift-url` 0.4.2 revision
  `9306a962396a50d7d88e924afcd7ec67226763db`.
- Chromium public-suffix blob `5eabc92d51226369bf800473de55787951809886`,
  SHA-256 `4155611645690529d1bbea0cfe653b0c45f63b028e0ba039de29a97edc3204ca`.

Commands:

```bash
swift package resolve
swift package show-dependencies --format json
jq empty References/upstream-lock.json References/upstream-inventory.json Package.resolved
swift test --filter WebAuthn
swift test --filter Assertion
```

Result:

- Exact-version WHATWG/UTS #46 parsing and immutable ICANN/private suffix data
  replace OS-dependent normalization. Unicode/Punycode, private suffix,
  wildcard/exception, localhost, IP, and unrelated-RP cases fail or normalize
  as declared.
- Exact assertion client data is 117 bytes for the retained vector and hashes
  to `46f1878ce4e2ddba32f788e73968f3bca685d43bfc7ddffba91be4e2e7da9b5c`.
- A validated ceremony has no public initializer and requires an explicit
  consumer authorizer. Challenge, origin, RP, allow list, UV policy, and client
  data are immutable after authorization.
- `ValidatedWebAuthnAssertionCeremony + AuthenticatorInfo` compiles one opaque
  CTAP2 plan. U2F-only, required-UV unavailable, resident-key unavailable,
  credential-count, credential-size, and message-size mismatches fail before
  assertion dispatch.
- Dependency resolution also records `swift-system` 1.8.1 revision
  `869129b7bf4ecc57b97d0193ad29690ca2134750`; it is transitive and not linked
  by the selected WebURL product.

Decision: keep. This is source and local vector evidence, not physical-device
interoperability or Chromium parity.

## EXP-012 — Strict assertion transport and server verification

Date: 2026-08-20

Question:

Does one actor-owned hybrid transport execute allow-list and discoverable CTAP2
assertions exactly once, validate every returned trust field, and produce an
independently server-verifiable result?

Commands:

```bash
swift test --filter Assertion
swift test --filter Hybrid
swift test --filter server
swift test
rg -n 'fatalError|preconditionFailure|try!|as!|Task\.detached|DispatchSemaphore|Process\(' Sources Tests
rg -n 'print\(|debugPrint|NSLog|os_log|Logger' Sources Tests
```

Result:

- The private hybrid transport owns the channel/cipher and issues one send per
  transaction. Allow-list dispatch is `[0x02]`; a two-result discoverable flow
  is `[0x02, 0x08]`; no explicit getInfo replay is inserted before assertion.
- Pinned-source review caught and corrected the first test peer's revision-zero
  framing error. Revision zero now uses raw encrypted CTAP with no shutdown;
  current PXP uses typed CTAP/update/shutdown. GetInfo and allow-list assertion
  tests pass under both exact profiles, with no profile inference or retry.
- An injected ambiguous send/receive outcome records one `0x02`, closes the
  transport, and leaves the ceremony terminally failed. Profile mismatch, U2F,
  excluded transport hints, missing selector, UV mismatch, duplicate results,
  invalid selection, and selection timeout never trigger fallback.
- Assertion parsing enforces canonical bounded CBOR, RP hash, UP/required UV,
  backup flags, credential membership, user privacy, signature bounds, exact
  next-result count, counter parsing, and canonical extension output.
- The independent RP verifier reconstructs server-owned client data, checks the
  registered ES256 key, RP hash, credential/user handle, UP/UV, signature, and
  monotonic counter. Every byte mutation across client data, authenticator data,
  and DER signature was rejected.
- The complete package suite executed 60 tests with zero failures. The two
  source scans returned no matches.

Decision: keep. Mock phone/channel and generated-key verification are
development evidence only; they are not a real-phone receipt.

## EXP-013 — Controlled RP harness and public ingress

Date: 2026-08-20

Question:

Can a separate Swift-only harness issue real browser registration/assertion
challenges, preserve secret-free operation, and expose the controlled RP over a
valid public HTTPS origin without weakening the package boundary?

Commands:

```bash
swift build --package-path Tools/ControlledRP
swift test --package-path Tools/ControlledRP
Tools/ControlledRP/build-app.sh
swift run --package-path Tools/ControlledRP SiriusSecurityKeyControlledRP serve --origin http://localhost:8765 --port 8765
curl --http1.1 http://localhost:8765/
curl --http1.1 -H 'content-type: application/json' -d '{"deviceLabel":"local-smoke"}' http://localhost:8765/register/options
tailscale up
tailscale funnel status
curl https://mikholae-macbook-m4-pro.tailefb2e3.ts.net/
```

Result:

- Two harness tests pass: strict `fmt=none` registration followed by an ES256
  server-verified assertion/counter update, and altered-client-data rejection.
- Registration requires resident-key and UV, accepts only ES256, validates exact
  create client data, RP hash, UP/UV/AT/backup flags, credential ID, canonical
  COSE key, curve point, and empty attestation statement.
- Assertion state and credentials are memory-only. HTTP requests, headers,
  bodies, pending challenges, registrations, and assertions have explicit
  bounds. Logs contain stage categories and opaque verification receipt IDs.
- Local HTTP returned the registration page and exact required-UV ES256 options.
  The configured Tailscale Funnel exposed the same page at a valid HTTPS origin
  and returned HTTP 200 with `no-store`, CSP, and `nosniff` headers.
- The first harness build failed because `@main` was placed in `main.swift` and
  a listener callback captured mutable state under Swift 6 concurrency. Both
  attempts were discarded: the entry file was renamed and readiness now uses a
  lock-protected one-shot gate.
- The first server lifetime emitted a checked-continuation misuse warning; the
  leaked continuation was replaced with a cancellable monotonic-clock loop and
  the clean launch/public smoke was repeated.
- Artifact inspection then found the first manual `.app` assembly omitted the
  SwiftPM suffix resource bundle. The build script now copies it into
  `Contents/Resources`; the rebuilt artifact's suffix bytes hash to the locked
  `4155611645690529d1bbea0cfe653b0c45f63b028e0ba039de29a97edc3204ca`.
- No iPhone or Android registration/assertion receipt is recorded by this
  experiment. The HTTPS page being reachable is not device interoperability.

Decision: keep the separate harness and public-ingress contract. Physical
allow-list/discoverable matrix rows remain unpassed pending explicit user/device
interaction.

## EXP-014 — Trust-bound assertion local source and sanitizer gate

Date: 2026-08-20

Question:

Does the reconciled assertion tree pass its complete local source, negative,
mutation, server, harness, release, memory-safety, race, dependency, and
format/provenance gates?

Commands:

```bash
swift --version
sw_vers
uname -m
swift format lint --recursive Sources Tests Package.swift Tools/ControlledRP/Package.swift Tools/ControlledRP/Sources Tools/ControlledRP/Tests
jq empty References/upstream-lock.json References/upstream-inventory.json Tests/SiriusSecurityKeyTests/Vectors/hybrid-vectors.json Package.resolved Tools/ControlledRP/Package.resolved
swift build
swift test
swift build -c release
swift test --sanitize=address
swift test --sanitize=thread
swift build --package-path Tools/ControlledRP -c release
swift test --package-path Tools/ControlledRP
xcodebuild -scheme SiriusSecurityKey -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
git diff --check
```

Environment:

- Apple Swift 6.3.3 (`swiftlang-6.3.3.1.3`, `clang-2100.1.1.101`).
- macOS 26.2 build `25C56` on arm64.

Result:

- Format, provenance/package JSON, debug build, 60 package tests, release build,
  two controlled-RP tests, controlled-RP release build, and diff check pass.
- The same 60 package tests pass under AddressSanitizer and ThreadSanitizer with
  no reported issue.
- The local generic iOS build remains unavailable before compilation: iOS 26.5
  is not installed and CoreSimulator 1051.54.0 is older than Xcode's required
  1051.55.0. This gate is skipped locally, not passed; hosted CI retains it.
- The final exact-head hosted workflow, external clean consumer, physical phone
  matrix, and release-byte certification are not part of this local result.

Decision: keep the local implementation. Await physical device receipts and the
exact pushed-SHA hosted workflow; do not broaden any parity or release claim.

## EXP-015 — Exact pushed-SHA hosted assertion gate

Date: 2026-08-20

Question:

Does the pushed trust-bound assertion implementation pass the complete hosted
source, sanitizer, harness, and generic-iOS workflow at the exact source SHA?

Immutable revision:

- Repository: `https://github.com/mikhutchinson/SiriusSecurityKey`
- Revision: `a0d0f068c7d185458c2f4802b786acdc7f8fef5c`
- Workflow run: `32372627889`
- Job: `96436477198`

Commands:

```bash
git push origin main
gh run watch 32372627889 --exit-status
gh run view 32372627889 --json databaseId,headSha,status,conclusion,url,jobs
gh run view 32372627889 --log | rg -n 'Test run with|warning:|error:'
git diff --check
```

Result:

- The hosted workflow completed successfully against exact revision
  `a0d0f068c7d185458c2f4802b786acdc7f8fef5c` in 3 minutes 25 seconds.
- Checkout, format/provenance, debug build, tests, sanitizers, release build,
  controlled-RP harness, and generic iOS build all passed.
- The package ran 60 tests normally, 60 under AddressSanitizer, and 60 under
  ThreadSanitizer, all with zero failures. The controlled-RP harness ran two
  tests with zero failures.
- The warning/error scan returned no warning or error lines.
- The evidence-only ledger reconciliation passed `git diff --check`.
- This run verifies pushed source and the generic iOS build. It does not supply
  a physical iPhone or Android assertion receipt and does not certify release
  bytes or Chromium parity.

Decision: keep. The pushed source gate is passed; the four physical-device
allow-list/discoverable rows remain unpassed until server-verified receipts are
observed.
