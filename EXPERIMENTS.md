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
