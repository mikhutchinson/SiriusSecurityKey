# Bugfix and Risk Ledger

This append-only ledger records defects, risks, root causes, fixes,
verification, and intentional deferrals. Preserve original findings and add
dated follow-ups when their status changes.

## BUG-001 — Scaffold can be mistaken for passkey support

Date: 2026-08-19

Status: open; guarded by documentation

Symptom:

A compiling package and byte-framing tests could be described as a passkey,
WebAuthn, hybrid, or Chromium-parity implementation even though none of those
flows exists yet.

Root cause:

Repository creation, protocol implementation, real-device interoperability,
parity, and release certification are separate milestones.

Current mitigation:

- `README.md` and `AGENTS.md` state the exact pre-implementation boundary.
- The parity plan requires evidence per feature-matrix row.
- `EXPERIMENTS.md` separates source gates from interoperability and release
  evidence.

Closure gate:

Close only when every claimed feature has its declared vectors and
interoperability receipts. Do not close merely because the first hybrid
handshake succeeds.

## BUG-002 — Deployed hybrid protocol and draft evolution can diverge

Date: 2026-08-19

Status: open

Symptom:

An implementation of the newest written PXP draft may fail against deployed
phones or browsers using caBLE v2/CTAP hybrid behavior, while a Chromium-derived
implementation may lag newer normative requirements.

Root cause:

The deployed ecosystem and the evolving specification are independently
versioned.

Current mitigation:

- Pin both specifications and the comparison Chromium revision.
- Version handshake, framing, and feature capabilities explicitly.
- Make the first gate a real-phone `authenticatorGetInfo` exchange before
  generalizing the protocol layer.

Closure gate:

Maintain explicit compatibility rows for deployed and current protocol
versions; never collapse them into one unversioned “hybrid supported” claim.

## BUG-003 — Tunnel interoperability is not yet proven independent

Date: 2026-08-19

Status: open

Symptom:

The QR payload and Bluetooth proximity exchange may succeed while both peers
still fail to meet on a compatible tunnel service or complete the encrypted
handshake.

Root cause:

Tunnel-domain assignment, routing, WebSocket behavior, and deployed peer
expectations have not yet been demonstrated by this package.

Current mitigation:

Treat QR display, BLE observation, tunnel connection, Noise completion, and
CTAP response as separate receipts. Do not claim cross-device authentication
from a QR or Bluetooth-only demonstration.

Closure gate:

Complete the first-slice real-device matrix with exact tunnel and handshake
results, without logging secrets.

## BUG-004 — Upstream provenance can be lost during a Swift port

Date: 2026-08-19

Status: open; process guard established

Symptom:

Selective translation of Chromium behavior can lose file-level copyright,
license, revision, or semantic provenance.

Root cause:

Algorithm ports often begin as experimental code before repository notices and
differential vectors are assembled.

Current mitigation:

`AGENTS.md` requires provenance before derived code lands, and
`References/upstream-lock.json` pins the initial reference revision. No Chromium
code has been copied during bootstrap.

Closure gate:

Every derived file maps to exact upstream paths and hashes, retains required
notices, and has differential evidence. Keep this guard active for future
upstream refreshes.

## BUG-005 — Initial CI checkout action used a deprecated Node runtime

Date: 2026-08-19

Status: fixed and hosted-verified

Symptom:

The first hosted CI run passed but warned that Node.js 20 is deprecated and
that `actions/checkout@v4` was being forced to run on Node.js 24.

Root cause:

The initial workflow used the older checkout action copied by the bootstrap
template.

Fix:

Update `.github/workflows/ci.yml` to `actions/checkout@v5`, whose runtime is
Node.js 24.

Verification:

GitHub Actions run `32312963821` on commit
`ddebb95906af451a5f2e2bac6b261c72638bd43e` completed the debug build, all three
tests, and release build successfully with `actions/checkout@v5`. The prior
Node.js 20 deprecation annotation did not recur.

## BUG-006 — Data slices retained nonzero indices across protocol boundaries

Date: 2026-08-19

Status: fixed and source-verified

Symptom:

A focused Noise tamper test terminated with signal 5 when it indexed a
`Data` value at integer zero. Foundation `Data` slices can preserve the source
collection's nonzero `startIndex`, even when the static type is `Data`.

Root cause:

Crypto and framing code returned or retained `prefix`, `suffix`, and
`dropFirst` values without consistently copying them into zero-based storage.
Byte equality hid the index contract until mutation used integer subscripting.

Fix:

- Normalize cryptographic plaintext/AES output and bounded decoder input before
  indexed access.
- Normalize public CTAP payload and Bluetooth service-data inputs.
- Use `startIndex` or sequence operations when a slice does not require random
  access.

Verification:

The focused tamper test now reports the expected terminal authentication
failure. CTAP framing tests explicitly assert zero-based payload indices, and
the complete suite exercises EID, QR, Noise, and CTAP slice paths.

## BUG-007 — Explicit session cancellation waited for the proximity timeout

Date: 2026-08-19

Status: fixed and source-verified

Symptom:

`HybridSession.cancel()` eventually returned the correct terminal error, but a
focused test took 63.700 seconds because cancellation queued behind the
discovery actor's task-group scope and waited for its 60-second sleeper.

Root cause:

The session treated a call into another actor as its cancellation primitive.
That actor call could not preempt the already-running discovery scope, so
closing the scan was advisory rather than structurally cancelling the owning
operation.

Fix:

- Race the operation and a session cancellation signal inside a structured
  throwing task group.
- On cancellation, finish the signal and directly stop the active scanner and
  channel.
- Wrap URLSession WebSocket opening in a cancellation handler that resolves its
  pending continuation and invalidates the task/session.

Verification:

The same explicit-cancellation test now completes in 0.001 seconds. Additional
tests cancel during tunnel connection and before a WebSocket delegate callback;
both complete in 0.001 seconds with terminal cancellation.

## BUG-008 — QR configuration could advertise capabilities the session lacked

Date: 2026-08-19

Status: fixed and source-verified

Symptom:

Callers could configure a one-shot session to advertise a ceremony other than
getAssertion, persistent linking, an unknown assigned tunnel-domain count, or
BLE as a data-transfer channel even though this slice implements none of those
paths.

Root cause:

The QR encoder correctly represented the broader PXP schema, but the composed
session did not constrain that schema to its retained implementation surface.

Fix:

`HybridSession` now accepts only the getAssertion UI hint, the two pinned
assigned domains, linking false or absent, and WebSocket-only/implicit-WebSocket
transfer. Unsupported capabilities fail before QR generation; the session never
silently switches channels or wire profiles.

Verification:

Focused tests cover all three rejected configurations, and the explicit profile
mismatch integration test fails terminally without compatibility retry.

### BUG-001 follow-up — first slice remains development-only

Date: 2026-08-19

Status: open; documentation guard advanced

`README.md`, `AGENTS.md`, `PARITY.md`, and the active plan now distinguish the
retained local first slice from real-phone interoperability, passkey ceremony,
parity, production support, and release evidence. Nine matrix rows moved only
to `development`; none moved to `supported`.

### BUG-002 follow-up — wire evolution is explicit and non-retrying

Date: 2026-08-19

Status: open; development mitigation retained

The session now selects either PXP 2026-07-17 post-handshake framing or pinned
Chromium caBLE revision-zero framing before I/O. Profile mismatch is terminal;
the parser never retries under the other profile. Real deployed-phone rows are
still required before either profile can be supported.

### BUG-003 follow-up — local tunnel state exists, interoperability does not

Date: 2026-08-19

Status: open

Assigned/hashed domain derivation, URL construction, binary/subprotocol checks,
message bounds, redirects, and cancellation now have local source evidence. No
public tunnel or real peer was contacted, so the closure gate is unchanged.

### BUG-004 follow-up — first derived ports have exact provenance

Date: 2026-08-19

Status: open; first-slice mapping verified

`References/upstream-inventory.json` maps every retained source-derived Swift
file to exact Chromium source paths, blob/SHA-256 hashes, revision, build
conditions, and license. Per-file headers and `THIRD_PARTY_NOTICES.md` retain
the BSD notice. The process guard remains open for future ports and refreshes.

## BUG-009 — Decimal QR decoding allocated before enforcing the CBOR bound

Date: 2026-08-19

Status: fixed and source-verified

Symptom:

`FIDO:/` parsing bounded the decoded CBOR to 1024 bytes only after converting an
arbitrarily long decimal suffix into a growing `Data` buffer. It also used
Unicode's broad `isNumber` classification instead of the protocol's ASCII
decimal alphabet.

Root cause:

The resource limit lived at the CBOR layer rather than the preceding decimal
transport encoding boundary.

Fix:

The parser now rejects non-ASCII digits and more than 2,487 digits before
copying or decoding the suffix. That is the largest decimal representation that
can encode the existing 1024-byte QR CBOR limit.

Verification:

Focused QR negatives reject Arabic-Indic digits and an input one byte over the
decimal bound, while the canonical fixture and every-truncation campaign still
pass.

## BUG-010 — Empty canonical maps formed an invalid Swift range

Date: 2026-08-19

Status: fixed and source-verified

Symptom:

Encoding a valid empty CBOR map reached duplicate-key validation with the range
`1..<0`, which traps before producing the canonical byte `a0`.

Root cause:

The duplicate scan assumed at least two sorted map entries.

Fix:

Run the adjacent-key scan only when the map contains more than one entry.

Verification:

A regression test now encodes and decodes the empty map exactly as `a0`; the
duplicate-key and map-order negatives remain green.

## BUG-011 — Platform URL and suffix behavior could drift across hosts

Date: 2026-08-20

Status: fixed and source-verified

Symptom:

Origin and RP authorization would be security-sensitive if implemented with a
Foundation URL parser, an OS-dependent IDNA transform, an incomplete suffix
list, or a caller-provided trust override.

Root cause:

The scaffold had no immutable normalization authority and no RP authorization
layer. Platform behavior could therefore have become part of the protocol
without an exact dependency or dataset lock.

Fix:

- Pin `swift-url` 0.4.2 and its exact revision for WHATWG URL parsing and UTS
  #46 non-transitional normalization.
- Bundle Chromium revision `535b8248`'s exact ICANN/private public-suffix bytes
  and validate exact, wildcard, exception, and registrable-domain rules.
- Make validated RP IDs constructible only through origin-bound validation; no
  public trust flag or unchecked initializer exists.

Verification:

Unicode/Punycode, HTTPS, localhost, credential/path/query/fragment, IP,
unrelated suffix, private `appspot.com`/`up.railway.app`, and Kawasaki exception
tests pass. The resource and dependency revisions/hashes are locked in both
provenance files.

## BUG-012 — Hybrid execution was shaped around a hard-coded getInfo endpoint

Date: 2026-08-20

Status: fixed and source-verified

Symptom:

`HybridSession` directly emitted `[type=CTAP, command=0x04]`. Extending that
shape for assertions risked a second channel owner, raw command access around
ceremony policy, request replay, or divergent status-message handling.

Root cause:

The first slice stopped at a diagnostic command and had no private reusable
authenticator transport or typed ceremony operation.

Fix:

- Give one private `HybridAuthenticatorTransport` actor exclusive ownership of
  the Noise cipher and binary channel.
- Route diagnostic getInfo and typed assertion transactions through the same
  one-send transport; any encrypt/send/receive ambiguity closes it permanently.
- Keep encoded plans and the live hybrid CTAP transport internal. The public
  assertion path accepts only an immutable, intent-authorized ceremony.

Verification:

Both explicit profiles still pass getInfo. Allow-list and discoverable
assertions pass through the same owner, while an injected post-dispatch failure
records exactly one `0x02` command and leaves the session terminally failed.

## BUG-013 — Controlled RP lifetime used an intentionally leaked continuation

Date: 2026-08-20

Status: fixed and harness-verified

Symptom:

The first local controlled-RP launch printed Swift's continuation-misuse
diagnostic because the server kept itself alive with a checked continuation
that was deliberately never resumed.

Root cause:

A checked continuation was used as an infinite process-lifetime primitive
rather than only for an operation with one eventual completion.

Fix:

Retain the listener normally and keep the async command alive with a cancellable
continuous-clock loop. Listener readiness still uses a lock-protected,
single-resume continuation gate.

Verification:

The rebuilt server launched without runtime diagnostics, served the
registration page and required-UV ES256 options through local HTTP and the
configured public HTTPS funnel, and shut down on explicit process cancellation.

### BUG-001 follow-up — assertion source exists; physical evidence does not

Date: 2026-08-20

Status: open; documentation guard advanced

Trust-bound assertion, server verification, and controlled-RP source now pass
local tests, mutation, and sanitizers. No iPhone or Android assertion receipt
has yet been retained, so every affected parity row remains `development` and
the physical matrix remains unpassed.

### BUG-002 follow-up — explicit profiles still require deployed-peer proof

Date: 2026-08-20

Status: open; no-fallback mitigation retained

The live harness requires either `pxp-20260717` or
`chromium-cable-v2-r0`; it has no default and never retries the other profile.
Neither profile is classified as deployed-phone compatible until its exact
physical-device row passes.

## BUG-014 — Live app bundle initially omitted the pinned suffix resource

Date: 2026-08-20

Status: fixed and artifact-verified

Symptom:

The first controlled-RP `.app` assembly copied the release executable and
Bluetooth usage description but not SwiftPM's generated resource bundle. Exact
host RP IDs happened not to load the suffix database, masking the incomplete
artifact during the first public-ingress smoke.

Root cause:

SwiftPM places target resources next to the command-line executable; manually
assembling an app bundle requires copying that generated bundle into
`Contents/Resources`.

Fix:

`Tools/ControlledRP/build-app.sh` now copies the exact
`SiriusSecurityKey_SiriusSecurityKey.bundle` with `ditto` on every release app
assembly.

Verification:

The rebuilt app contains `effective_tld_names.dat` under `Contents/Resources`.
Its SHA-256 is the locked
`4155611645690529d1bbea0cfe653b0c45f63b028e0ba039de29a97edc3204ca`.

## BUG-015 — Revision-zero tests incorrectly retained revision-one message types

Date: 2026-08-20

Status: fixed and source-verified

Symptom:

The first-slice scripted peer applied revision-zero post-handshake padding but
still expected a message-type byte and shutdown frame. Pinned Chromium source
shows revision zero has neither; only revision one and current PXP framing use
typed CTAP/update/shutdown messages.

Root cause:

The original profile seam covered post-handshake decoding but did not carry the
selected revision into established transport framing. Shared tests therefore
proved the wrong historical wire behavior.

Fix:

- Pass the immutable wire profile into the private hybrid transport owner.
- For Chromium revision zero, send and receive raw encrypted CTAP frames and
  close the WebSocket without a shutdown message.
- For current PXP/revision-one framing, retain typed messages, bounded updates,
  and explicit shutdown.
- Make allow-list assertion and getInfo integration tests run under both exact
  profiles with distinct framing expectations.

Verification:

The focused hybrid suite passes 29 tests/cases. Both profiles complete getInfo
and an assertion; revision zero records no shutdown frame, current PXP does,
and the profile-mismatch test still fails without retry.

## BUG-016 — Controlled-RP app assembly overwrote a mapped executable

Date: 2026-08-20

Status: fixed and artifact-concurrency verified

Symptom:

After the controlled-RP app was rebuilt while an earlier server process still
mapped the same bundle executable path, a subsequent assertion-client process
remained at `_dyld_start`, used 96 KiB, opened no network socket, created no QR
directory, and did not enter package code. `SIGTERM` and `SIGKILL` remained
pending while the process was in uninterruptible executable loading.

Root cause:

`Tools/ControlledRP/build-app.sh` copied the release executable directly onto
the existing app executable. `cp` truncated and rewrote the destination vnode
instead of publishing a new complete bundle, violating the running-process
boundary.

Fix:

Assemble the complete app in a task-owned staging directory, move the previous
bundle aside, and rename the complete staged directory into place. A guarded
trap removes only the exact staging/backup paths and restores the prior app if
publication fails before the new bundle exists.

Verification:

The script passes `sh -n`. The rebuilt artifact retains the locked suffix-list
hash, leaves no staging/backup path, and simultaneously runs a local server and
a second assertion client from the same app. The second client reaches the
server and returns the expected empty-store error rather than hanging. A second
test kept the old app server mapped while rebuilding: the old server continued
returning HTTP 200 and a client from the newly published app reached it without
a loader hang. The original kill-pending process remains in macOS
uninterruptible `_dyld_start` with no socket or ceremony I/O; no broader runtime
claim is derived from it.
