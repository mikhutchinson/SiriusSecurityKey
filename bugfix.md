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
