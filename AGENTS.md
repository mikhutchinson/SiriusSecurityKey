# AGENTS.md

Read this file completely before changing this repository. Then read
`EXPERIMENTS.md`, `bugfix.md`, and `changelog.md` completely. For multi-part
work, read the active plan under `.plan/` completely as well.

## Repository purpose

SiriusSecurityKey is a standalone, general-purpose SwiftPM implementation of
the browser-side WebAuthn, CTAP, passkey, security-key, and FIDO hybrid stack.
Its product goal is observable feature parity with Chromium's passkey behavior,
including cross-device QR and Bluetooth proximity authentication.

The package exists for any application that needs browser-grade passkey support
without waiting for a platform vendor to expose a privileged integration. It
must never acquire consumer-specific UI, model objects, storage schemas,
session names, provider logic, or policy exceptions.

The distributed package is **100% Swift**:

- no Python or embedded Python runtime;
- no command-line subprocess as a protocol implementation;
- no browser-engine dependency;
- no required localhost daemon or HTTP service;
- no undocumented platform API;
- no entitlement that is available only through private approval;
- no site-specific or relying-party-specific compatibility hacks.

Public platform frameworks are allowed when they expose generally available
capabilities such as Bluetooth, cryptography, secure storage, networking, NFC,
or system UI. Platform adapters must remain explicit, testable boundaries; the
protocol core must not become a wrapper around one vendor's credential API.

## Current truth

This repository is a pre-implementation scaffold. It contains a byte-preserving
CTAP request/response transport seam and source tests. It does **not** yet
implement or claim:

- WebAuthn ceremony validation;
- canonical CBOR;
- QR bootstrap encoding;
- Bluetooth discovery or proximity proof;
- WebSocket tunnel operation;
- Noise handshake or encrypted framing;
- CTAP authenticator commands beyond raw framing;
- USB, NFC, Bluetooth, hybrid, or platform authenticator operation;
- passkey creation or assertion;
- conditional mediation or autofill;
- Chromium parity;
- a release artifact.

Never describe planned behavior as shipped behavior. Never turn a source test,
mock, simulator, local handshake, or one-device demonstration into a broader
interoperability or parity claim.

## Upstream authorities and provenance

The normative protocol authorities are the published W3C WebAuthn and FIDO
Alliance CTAP/PXP specifications. Chromium's open-source `device/fido` stack is
the primary behavioral and interoperability reference.

`References/upstream-lock.json` records the exact upstream revision and
specification snapshots used for a body of work. Mutable `HEAD`, a search
result, an article, or remembered behavior is not acceptable evidence for an
implementation or parity decision.

Before copying, translating, or structurally porting upstream code:

1. Record the exact repository, revision, source paths, and file hashes.
2. Read the governing license and per-file notices.
3. Decide and record whether the work is a clean specification implementation,
   a behavioral reimplementation, or derived/translated source.
4. Preserve every required copyright and license notice in the derived file
   and repository notices.
5. Record the source-to-destination mapping in `EXPERIMENTS.md`.
6. Add differential vectors or tests that prove semantics instead of relying on
   visual similarity to upstream code.

Do not copy Chromium's dependency graph wholesale. Port the minimum protocol
state machines and algorithms needed for the public contract. Chromium-specific
task runners, browser UI, metrics, network wrappers, Bluetooth abstractions,
and process globals do not belong here.

## Load-bearing invariants

Every plan and implementation change preserves these invariants:

- **INV-SK1 — General-purpose boundary.** Public types contain only WebAuthn,
  CTAP, FIDO, authenticator, transport, ceremony, and security concepts.
- **INV-SK2 — Swift-only distribution.** Every released product builds through
  SwiftPM without Python, a sidecar process, a browser engine, or a service.
- **INV-SK3 — Public-API independence.** Core functionality does not require
  private frameworks, undocumented selectors, privileged code injection, or
  selectively granted entitlements.
- **INV-SK4 — Origin and RP binding.** A ceremony is bound to a normalized,
  trustworthy origin and validated RP ID. Callers cannot silently substitute
  either after user intent or authenticator selection.
- **INV-SK5 — User intent is explicit.** Presence, verification, consent, and
  conditional mediation remain distinct. A library convenience API may not
  manufacture a gesture or consent receipt.
- **INV-SK6 — Secrets never become diagnostics.** QR secrets, ECDH material,
  tunnel identifiers, credential IDs, PIN/UV tokens, private keys, assertions,
  and decrypted CTAP payloads are excluded from logs and crash metadata.
- **INV-SK7 — Cryptography is spec-exact.** Curve points, transcript hashes,
  HKDF labels, nonces, counters, AEAD associated data, and key rotation are
  checked against authoritative vectors. No permissive fallback weakens a
  failed handshake.
- **INV-SK8 — Canonical bytes are preserved.** CBOR and wire encoders enforce
  required canonical forms, bounds, and duplicate-key rejection. Byte identity
  is tested at protocol boundaries.
- **INV-SK9 — Proximity is not identity.** Bluetooth proves the required nearby
  channel property; it does not authenticate the phone or replace the encrypted
  handshake.
- **INV-SK10 — Cancellation is terminal.** Navigation, origin change, caller
  cancellation, timeout, Bluetooth loss, tunnel failure, or authenticator
  cancellation ends that ceremony. Mutating commands are never replayed after
  an ambiguous failure.
- **INV-SK11 — State is bounded.** Frames, CBOR values, QR payloads, tunnel
  messages, queues, retries, timers, pairing records, and discovery lifetimes
  have explicit limits.
- **INV-SK12 — Pairing is optional and revocable.** One-shot QR operation ships
  before persistent pairing. Pairing secrets require protected storage,
  rotation, user-visible removal, and protocol-version binding.
- **INV-SK13 — Platform storage is an adapter.** Credential storage and user
  verification are capability-driven interfaces. No single platform provider
  defines the core data model or silently narrows the protocol.
- **INV-SK14 — Parity is matrixed evidence.** Chromium parity is claimed per
  exact upstream revision, OS/toolchain, operation, extension, authenticator,
  and device/browser combination. Unknown and skipped rows remain unsupported.
- **INV-SK15 — Release bytes are separately proven.** Source tests do not
  certify a tagged SwiftPM release. Release claims require exact tag, hosted
  revision, clean consumer resolution, checksums, license inventory, and the
  declared interoperability matrix.

## Architecture boundary

Keep the implementation layered even if it begins in one Swift target:

```text
WebAuthn client and policy
        ↓
CTAP client, CBOR, extensions, PIN/UV
        ↓
AuthenticatorTransport
   ├─ platform adapter
   ├─ USB / NFC / Bluetooth adapters
   └─ hybrid transport
        ├─ QR bootstrap
        ├─ Bluetooth proximity
        ├─ tunnel discovery and WebSocket
        └─ Noise handshake and encrypted framing
```

Protocol types must not import UI frameworks. UI helpers, if ever shipped, are
separate products layered over the protocol API. CoreBluetooth callbacks,
URLSession delegates, and secure-storage APIs are isolated behind actor-safe
adapters. Consumers own presentation and application lifecycle, while this
package owns protocol correctness and cancellable session state.

Use Swift structured concurrency. Public state crossing tasks is `Sendable`.
Shared mutable protocol state belongs in an actor. Avoid detached tasks,
unstructured callbacks, global mutable state, and thread-blocking waits.

## Mandatory ledger discipline

The repository records are synchronized sources of truth:

- `AGENTS.md` defines boundaries, invariants, workflow, and evidence rules.
- `EXPERIMENTS.md` is the append-only experiment and verification ledger.
- `bugfix.md` is the append-only defect, risk, mitigation, and verification
  ledger.
- `changelog.md` is the durable behavior, structure, documentation, and release
  history.
- `PARITY.md` is the versioned Chromium feature matrix and evidence index.
- `.plan/<Name> Plan/` contains plan-only multi-part implementation contracts.

Maintaining these records is part of implementation. It is not optional
bookkeeping and it is not deferred cleanup.

Every agent and contributor must:

1. Read all root ledgers before relying on repository state.
2. Inspect the latest IDs before adding an `EXP-*` or `BUG-*` entry. Never
   reuse, renumber, or silently rewrite an existing entry.
3. Add an `EXPERIMENTS.md` entry for every implementation attempt, protocol
   experiment, differential comparison, benchmark, interoperability run,
   fuzzing campaign, meaningful test run, upstream refresh, and material
   technical decision.
4. Record exact commands, toolchain/host, inputs and immutable revisions,
   relevant environment, produced artifacts or hashes, literal results,
   skipped gates, and a keep/discard/defer decision.
5. Record failures and discarded approaches with the same fidelity as retained
   approaches. Failed work is evidence and must not disappear from history.
6. Add or update `bugfix.md` when a defect or risk is discovered, reproduced,
   fixed, mitigated, reopened, deferred, or materially reclassified. Preserve
   the original symptom and add dated follow-ups; do not erase it.
7. Update `changelog.md` in the same change whenever behavior, public API,
   repository structure, platform support, documentation contract, dependency,
   security posture, or release state changes.
8. Update the active `.plan/` part when evidence changes its assumptions,
   ordering, gates, or disposition. Plans never override observed evidence.
9. Update `PARITY.md` in the same change whenever a matrix row, evidence link,
   upstream baseline, or comparison disposition changes.
10. Reconcile all ledgers before declaring completion. If the code and ledgers
   disagree, the task is incomplete.
11. Never claim a gate passed when it was skipped, unavailable, mocked, or run
    against different bytes than the claimed artifact.

A docs-only change still updates `changelog.md` and records its verification.
A refactor with unchanged behavior still records the build/test evidence. A
failed experiment still gets an experiment entry. A fixed bug gets both the
bug follow-up and reproducible verification. A release gets a changelog entry,
exact artifact evidence, and a clean external-consumer receipt.

## Planning rules

This repository does not use a root `plan.md`. Multi-part work lives under
`.plan/<Name> Plan/`.

Every plan file begins with `> **Status: PLAN ONLY.**` and contains:

- current source-backed truth with exact file and line references;
- scope and non-goals;
- affected invariants by ID;
- protocol/version and public-API impact;
- implementation sequence and dependencies;
- security and privacy consequences;
- acceptance evidence and explicit failure conditions;
- rollback or discard conditions;
- an exit checklist.

The plan entry point defines thesis, read order, dependency graph, build order,
hard invariants, and the overall exit gate. A plan is not evidence that its
behavior exists.

## Coding rules

- Swift 6 language mode and strict concurrency are the baseline.
- Prefer value types, immutable data, explicit state machines, and actors.
- Public API is documented and `Sendable` where semantically possible.
- Parse untrusted bytes with explicit size/depth/count limits before allocation.
- Reject unknown critical fields, invalid curve points, duplicate CBOR keys,
  invalid UTF-8, counter rollback, and transcript mismatch.
- Use constant-time primitives supplied by reviewed cryptographic libraries;
  do not implement novel cryptography.
- Randomness comes from the operating system CSPRNG and is injectable in tests.
- Wall-clock, monotonic time, networking, Bluetooth, storage, and randomness
  are dependency-injected at protocol boundaries.
- Structured logs contain public state names and bounded error categories only.
- Do not log wire payloads merely because a debug build is active.
- No force unwraps, unchecked integer arithmetic, unbounded recursion, or
  unbounded retry loops on attacker-controlled input.
- Search before adding a helper. One canonical encoder, transcript, state
  machine, and error taxonomy is better than parallel implementations.

## Testing and evidence gates

Routine source gate:

```bash
swift build
swift test
swift build -c release
git diff --check
```

Run focused tests during development, then the complete applicable source gate.
Protocol work additionally requires authoritative vectors. Parser/framing work
requires malformed, truncated, oversized, duplicate, and fuzz-generated inputs.
Concurrency work requires cancellation and race tests. Cryptographic work
requires transcript and negative vectors. Upstream-derived work requires
license/provenance verification and differential tests.

Chromium parity additionally requires the declared external matrix. At minimum,
record:

- exact Chromium revision used as the comparison authority;
- package revision and release-candidate bytes;
- macOS version and hardware architecture;
- phone OS/device and credential provider;
- relying party and exact ceremony/options;
- QR, Bluetooth, tunnel, handshake, CTAP, UV, and terminal outcomes;
- cancellation/error behavior;
- unsupported, skipped, and unavailable rows.

Tests against local mocks do not certify a real phone. A real phone against a
test relying party does not certify arbitrary sites. One assertion does not
certify credential creation, conditional mediation, extensions, roaming keys,
or platform credentials. Development evidence does not certify release bytes.

## Definition of done

A change is complete only when:

- the implementation respects every affected invariant;
- relevant source, negative, vector, differential, and interoperability gates
  have literal recorded results;
- `EXPERIMENTS.md`, `bugfix.md`, `changelog.md`, `PARITY.md`, and the active
  plan agree with the repository state;
- dependency and upstream locks are exact;
- licenses and notices are complete;
- `swift test`, the applicable release build, and `git diff --check` pass;
- skipped and unavailable gates are stated as such;
- no broader parity or release claim is made than the evidence supports.
