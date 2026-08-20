> **Status: PLAN ONLY.**

# 03 — Test, interoperability, security, and release plan

Affected invariants: all, especially `INV-SK6` through `INV-SK15`.

Current source anchors: `AGENTS.md:259-307` defines the source-versus-parity
evidence boundary and completion contract; `EXPERIMENTS.md:201-430` records the
first-slice provenance, source, negative, cancellation, and local gate evidence;
and `PARITY.md:31-54` keeps development below supported and the real-device and
release rows unimplemented.

## Test layers

1. **Pure unit tests:** canonical bytes, bounds, state transitions, errors, and
   cancellation with deterministic dependencies.
2. **Normative vectors:** W3C/FIDO examples and retained project vectors with
   exact specification/version provenance.
3. **Differential tests:** same inputs against the pinned Chromium behavior or
   extracted compatible test oracle; discrepancies are classified, not hidden.
4. **Property and fuzz tests:** CBOR, QR, tunnel frames, Noise messages, CTAP,
   WebAuthn inputs, and state-machine event sequences.
5. **Local integration:** fake Bluetooth, WebSocket/tunnel, authenticator, clock,
   randomness, storage, and lifecycle failure injection.
6. **Real-device interoperability:** declared iPhone and Android devices,
   platform credential providers, roaming keys, and relying parties.
7. **External consumer:** a clean SwiftPM project resolves only the public tag
   and executes the applicable matrix against the exact release candidate.

## Security gates

- Threat model covers malicious relying parties, hostile page input, malicious
  authenticators, tunnel observers/operators, BLE spoofing, replay, downgrade,
  parser exhaustion, cancellation races, and secret leakage.
- Fuzzers have explicit corpus, duration, sanitizer, crash-artifact, and
  minimization receipts.
- Cryptographic code uses reviewed primitives and byte-exact vectors.
- All attacker-controlled lengths/counts/depths are bounded before allocation.
- Logging and crash metadata are scanned for credential and session secrets.
- Persistent pairing cannot ship until revocation, storage protection,
  migration, and corruption behavior are verified.

## Interoperability matrix

Each run records exact package revision, upstream baseline, OS/toolchain,
hardware, phone/device/provider, relying party, request options, transport,
stepwise outcome, terminal error, and artifact disposition. Accounts,
credential IDs, QR payloads, secrets, assertions, and personal data are never
stored in the public ledger.

Required ceremony classes:

- cross-device assertion and creation;
- discoverable and allow-list assertion;
- user-presence and user-verification requirements;
- conditional and explicit mediation;
- cancellation at QR, BLE, tunnel, handshake, UV, and CTAP stages;
- extension matrix from Part 01;
- platform and each roaming transport claimed by the release.

## Release gate

A release requires:

- clean source and release builds;
- exact tag/revision and immutable upstream/specification locks;
- complete license and source-provenance inventory;
- no unclassified parity-matrix rows in the claimed scope;
- green negative, vector, differential, fuzz, and declared interoperability
  gates against the release bytes;
- clean external SwiftPM resolution with no local path override;
- signed tag and published checksum/provenance receipt;
- `EXPERIMENTS.md`, `bugfix.md`, and `changelog.md` synchronized with the hosted
  revision.

## Exit checklist

- [ ] Every supported matrix row names its required test layers.
- [ ] Fuzz/security gates have reproducible commands and retained dispositions.
- [ ] Real-device artifacts contain no secrets or personal data.
- [ ] External-consumer evidence uses hosted release bytes.
- [ ] Skipped rows remain unsupported.
- [ ] Release wording matches the exact matrix with no universal inference.
