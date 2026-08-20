# Security policy

SiriusSecurityKey is pre-release. It contains a development-stage one-shot
hybrid transport through CTAP `authenticatorGetInfo`, but no WebAuthn ceremony,
credential creation/assertion, real-device certification, or production-
supported release. Security reports are welcome, especially for protocol
design, origin/RP binding, parsing, cryptographic transcripts, transport state,
cancellation, secret handling, and denial-of-service risks.

Please use the repository's private GitHub security-advisory form. Do not place
credentials, QR payloads, private keys, assertions, pairing records, account
identifiers, or other secrets in a public issue.

Published releases will list their supported versions here. Until then, no
version is considered production-supported.
