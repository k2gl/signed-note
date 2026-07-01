# Changelog

## 1.0.0

First public release. Parse, verify and sign signed notes — the format Go's sumdb
and transparency-log checkpoints (Sigstore Rekor) use.

- **`Note::parse()`** — split a note into its signed text and `NoteSignature`
  lines; `__toString()` renders it back.
- **`VerifierKey`** — a trusted key: `ed25519()` / `fromString()` (Go
  `name+hash+base64` key strings) for the standard Ed25519 algorithm, and
  `fromPem()` for a Sigstore-style key hash over any RSA/ECDSA/Ed25519 key.
- **`NoteVerifier`** — fail-closed: returns the signatures that verify against a
  known key, throws when none do.
- **`SignerKey`** — signs a note with an Ed25519 key, byte-compatible with Go's
  `note.Sign` (verified against the `x/mod/sumdb/note` test vectors).

Cryptography is delegated to [`k2gl/dsse`]. Ed25519 needs `ext-sodium`; ECDSA
notes need `ext-openssl`.

[`k2gl/dsse`]: https://github.com/k2gl/dsse
