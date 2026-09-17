# k2gl/signed-note

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/signed-note/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/signed-note/actions/workflows/ci.yml)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/signed-note?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/signed-note)
[![Total Downloads](https://img.shields.io/packagist/dt/k2gl/signed-note?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/signed-note)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-level%209-2a5ea7?logo=php&logoColor=white)](https://phpstan.org)
[![License](https://img.shields.io/packagist/l/k2gl/signed-note?color=yellowgreen)](https://packagist.org/packages/k2gl/signed-note)

Parse, verify and sign **signed notes** in PHP — the format Go's sumdb and
transparency-log **checkpoints** (Sigstore Rekor) use. A note is some text, a
blank line, then one or more signature lines:

```
If you think cryptography is the answer to your problem,
then you don't know what your problem is.

— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=
```

Each signature line is `— <name> <base64>`, where the base64 decodes to a 4-byte
key hash and the raw signature over the text. The cryptography is delegated to
[`k2gl/dsse`].

## Install

```bash
composer require k2gl/signed-note
```

Requires PHP 8.1+ with `ext-sodium` (Ed25519); `ext-openssl` is needed only for
ECDSA-signed notes such as Rekor v1 checkpoints.

## Verify

Give a `NoteVerifier` the keys you trust; it returns the signatures that verify
and throws if none do.

```php
use K2gl\SignedNote\Note;
use K2gl\SignedNote\NoteVerifier;
use K2gl\SignedNote\VerifierKey;

$key = VerifierKey::fromString('PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW');

$verified = (new NoteVerifier($key))->verify(Note::parse($envelope));
// $verified is the list of NoteSignature that checked out; SignatureVerificationFailed otherwise.
```

A Rekor checkpoint is a note signed by the log's key. Load that key from its PEM —
the key hash is derived the Sigstore way (first four bytes of SHA-256 of the DER
key), and any RSA/ECDSA/Ed25519 key works:

```php
$log = VerifierKey::fromPem('rekor.sigstore.dev - 1193050959916656506', $logPublicKeyPem);
(new NoteVerifier($log))->verify(Note::parse($checkpoint));
```

## Checkpoints

A transparency log publishes its head as a checkpoint: a note whose text is the
log's origin, the tree size and the base64 root hash, one per line (further lines
are extensions). `Checkpoint` reads those three lines; the signatures stay the
note's, so it is verified with the log's key like any other note.

```php
use K2gl\SignedNote\Checkpoint;
use K2gl\SignedNote\NoteVerifier;
use K2gl\SignedNote\VerifierKey;

$checkpoint = Checkpoint::parse($envelope);

$checkpoint->origin;     // "log2025-1.rekor.sigstore.dev"
$checkpoint->treeSize;   // 114068855
$checkpoint->rootHash;   // raw 32 bytes
$checkpoint->extensions; // any lines after the first three

$log = VerifierKey::ed25519($checkpoint->origin, $rawEd25519PublicKey); // a Rekor v2 log
$checkpoint->verify(new NoteVerifier($log)); // SignatureVerificationFailed otherwise
```

A Rekor v2 log signs with an Ed25519 key whose hash is the note one (origin plus
key), hence `VerifierKey::ed25519()`; a Rekor v1 log's ECDSA key is `fromPem()` as
above. The test suite reads a real `log2025-1.rekor.sigstore.dev` checkpoint and
verifies it against the key from Sigstore's trusted root.

## Sign

```php
use K2gl\SignedNote\SignerKey;

$signer = SignerKey::fromString('PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz');

$note = $signer->sign("hello\n"); // text must end with a newline
echo $note;                       // renders the note with its signature line
```

The output is byte-for-byte what Go's `note.Sign` produces (checked against the
`golang.org/x/mod/sumdb/note` test vectors).

## Design

- **Two layers.** `Note` is the generic note and knows nothing about logs;
  `Checkpoint` adds the meaning of the first three lines and nothing else.
- **Fail-closed.** A verified result means a trusted key signed the exact text.
- **Ed25519 is the standard.** `VerifierKey::fromString()` / `SignerKey` handle the
  Ed25519 key strings from Go's `note` package; `fromPem()` covers ECDSA/RSA logs.

## License

MIT.
