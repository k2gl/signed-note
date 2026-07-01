<?php

declare(strict_types=1);

namespace K2gl\SignedNote;

use K2gl\Dsse\Ed25519Signer;
use K2gl\SignedNote\Exception\InvalidNoteException;
use K2gl\SignedNote\Internal\NoteKey;

/**
 * An Ed25519 key that signs a note, producing the same bytes as Go's
 * `note.Sign`. Signing is delegated to k2gl/dsse.
 */
final class SignerKey
{
    private function __construct(
        public readonly string $name,
        public readonly string $keyHash,
        private readonly Ed25519Signer $signer,
    ) {}

    /**
     * Parse a Go-format signer key string, `PRIVATE+KEY+name+hash+base64(alg||seed)`
     * (as produced by `note.GenerateKey`).
     */
    public static function fromString(string $encoded): self
    {
        $parts = explode('+', $encoded, 5);

        if (count($parts) !== 5 || $parts[0] !== 'PRIVATE' || $parts[1] !== 'KEY') {
            throw new InvalidNoteException('Malformed signer key: expected PRIVATE+KEY+name+hash+base64.');
        }

        [, , $name, $hashHex, $base64] = $parts;
        $raw = base64_decode($base64, true);

        if ($raw === false || $raw === '') {
            throw new InvalidNoteException('Signer key body is not valid base64.');
        }

        if (ord($raw[0]) !== NoteKey::ALG_ED25519) {
            throw new InvalidNoteException('Unsupported signer key algorithm (only Ed25519 is defined).');
        }

        $seed = substr($raw, 1);

        if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new InvalidNoteException('Ed25519 seed must be 32 bytes.');
        }

        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $secretKey = sodium_crypto_sign_secretkey($keypair);
        $keyHash = NoteKey::hash($name, chr(NoteKey::ALG_ED25519) . sodium_crypto_sign_publickey($keypair));

        if (bin2hex($keyHash) !== $hashHex) {
            throw new InvalidNoteException('Signer key hash does not match the key.');
        }

        return new self($name, $keyHash, new Ed25519Signer($secretKey));
    }

    /** Sign the text (which must end in a newline) and return the signed note. */
    public function sign(string $text): Note
    {
        if ($text === '' || ! str_ends_with($text, "\n")) {
            throw new InvalidNoteException('Note text must be non-empty and end with a newline.');
        }

        return new Note($text, [
            new NoteSignature($this->name, $this->keyHash, $this->signer->sign($text)),
        ]);
    }
}
