<?php

declare(strict_types=1);

namespace K2gl\SignedNote;

use K2gl\Dsse\Ed25519Verifier;
use K2gl\Dsse\KeyId;
use K2gl\Dsse\PublicKey;
use K2gl\Dsse\Verifier;
use K2gl\SignedNote\Exception\InvalidNoteException;
use K2gl\SignedNote\Internal\NoteKey;

/**
 * A trusted key that can verify a note's signatures. Its 4-byte key hash selects
 * which signature line it applies to. The verification itself is delegated to
 * k2gl/dsse.
 */
final class VerifierKey
{
    private function __construct(
        public readonly string $name,
        public readonly string $keyHash,
        private readonly Verifier $verifier,
    ) {}

    /** An Ed25519 key from a raw 32-byte public key (the standard note algorithm). */
    public static function ed25519(string $name, string $publicKey): self
    {
        if ($publicKey === '' || strlen($publicKey) !== 32) {
            throw new InvalidNoteException('Ed25519 public key must be 32 bytes.');
        }

        $keyHash = NoteKey::hash($name, chr(NoteKey::ALG_ED25519) . $publicKey);

        return new self($name, $keyHash, new Ed25519Verifier($publicKey));
    }

    /**
     * Parse a Go-format verifier key string, `name+hash+base64(alg||publicKey)`
     * (as produced by `note.NewEd25519VerifierKey`). Ed25519 only.
     */
    public static function fromString(string $encoded): self
    {
        $parts = explode('+', $encoded, 3);

        if (count($parts) !== 3) {
            throw new InvalidNoteException('Malformed verifier key: expected name+hash+base64.');
        }

        [$name, $hashHex, $base64] = $parts;
        $raw = base64_decode($base64, true);

        if ($raw === false || $raw === '') {
            throw new InvalidNoteException('Verifier key body is not valid base64.');
        }

        if (ord($raw[0]) !== NoteKey::ALG_ED25519) {
            throw new InvalidNoteException('Unsupported verifier key algorithm (only Ed25519 is defined).');
        }

        $key = self::ed25519($name, substr($raw, 1));

        if (bin2hex($key->keyHash) !== $hashHex) {
            throw new InvalidNoteException('Verifier key hash does not match the key.');
        }

        return $key;
    }

    /**
     * A key identified the Sigstore way: the key hash is the first four bytes of
     * SHA-256 of the DER public key. Accepts any algorithm k2gl/dsse can load
     * (RSA, ECDSA P-256/384/521, Ed25519) — e.g. a Rekor v1 log's ECDSA key.
     */
    public static function fromPem(string $name, string $publicKeyPem): self
    {
        $keyHash = substr((string) hex2bin(KeyId::sha256Spki($publicKeyPem)), 0, 4);

        return new self($name, $keyHash, PublicKey::fromPem($publicKeyPem));
    }

    public function verify(string $signedText, string $signature): bool
    {
        return $this->verifier->verify($signedText, $signature);
    }
}
