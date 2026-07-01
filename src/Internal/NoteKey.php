<?php

declare(strict_types=1);

namespace K2gl\SignedNote\Internal;

/**
 * Note key primitives shared by the verifier and signer keys.
 *
 * @internal
 */
final class NoteKey
{
    /** The only algorithm the note format defines for its own key hashes. */
    public const ALG_ED25519 = 1;

    /**
     * The 4-byte key hash used in a signature line and in a key string: the first
     * four bytes of SHA-256(name + "\n" + key), where key is the algorithm byte
     * followed by the raw public key.
     */
    public static function hash(string $name, string $key): string
    {
        return substr(hash('sha256', $name . "\n" . $key, true), 0, 4);
    }
}
