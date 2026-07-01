<?php

declare(strict_types=1);

namespace K2gl\SignedNote;

/**
 * One signature line of a note: the signer's name, its 4-byte key hash (which
 * selects the signing key), and the raw signature bytes.
 */
final class NoteSignature
{
    public function __construct(
        public readonly string $name,
        public readonly string $keyHash,
        public readonly string $signature,
    ) {}
}
