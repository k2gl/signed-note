<?php

declare(strict_types=1);

namespace K2gl\SignedNote;

use K2gl\SignedNote\Exception\SignatureVerificationFailed;

/**
 * Verifies a note's signatures against a set of trusted keys, fail-closed: a
 * signature counts only when a known key with the matching hash verifies it.
 */
final class NoteVerifier
{
    /** @var list<VerifierKey> */
    private array $keys;

    public function __construct(VerifierKey ...$keys)
    {
        $this->keys = array_values($keys);
    }

    /**
     * Return the signatures that verified against a known key. Throws when none do.
     *
     * @return list<NoteSignature>
     *
     * @throws SignatureVerificationFailed
     */
    public function verify(Note $note): array
    {
        $verified = [];

        foreach ($note->signatures as $signature) {
            foreach ($this->keys as $key) {
                if ($key->keyHash === $signature->keyHash && $key->verify($note->text, $signature->signature)) {
                    $verified[] = $signature;

                    break;
                }
            }
        }

        if ($verified === []) {
            throw new SignatureVerificationFailed('No note signature verified against a known key.');
        }

        return $verified;
    }
}
