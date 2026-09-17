<?php

declare(strict_types=1);

namespace K2gl\SignedNote;

use K2gl\SignedNote\Exception\InvalidNoteException;
use K2gl\SignedNote\Exception\SignatureVerificationFailed;
use Stringable;

/**
 * A transparency-log checkpoint: a note whose text names the log (the origin
 * line) and commits it to a tree size and a root hash, one per line and in that
 * order; any further lines are extensions. Sigstore Rekor, Go's sumdb and the
 * Trillian/Tessera logs all publish their heads this way.
 *
 * The note itself is read by {@see Note}; what lives here is the meaning of
 * the first three lines. The signatures are the note's, so a checkpoint is
 * verified like any other note — with the log's key.
 *
 * @see https://c2sp.org/tlog-checkpoint
 */
final class Checkpoint implements Stringable
{
    /**
     * @param list<string> $extensions
     */
    private function __construct(
        public readonly Note $note,
        public readonly string $origin,
        public readonly int $treeSize,
        public readonly string $rootHash,
        public readonly array $extensions,
    ) {}

    public static function parse(string $envelope): self
    {
        return self::fromNote(Note::parse($envelope));
    }

    public static function fromNote(Note $note): self
    {
        // signedText() ends with the newline the log wrote before the blank separator.
        $lines = explode("\n", substr($note->signedText(), 0, -1));

        if (count($lines) < 3) {
            throw new InvalidNoteException('Checkpoint must have at least three lines: origin, tree size and root hash.');
        }

        [$origin, $size, $hash] = $lines;

        if ($origin === '') {
            throw new InvalidNoteException('Checkpoint origin line must not be empty.');
        }

        if (preg_match('/^(0|[1-9][0-9]*)$/', $size) !== 1 || (string) (int) $size !== $size) {
            throw new InvalidNoteException('Checkpoint tree size is not a decimal integer.');
        }

        $rootHash = base64_decode($hash, true);

        if ($rootHash === false || $rootHash === '' || base64_encode($rootHash) !== $hash) {
            throw new InvalidNoteException('Checkpoint root hash is not valid base64.');
        }

        return new self($note, $origin, (int) $size, $rootHash, array_slice($lines, 3));
    }

    /**
     * Verify the checkpoint against the log's key(s) and return the signatures
     * that checked out. Throws when none do.
     *
     * @return list<NoteSignature>
     *
     * @throws SignatureVerificationFailed
     */
    public function verify(NoteVerifier $verifier): array
    {
        return $verifier->verify($this->note);
    }

    /** The checkpoint as the log served it. */
    public function __toString(): string
    {
        return (string) $this->note;
    }
}
