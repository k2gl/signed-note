<?php

declare(strict_types=1);

namespace K2gl\SignedNote;

use K2gl\SignedNote\Exception\InvalidNoteException;
use Stringable;

/**
 * A signed note: some text followed by a blank line and one or more signature
 * lines. This is the format Go's sumdb and transparency-log checkpoints (Sigstore
 * Rekor) use. The signed bytes are the text up to and including the newline before
 * the blank separator; each signature line is "— <name> <base64>", where the
 * base64 decodes to a 4-byte key hash followed by the raw signature.
 *
 * @see https://pkg.go.dev/golang.org/x/mod/sumdb/note
 */
final class Note implements Stringable
{
    /** Em-dash (U+2014) and a space — the prefix of every signature line. */
    private const SIGNATURE_PREFIX = "\u{2014} ";

    /**
     * @param list<NoteSignature> $signatures
     */
    public function __construct(
        public readonly string $text,
        public readonly array $signatures,
    ) {}

    public static function parse(string $envelope): self
    {
        $separator = strpos($envelope, "\n\n");

        if ($separator === false) {
            throw new InvalidNoteException('Note has no blank line separating text and signatures.');
        }

        $text = substr($envelope, 0, $separator) . "\n";
        $signatures = self::parseSignatures(substr($envelope, $separator + 2));

        if ($signatures === []) {
            throw new InvalidNoteException('Note has no signatures.');
        }

        return new self($text, $signatures);
    }

    /** The exact bytes covered by the signatures (the text, ending in a newline). */
    public function signedText(): string
    {
        return $this->text;
    }

    /** @return list<NoteSignature> */
    public function signatures(): array
    {
        return $this->signatures;
    }

    public function __toString(): string
    {
        $lines = '';

        foreach ($this->signatures as $signature) {
            $lines .= self::SIGNATURE_PREFIX . $signature->name . ' '
                . base64_encode($signature->keyHash . $signature->signature) . "\n";
        }

        return $this->text . "\n" . $lines;
    }

    /**
     * @return list<NoteSignature>
     */
    private static function parseSignatures(string $block): array
    {
        $signatures = [];

        foreach (explode("\n", $block) as $line) {
            if ($line === '') {
                continue;
            }

            if (! str_starts_with($line, self::SIGNATURE_PREFIX)) {
                throw new InvalidNoteException('Signature line does not start with an em-dash.');
            }

            // The signature is the last space-separated token; the name may itself
            // contain spaces (a Rekor checkpoint origin does).
            $rest = substr($line, strlen(self::SIGNATURE_PREFIX));
            $space = strrpos($rest, ' ');

            if ($space === false) {
                throw new InvalidNoteException('Signature line has no space between name and signature.');
            }

            $decoded = base64_decode(substr($rest, $space + 1), true);

            if ($decoded === false || strlen($decoded) <= 4) {
                throw new InvalidNoteException('Signature is not valid base64 or is too short.');
            }

            $signatures[] = new NoteSignature(
                name: substr($rest, 0, $space),
                keyHash: substr($decoded, 0, 4),
                signature: substr($decoded, 4),
            );
        }

        return $signatures;
    }
}
