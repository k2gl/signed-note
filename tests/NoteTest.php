<?php

declare(strict_types=1);

namespace K2gl\SignedNote\Tests;

use K2gl\SignedNote\Exception\InvalidNoteException;
use K2gl\SignedNote\Note;
use K2gl\SignedNote\NoteSignature;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Note::class)]
#[CoversClass(NoteSignature::class)]
#[CoversClass(InvalidNoteException::class)]
final class NoteTest extends TestCase
{
    public function testParsesTextAndSignatures(): void
    {
        $blob = base64_encode(str_repeat("\x00", 4) . str_repeat("\x11", 64));
        $note = Note::parse("line one\nline two\n\n\u{2014} Alice {$blob}\n");

        fact($note->signedText())->is("line one\nline two\n");
        fact(count($note->signatures))->is(1);
        fact($note->signatures[0]->name)->is('Alice');
        fact(strlen($note->signatures[0]->keyHash))->is(4);
        fact(strlen($note->signatures[0]->signature))->is(64);
    }

    public function testToStringRoundTrips(): void
    {
        $blob = base64_encode(str_repeat("\x00", 4) . str_repeat("\x22", 64));
        $envelope = "hello\n\n\u{2014} Bob {$blob}\n";

        fact((string) Note::parse($envelope))->is($envelope);
    }

    public function testRejectsNoteWithoutBlankLine(): void
    {
        $this->expectException(InvalidNoteException::class);

        Note::parse("just text with no separator\n\u{2014} Bob AAAAAAAA\n");
    }

    public function testRejectsSignatureLineWithoutEmDash(): void
    {
        $this->expectException(InvalidNoteException::class);

        Note::parse('text' . "\n\n" . 'Bob ' . base64_encode(str_repeat("\x00", 68)) . "\n");
    }

    public function testRejectsNoteWithNoSignatures(): void
    {
        $this->expectException(InvalidNoteException::class);

        Note::parse("text\n\n");
    }
}
