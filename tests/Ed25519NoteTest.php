<?php

declare(strict_types=1);

namespace K2gl\SignedNote\Tests;

use K2gl\SignedNote\Exception\InvalidNoteException;
use K2gl\SignedNote\Exception\SignatureVerificationFailed;
use K2gl\SignedNote\Internal\NoteKey;
use K2gl\SignedNote\Note;
use K2gl\SignedNote\NoteSignature;
use K2gl\SignedNote\NoteVerifier;
use K2gl\SignedNote\SignerKey;
use K2gl\SignedNote\VerifierKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * Canonical vectors from golang.org/x/mod/sumdb/note.
 */
#[CoversClass(VerifierKey::class)]
#[CoversClass(SignerKey::class)]
#[CoversClass(NoteVerifier::class)]
#[CoversClass(Note::class)]
#[CoversClass(NoteSignature::class)]
#[CoversClass(NoteKey::class)]
#[CoversClass(SignatureVerificationFailed::class)]
#[CoversClass(InvalidNoteException::class)]
final class Ed25519NoteTest extends TestCase
{
    private const VKEY = 'PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW';
    private const SKEY = 'PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz';
    private const TEXT = "If you think cryptography is the answer to your problem,\n"
        . "then you don't know what your problem is.\n";
    private const SIG_B64 = 'x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=';

    public function testSignsTheCanonicalVectorByteForByte(): void
    {
        $note = SignerKey::fromString(self::SKEY)->sign(self::TEXT);
        $signature = $note->signatures[0];

        fact($signature->name)->is('PeterNeumann');
        fact(base64_encode($signature->keyHash . $signature->signature))->is(self::SIG_B64);
        fact((string) $note)->is(self::TEXT . "\n\u{2014} PeterNeumann " . self::SIG_B64 . "\n");
    }

    public function testVerifiesTheCanonicalNote(): void
    {
        $envelope = self::TEXT . "\n\u{2014} PeterNeumann " . self::SIG_B64 . "\n";

        $verified = (new NoteVerifier(VerifierKey::fromString(self::VKEY)))->verify(Note::parse($envelope));

        fact(count($verified))->is(1);
        fact($verified[0]->name)->is('PeterNeumann');
    }

    public function testSignThenVerifyRoundTrips(): void
    {
        $note = SignerKey::fromString(self::SKEY)->sign("some fresh text\n");

        $verified = (new NoteVerifier(VerifierKey::fromString(self::VKEY)))->verify($note);

        fact(count($verified))->is(1);
    }

    public function testRejectsTamperedText(): void
    {
        $note = SignerKey::fromString(self::SKEY)->sign("hello\n");
        $tampered = new Note("HELLO\n", $note->signatures);

        $this->expectException(SignatureVerificationFailed::class);

        (new NoteVerifier(VerifierKey::fromString(self::VKEY)))->verify($tampered);
    }

    public function testRejectsWhenNoKnownKeyMatches(): void
    {
        $note = SignerKey::fromString(self::SKEY)->sign("hello\n");
        $stranger = VerifierKey::ed25519('Stranger', str_repeat("\x01", 32));

        $this->expectException(SignatureVerificationFailed::class);

        (new NoteVerifier($stranger))->verify($note);
    }

    public function testFromStringRejectsKeyHashMismatch(): void
    {
        $this->expectException(InvalidNoteException::class);

        VerifierKey::fromString('PeterNeumann+00000000+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW');
    }
}
