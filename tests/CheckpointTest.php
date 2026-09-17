<?php

declare(strict_types=1);

namespace K2gl\SignedNote\Tests;

use K2gl\SignedNote\Checkpoint;
use K2gl\SignedNote\Exception\InvalidNoteException;
use K2gl\SignedNote\Exception\SignatureVerificationFailed;
use K2gl\SignedNote\Note;
use K2gl\SignedNote\NoteVerifier;
use K2gl\SignedNote\SignerKey;
use K2gl\SignedNote\VerifierKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Checkpoint::class)]
#[CoversClass(Note::class)]
#[CoversClass(NoteVerifier::class)]
#[CoversClass(VerifierKey::class)]
#[CoversClass(SignerKey::class)]
#[CoversClass(InvalidNoteException::class)]
#[CoversClass(SignatureVerificationFailed::class)]
final class CheckpointTest extends TestCase
{
    /** The Rekor v2 log's Ed25519 key as Sigstore's trusted root carries it (DER SubjectPublicKeyInfo). */
    private const REKOR_V2_SPKI = 'MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=';

    private const SKEY = 'PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz';
    private const VKEY = 'PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW';

    public function testReadsARealRekorV2Checkpoint(): void
    {
        $envelope = self::fixture('rekor-v2-checkpoint.txt');

        $checkpoint = Checkpoint::parse($envelope);

        fact($checkpoint->origin)->is('log2025-1.rekor.sigstore.dev');
        fact($checkpoint->treeSize)->is(114068855);
        fact(base64_encode($checkpoint->rootHash))->is('uXmV5jkyZgXN2o6QMPYIPpTwzaAdL+3IFw0SMp4JmGI=');
        fact($checkpoint->extensions)->is([]);
        fact($checkpoint->note->signatures)->count(4); // the log and three witnesses
        fact((string) $checkpoint)->is($envelope);
    }

    public function testVerifiesARealRekorV2CheckpointWithTheLogKey(): void
    {
        // arrange — an Ed25519 SubjectPublicKeyInfo is a 12-byte prefix and the raw key
        $raw = substr((string) base64_decode(self::REKOR_V2_SPKI, true), -32);
        $checkpoint = Checkpoint::parse(self::fixture('rekor-v2-checkpoint.txt'));

        // act
        $verified = $checkpoint->verify(new NoteVerifier(VerifierKey::ed25519($checkpoint->origin, $raw)));

        // assert
        fact($verified)->count(1);
        fact($verified[0]->name)->is('log2025-1.rekor.sigstore.dev');
    }

    public function testRejectsARealCheckpointUnderTheWrongKey(): void
    {
        // arrange
        $checkpoint = Checkpoint::parse(self::fixture('rekor-v2-checkpoint.txt'));
        $other = new NoteVerifier(VerifierKey::ed25519('log2025-1.rekor.sigstore.dev', str_repeat("\x01", 32)));

        // act + assert
        fact(static fn () => $checkpoint->verify($other))->throws(SignatureVerificationFailed::class);
    }

    public function testKeepsOriginsWithSpacesAndExtensionLines(): void
    {
        // arrange — a Rekor v1 style origin, plus an extension line
        $text = "rekor.example - 123\n8\n" . base64_encode(str_repeat("\x42", 32)) . "\nsome extension\n";
        $note = SignerKey::fromString(self::SKEY)->sign($text);

        // act
        $checkpoint = Checkpoint::fromNote($note);

        // assert
        fact($checkpoint->origin)->is('rekor.example - 123');
        fact($checkpoint->treeSize)->is(8);
        fact($checkpoint->rootHash)->is(str_repeat("\x42", 32));
        fact($checkpoint->extensions)->is(['some extension']);
        fact($checkpoint->verify(new NoteVerifier(VerifierKey::fromString(self::VKEY))))->count(1);
    }

    public function testAcceptsAnEmptyTree(): void
    {
        $note = SignerKey::fromString(self::SKEY)->sign("log\n0\n" . base64_encode(hash('sha256', '', true)) . "\n");

        fact(Checkpoint::fromNote($note)->treeSize)->is(0);
    }

    public function testRejectsFewerThanThreeLines(): void
    {
        // arrange
        $note = SignerKey::fromString(self::SKEY)->sign("log\n8\n");

        // act + assert
        fact(static fn () => Checkpoint::fromNote($note))->throws(InvalidNoteException::class);
    }

    public function testRejectsAnEmptyOrigin(): void
    {
        // arrange
        $note = SignerKey::fromString(self::SKEY)->sign("\n8\n" . base64_encode(str_repeat("\x42", 32)) . "\n");

        // act + assert
        fact(static fn () => Checkpoint::fromNote($note))->throws(InvalidNoteException::class);
    }

    public function testRejectsATreeSizeThatIsNotADecimalInteger(): void
    {
        // arrange
        $hash = base64_encode(str_repeat("\x42", 32));
        $leadingZero = SignerKey::fromString(self::SKEY)->sign("log\n08\n{$hash}\n");
        $negative = SignerKey::fromString(self::SKEY)->sign("log\n-1\n{$hash}\n");
        $overflow = SignerKey::fromString(self::SKEY)->sign("log\n99999999999999999999\n{$hash}\n");

        // act + assert
        fact(static fn () => Checkpoint::fromNote($leadingZero))->throws(InvalidNoteException::class);
        fact(static fn () => Checkpoint::fromNote($negative))->throws(InvalidNoteException::class);
        fact(static fn () => Checkpoint::fromNote($overflow))->throws(InvalidNoteException::class);
    }

    public function testRejectsARootHashThatIsNotBase64(): void
    {
        // arrange
        $note = SignerKey::fromString(self::SKEY)->sign("log\n8\nnot*base64\n");

        // act + assert
        fact(static fn () => Checkpoint::fromNote($note))->throws(InvalidNoteException::class);
    }

    public function testRejectsANoteWithoutSignatures(): void
    {
        // act + assert
        fact(static fn () => Checkpoint::parse("log\n8\n" . base64_encode(str_repeat("\x42", 32)) . "\n\n"))
            ->throws(InvalidNoteException::class);
    }

    private static function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/' . $name);
        fact($contents)->notFalse();

        return (string) $contents;
    }
}
