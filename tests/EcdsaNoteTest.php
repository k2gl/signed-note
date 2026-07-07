<?php

declare(strict_types=1);

namespace K2gl\SignedNote\Tests;

use K2gl\SignedNote\Note;
use K2gl\SignedNote\NoteVerifier;
use K2gl\SignedNote\VerifierKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * A Rekor v1 checkpoint is a note signed with the log's ECDSA key, whose key hash
 * is the first four bytes of SHA-256 of the DER public key.
 */
#[CoversClass(VerifierKey::class)]
#[CoversClass(NoteVerifier::class)]
#[CoversClass(Note::class)]
final class EcdsaNoteTest extends TestCase
{
    public function testVerifiesAnEcdsaSignedNote(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        fact($key)->notFalse();
        $pem = (string) openssl_pkey_get_details($key)['key'];

        $origin = 'rekor.example - 123';
        $text = "{$origin}\n8\n" . base64_encode(str_repeat("\x42", 32)) . "\n";

        $signature = '';
        openssl_sign($text, $signature, $key, OPENSSL_ALGO_SHA256); // ASN.1 DER, as Rekor emits
        $keyHash = substr((string) hex2bin(hash('sha256', self::der($pem))), 0, 4);
        $envelope = $text . "\n\u{2014} {$origin} " . base64_encode($keyHash . $signature) . "\n";

        $verified = (new NoteVerifier(VerifierKey::fromPem($origin, $pem)))->verify(Note::parse($envelope));

        fact(count($verified))->is(1);
        fact($verified[0]->name)->is($origin);
    }

    public function testRejectsWrongEcdsaKey(): void
    {
        // arrange
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        fact($key)->notFalse();
        $pem = (string) openssl_pkey_get_details($key)['key'];
        $other = (string) openssl_pkey_get_details(
            openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']) ?: null
        )['key'];

        $origin = 'rekor.example - 123';
        $text = "{$origin}\n8\n" . base64_encode(str_repeat("\x42", 32)) . "\n";
        $signature = '';
        openssl_sign($text, $signature, $key, OPENSSL_ALGO_SHA256);
        // Sign with $key but present the note under $other's key hash + verify with $other.
        $keyHash = substr((string) hex2bin(hash('sha256', self::der($other))), 0, 4);
        $envelope = $text . "\n\u{2014} {$origin} " . base64_encode($keyHash . $signature) . "\n";

        // act + assert
        fact(static fn () => (new NoteVerifier(VerifierKey::fromPem($origin, $other)))->verify(Note::parse($envelope)))
            ->throws(\K2gl\SignedNote\Exception\SignatureVerificationFailed::class);
    }

    private static function der(string $pem): string
    {
        return (string) base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);
    }
}
