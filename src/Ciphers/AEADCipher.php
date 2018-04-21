<?php

namespace LaravelAEAD\Ciphers;

use LaravelAEAD\Contracts\Ciphers\AEADCipher as AEADCipherContract;
use RuntimeException;

/**
 * Class AEADCipher.
 *
 * Generic implementation for AEAD Ciphers.
 *
 * The default values on this class are for XChaCha20-Poly1305-IETF cipher, since it's the recommended one.
 *
 * All ciphers available on libsodium uses 256-bit keys.
 * While the key length is usually the same, declaring it's lengths on each implementation can
 * prevent future errors, since a given implementation may change, it should have it's parameters locally.
 *
 * The nonce lengths are not the same for all ciphers:
 * - AES-256-GCM:              12 bytes  (96  bits).
 * - ChaCha-Poly1305:          8  bytes  (64  bits).
 * - ChaCha-Poly1305-IETF:     12 bytes  (96  bits).
 * - XChaCha-Poly1305-IETF:    24 bytes  (192 bits).
 */
abstract class AEADCipher implements AEADCipherContract
{
    /**
     * @var string Current cipher name.
     */
    protected $cipherName;

    /**
     * @var string Encryption key.
     */
    protected $key;

    /**
     * {@inheritdoc}
     */
    public function __construct(string $key)
    {
        // check the key.
        if (!static::validKey($key)) {
            throw new RuntimeException('Invalid key provided.');
        }

        // assign the key on the cipher instance.
        $this->key = $key;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return $this->cipherName;
    }

    /**
     * {@inheritdoc}
     */
    public static function generateNonce(): string
    {
        return random_bytes(static::nonceLength());
    }

    /**
     * {@inheritdoc}
     */
    public static function generateKey(): string
    {
        return random_bytes(static::keyLength());
    }

    /**
     * {@inheritdoc}
     */
    public static function countBytes(string $value): int
    {
        return mb_strlen($value, '8bit');
    }

    /**
     * {@inheritdoc}
     */
    public static function validKey(string $key) : bool
    {
        // detect if the nonce is valid for the cipher.
        return static::countBytes($key) == static::keyLength();
    }

    /**
     * {@inheritdoc}
     */
    public static function validNonce(string $nonce) : bool
    {
        // detect if the nonce is valid for the cipher.
        return static::countBytes($nonce) == static::nonceLength();
    }
}