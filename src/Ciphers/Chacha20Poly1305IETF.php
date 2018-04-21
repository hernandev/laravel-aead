<?php

namespace LaravelAEAD\Ciphers;

use LaravelAEAD\Contracts\Ciphers\AEADCipher as AEADCipherContract;
use RuntimeException;

/**
 * Class Chacha20Poly1305IETF.
 *
 * Implementation of the ChaCha20-Poly1305-IETF cipher.
 */
class Chacha20Poly1305IETF extends AEADCipher implements AEADCipherContract
{
    /**
     * @var string Cipher name.
     */
    protected $cipherName = 'CHACHA20-POLY1305-IETF';

    /**
     * {@inheritdoc}
     */
    public static function keyLength(): int
    {
        return SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
    }

    /**
     * {@inheritdoc}
     */
    public static function nonceLength(): int
    {
        return SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES;
    }

    /*
     * {@inheritdoc}
     */
    public function encrypt(string $nonce, string $data, string $additionalData = null): string
    {
        // check the nonce.
        if (!static::validNonce($nonce)) {
            throw new RuntimeException('Invalid nonce provided.');
        }

        // encrypt the data and return the cipher text.
        return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($data, $additionalData, $nonce, $this->key);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $nonce, string $cipherText, string $additionalData = null) : string
    {
        // check the nonce.
        if (!static::validNonce($nonce)) {
            throw new RuntimeException('Invalid nonce provided.');
        }

        // decrypt the cipher text and return the data.
        return sodium_crypto_aead_chacha20poly1305_ietf_decrypt($cipherText, $additionalData, $nonce, $this->key);
    }
}