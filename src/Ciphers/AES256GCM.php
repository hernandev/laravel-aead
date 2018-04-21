<?php

namespace LaravelAEAD\Ciphers;

use LaravelAEAD\Contracts\Ciphers\AEADCipher as AEADCipherContract;
use RuntimeException;

/**
 * Class AES256GCM.
 *
 * Implementation of the AES-256-GCM cipher.
 */
class AES256GCM extends AEADCipher implements AEADCipherContract
{
    /**
     * @var string Cipher name.
     */
    protected $cipherName = 'AES-256-GCM';

    /**
     * {@inheritdoc}
     */
    public static function keyLength(): int
    {
        return SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES;
    }

    /**
     * {@inheritdoc}
     */
    public static function nonceLength(): int
    {
        return SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES;
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
        return sodium_crypto_aead_aes256gcm_encrypt($data, $additionalData, $nonce, $this->key);
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
        return sodium_crypto_aead_aes256gcm_decrypt($cipherText, $additionalData, $nonce, $this->key);
    }
}