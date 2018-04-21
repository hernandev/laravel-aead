<?php

namespace LaravelAEAD\Contracts\Ciphers;

/**
 * Interface AEADCipher.
 *
 * Generic interface for AEAD (Authenticated Encryption with Additional Data) cipher implementations.
 */
interface AEADCipher
{
    /**
     * Cipher constructor.
     *
     * @param string $key The raw encryption key value.
     */
    public function __construct(string $key);

    /**
     * Returns the UPPERCASE name for the cipher.
     *
     * For usage on generic implementations.
     *
     * @return string
     */
    public function getName() : string;

    /**
     * Encrypt a given value using the current cipher.
     *
     * @param string $nonce The encryption nonce (IV on some ciphers).
     * @param string $data The data to encrypt.
     * @param string $additionalData Additional data (AD).
     *
     * @return string
     */
    public function encrypt(string $nonce, string $data, string $additionalData = null) : string;

    /**
     * Decrypt a given cipher text using the current cipher.
     *
     * @param string $nonce The encryption nonce used to encrypt.
     * @param string $cipherText The encrypted cipher text to decrypt.
     * @param string $additionalData The additional data used when encrypting.
     *
     * @return string
     */
    public function decrypt(string $nonce, string $cipherText, string $additionalData = null) : string;

    /**
     * Generates a random secret key to use with the cipher.
     *
     * @return string
     */
    public static function generateKey() : string;

    /**
     * Generates a random nonce.
     *
     * @return string
     */
    public static function generateNonce() : string;

    /**
     * Returns the required key size for the cipher (in bytes).
     *
     * @return int
     */
    public static function keyLength() : int;

    /**
     * Returns the required nonce size for the cipher (in bytes).
     *
     * @return int
     */
    public static function nonceLength() : int;

    /**
     * Check if a given key is of valid for the cipher.
     *
     * @param string $key
     *
     * @return bool
     */
    public static function validKey(string $key) : bool;

    /**
     * Check if a given nonce is of valid for the cipher.
     *
     * @param string $nonce
     *
     * @return bool
     */
    public static function validNonce(string $nonce) : bool;

    /**
     * Determine the length, in bytes of a given value.
     *
     * @param string $value
     *
     * @return int
     */
    public static function countBytes(string $value) : int;
}