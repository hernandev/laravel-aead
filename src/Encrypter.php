<?php

namespace LaravelAEAD;

use LaravelAEAD\Ciphers;
use LaravelAEAD\Contracts\Encrypter as EncrypterContract;
use LaravelAEAD\Exceptions\DecryptException;
use LaravelAEAD\Exceptions\EncryptException;
use RuntimeException;

/**
 * Class Encrypter.
 *
 * This encrypter leverage libsodium to provide
 * Advanced Encryption with Additional Data (AEAD) for Laravel.
 */
class Encrypter implements EncrypterContract
{
    /**
     * @var array List of possible AEAD ciphers.
     */
    protected static $ciphers = [
        'AES-256-GCM'             => Ciphers\AES256GCM::class,
        'CHACHA20-POLY1305'       => Ciphers\Chacha20Poly1305::class,
        'CHACHA20-POLY1305-IETF'  => Ciphers\Chacha20Poly1305IETF::class,
        'XCHACHA20-POLY1305-IETF' => Ciphers\XChacha20Poly1305IETF::class
    ];

    /**
     * @var int Base64 variable to use.
     */
    protected $base64Variant = SODIUM_BASE64_VARIANT_ORIGINAL;

    /**
     * @var Ciphers\AEADCipher Cipher to encrypt/decrypt the data.
     */
    protected $cipher;

    /**
     * Create a new encrypter instance.
     *
     * @param  string $key
     * @param  string $cipherName
     * @return void
     *
     * @throws \RuntimeException
     */
    public function __construct($key, $cipherName = 'XCHACHA20-POLY1305-IETF')
    {
        // force the key into string.
        $key = (string)$key;

        // create the instance of the cipher.
        $this->cipher = self::makeCipher($key, $cipherName);
    }

    /**
     * Encrypt the given data, with optional additional data.
     *
     * @param null $plainValue
     * @param bool $serialize
     * @param null $additionalData
     *
     * @return null|string
     */
    public function encrypt($plainValue = null, $serialize = true, $additionalData = null)
    {
        // generate a nonce for the encryption.
        $nonce = $this->cipher->generateNonce();

        // serialize the value to encrypt
        $value = serialize($plainValue);
        // serialize the additional data.
        $ad = serialize($additionalData);

        // encrypt the data.
        try {
            $cipherText = $this->cipher->encrypt($nonce, $value, $ad);
        } catch (\Exception $e) {
            throw new EncryptException("Error while encrypting the data.", $e);
        }

        // return the encoded payload with the encrypted value (cipher text)
        return $this->encodePayload($nonce, $cipherText, $ad);
    }

    /**
     * Decrypt a given payload.
     *
     * @param string $payload
     * @param bool $serialized
     *
     * @return mixed|string
     */
    public function decrypt($payload, $serialized = true)
    {
        // decode the payload into an array.
        $payload = $this->decodePayload($payload);

        // try to decrypt.
        try {
            $value = $this->cipher->decrypt($payload['nonce'], $payload['value'], $payload['ad']);
        } catch (\Exception $e) {
            throw new DecryptException("Error while decrypting the payload.");
        }

        return unserialize($value);
    }

    /**
     * Create a new encryption key for the given cipher.
     *
     * @param  string $cipherName
     *
     * @return string
     */
    public static function generateKey($cipherName = 'XCHACHA20-POLY1305-IETF'): string
    {
        $cipherClass = self::getCipherClass($cipherName);

        return call_user_func([$cipherClass, 'generateKey']);
    }

    /**
     * Decode an encrypted payload into an array.
     *
     * @param string $payload
     *
     * @return array
     */
    protected function decodePayload(string $payload) : array
    {
        // decode from Base64, then from JSON.
        $payload = json_decode($this->decodeBase64($payload), true);

        // the payload should at least contain the 3 main keys.
        if (!array_has($payload, ['value', 'nonce', 'ad'])) {
            throw new DecryptException('Invalid Payload.');
        }

        // decode all base64 values.
        return array_map(function ($value) {
            return $this->decodeBase64($value);
        }, $payload);
    }

    /**
     * Encode the values to form the encrypted payload.
     *
     * @param $nonce
     * @param $cipherText
     * @param $ad
     *
     * @return null|string
     */
    protected function encodePayload($nonce, $cipherText, $ad) : ?string
    {
        // alias variable.
        $value = $cipherText;

        // compact into an array.
        $payload = compact('value', 'nonce', 'ad');

        // map the parts, encoding into Base64 each one.
        $payload = array_map(function ($value) {
            return $this->encodeBase64($value);
        }, $payload);

        // encode the payload into JSON, then on Base64.
        return $this->encodeBase64(json_encode($payload));
    }

    /**
     * Returns the current AEAD cipher on the encrypter instance.
     *
     * @return Ciphers\AEADCipher
     */
    public function getCipher() : Ciphers\AEADCipher
    {
        return $this->cipher;
    }

    /**
     * Content-type safe Base64 encoding.
     *
     * @param string|null $rawValue The raw value to encode.
     *
     * @return string The Base64 encoded value.
     */
    public function encodeBase64(string $rawValue = null): ?string
    {
        return $rawValue ? sodium_bin2base64($rawValue, $this->base64Variant) : null;
    }

    /**
     * Constant-type safe Base64 decoding.
     *
     * @param null|string $value Encoded value to decode.
     *
     * @return null|string The raw decoded value.
     */
    public function decodeBase64(string $value = null): ?string
    {
        return $value ? sodium_base642bin($value, $this->base64Variant) : null;
    }

    /**
     * Creates a cipher instance, from a key and a cipher name.
     *
     * @param string $key
     * @param string $cipherName
     *
     * @return Ciphers\AEADCipher
     */
    public static function makeCipher(string $key, string $cipherName = 'XCHACHA20-POLY1305-IETF'): Ciphers\AEADCipher
    {
        // retrieves the list of available ciphers
        $cipherClass = self::getCipherClass($cipherName);

        // return a new cipher instance, with the provided key.
        return new $cipherClass($key);
    }

    /**
     * Checks if a given cipher is actually supported, and the provided key is valid.
     *
     * @param string $key
     * @param string $cipherName
     *
     * @return bool
     */
    public static function supported(string $key, string $cipherName = 'XCHACHA20-POLY1305-IETF'): bool
    {
        try {
            return !!self::makeCipher($key, $cipherName);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Returns a list of available ciphers, in an associative array with name => class format.
     *
     * @return array
     */
    public static function getCiphers(): array
    {
        return self::$ciphers;
    }

    /**
     * Returns the cipher class / implementation based on it's name.
     *
     * @param string $cipherName
     *
     * @return string
     */
    public static function getCipherClass(string $cipherName): string
    {
        // retrieves the list of available ciphers
        $cipherClass = array_get(self::getCiphers(), $cipherName, null);

        // check if the cipher exists.
        if (!$cipherClass || !class_exists($cipherClass)) {
            throw new RuntimeException("The cipher {$cipherName} is not supported.");
        }

        // returns the cipher class.
        return $cipherClass;
    }
}