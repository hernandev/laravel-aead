<?php

namespace LaravelAEAD\Providers;

use LaravelAEAD\Encrypter;
use Illuminate\Encryption\Encrypter as LaravelEncrypter;
use Illuminate\Encryption\EncryptionServiceProvider as LaravelEncryptionServiceProvider;
use Illuminate\Support\Str;
use Illuminate\Contracts\Config\Repository as Config;

/**
 * Class EncryptionServiceProvider.
 *
 * This service provider can be used to register the package encrypter and fallback to
 * the default Laravel encrypter.
 *
 * It means unless the configured cipher changes to one of the supported ciphers of the package,
 * the default Laravel encrypter will still be used.
 */
class EncryptionServiceProvider extends LaravelEncryptionServiceProvider
{
    /**
     * Register the encrypter.
     */
    public function register()
    {
        // starts the singleton.
        $this->app->singleton('encrypter', function () {
            // find the encryption key from config.
            $key = $this->getConfigValue('app.key');

            // find the cipher from config.
            $cipher = $this->getConfigValue('app.cipher', 'AES-256-CBC');

            // when the configured cipher is not supported,
            // default to Laravel encrypter.
            if (!$this->supported($cipher)) {
                return new LaravelEncrypter($key, $cipher);
            }

            // return a new Encrypter instance.
            return new Encrypter($key, $cipher);
        });
    }

    /**
     * Check if a given cipher is supported by this library.
     *
     * @param string $cipher
     *
     * @return bool
     */
    protected function supported(string $cipher) : bool
    {
        return array_has(Encrypter::getCiphers(), $cipher);
    }

    /**
     * Extract a configuration value.
     *
     * @param string $key
     * @param mixed|string|null $default
     *
     * @return mixed|string|null
     */
    protected function getConfigValue(string $key, $default = null)
    {
        // get the config repository.
        /** @var Config $config */
        $config = $this->app->make('config');

        // retrieve the value for the given key.
        $value = $config->get($key, $default);

        // when the value is a string and it's value starts with base64:
        if (is_string($value) && Str::startsWith($value, 'base64:')) {
            $value = base64_decode(substr($value, 7));
        }

        // retrieve the value for the key,
        return $value;
    }
}