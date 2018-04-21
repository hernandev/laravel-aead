# LaravelAEAD.

**LaravelAEAD** is a library which provides *Advanced Encryption with Associated Data* (AEAD) for Laravel.

## Abstract:
This package replaces, when installed and enabled, the default encryption implementation of Laravel, which currently supports only two variants of the same block cipher, `AES-128-CBC` and `AES-256-CBC`.

The reason for only having two options is probably based on PHP history itself, like the (not so much) rececent depreciation of MCrypt.

As of PHP 7.2, we can now count on the exceptional `libsodium` extension, with supports the most secure AEAD construtions and it's variants.

AEAD stands for Advanced Encryption, with Associated Data, and they are algorithms which combine a **stream cipher** with a **message authentication** code (MAC).

The result of such combination is a encryption scheme with provides three aspects that are useful for modern applications:
- Confidentiality
- Integrity
- Authenticity

For more information on AEAD, I highly recommend [reading the libsodium documentation](https://download.libsodium.org/doc/secret-key_cryptography/aead.html), which states the main parts, but, reading the construction IETF RFC's is also something interesting if you care for security.

## Available Constructions.

Those are the libsodium AEAD constructors, and they respective key for usage with this package.

| AEAD Cipher / Contruction | Key Size  | Nonce Size  | Config Key (config/app.php) 
| -                         | -         | -           | - 
| XChaCha20-Poly1305-IEFT   | 256 bits  | 192 bits    | 'XCHACHA20-POLY1305-IEFT'
| ChaCha20-Poly1305-IEFT    | 256 bits  | 96 bits     | 'CHACHA20-POLY1305-IEFT'
| ChaCha20-Poly1305         | 256 bits  | 64 bits     | 'CHACHA20-POLY1305'
| AES-256-GCM               | 256 bits  | 96 bits     | 'AES-256-GCM'

## Installing & Configuring.

Installing the Library.

```php
composer require hernandev/laravel-aead
```

Changing the authentication provider (on config/app.php):

```php
    // YOU MUST COMMENT OUT THE DEFAULT ENCRYPTION CLASS>
    // Illuminate\Encryption\EncryptionServiceProvider::class,
    // THIS ONE SHOULD BE USED INSTEAD.
    LaravelAEAD\Providers\EncryptionServiceProvider::class,
```

Configuring the cipher (also on config/app.php):

```php
    'cipher' => 'XCHACHA20-POLY1305-IETF',
```

## Usage.

After doing this install, all default Laravel encryption will be performed under the relative constructions / ciphers.

Meaning if you use `encrypt()` and `decrypt()`, they will use this package instead of the default encryption.

It also means that cookies & session, that should be encrypted, will use it.

