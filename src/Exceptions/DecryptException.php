<?php

namespace LaravelAEAD\Exceptions;

use Illuminate\Contracts\Encryption\DecryptException as LaravelDecryptException;

/**
 * Class DecryptException.
 *
 * Generic exception for decryption errors.
 */
class DecryptException extends LaravelDecryptException
{
    //
}