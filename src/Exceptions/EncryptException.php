<?php

namespace LaravelAEAD\Exceptions;

use Illuminate\Contracts\Encryption\EncryptException as LaravelEncryptException;

/**
 * Class EncryptException.
 *
 * Generic exception for encryption errors.
 */
class EncryptException extends LaravelEncryptException
{
    //
}