<?php

namespace Jiaxincui\JWTAuth\Facades;

use Illuminate\Support\Facades\Facade;

class JWTAuth extends Facade
{

    /**
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'jwtauth';
    }
}
