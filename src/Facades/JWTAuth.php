<?php

namespace Jiaxincui\JWTAuth\Facades;

use Illuminate\Support\Facades\Facade;
use Jiaxincui\JWTAuth\Manager;

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
