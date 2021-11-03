<?php

namespace Jiaxincui\JWTAuth\Facades;

use Illuminate\Support\Facades\Facade;
use Jiaxincui\JWTAuth\Manager;

class JWT extends Facade
{

    /**
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return Manager::class;
    }
}
