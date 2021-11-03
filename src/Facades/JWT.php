<?php

namespace Jiaxincui\JWTAuth\Facades;

use Illuminate\Support\Facades\Facade;
use Jiaxincui\JWTAuth\Manager;

class JWT extends Facade
{

    protected static function getFacadeAccessor()
    {
        return Manager::class;
    }
}
