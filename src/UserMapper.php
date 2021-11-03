<?php

namespace Jiaxincui\JWTAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Token\DataSet;

interface UserMapper
{
    /**
     * @param DataSet $claims
     * @return Authenticatable
     */
    public function user(DataSet $claims): Authenticatable;
}
