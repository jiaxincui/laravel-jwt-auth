<?php

namespace Jiaxincui\JWTAuth;

use Lcobucci\JWT\Token\DataSet;

interface UserMapper
{
    public function user(DataSet $claims);
}
