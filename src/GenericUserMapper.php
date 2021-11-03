<?php

namespace Jiaxincui\JWTAuth;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Token\DataSet;

class GenericUserMapper implements UserMapper
{
    /**
     * @param DataSet $claims
     * @return Authenticatable
     */
    public function user(DataSet $claims): Authenticatable
    {
        return new GenericUser([
            'id' => $claims->get('sub')
        ]);
    }
}
