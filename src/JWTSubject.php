<?php

namespace Jiaxincui\JWTAuth;

interface JWTSubject
{
    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return int|string
     */
    public function getJWTIdentifier(): int|string;

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims(): array;
}
