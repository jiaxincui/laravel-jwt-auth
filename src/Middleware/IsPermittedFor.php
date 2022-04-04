<?php

namespace Jiaxincui\JWTAuth\Middleware;

use Closure;
use Jiaxincui\JWTAuth\Manager;
use Jiaxincui\JWTAuth\Exceptions\JWTException;

class IsPermittedFor
{
    protected $jwt;

    /**
     * Create a new bindings substitutor.
     *
     * @return void
     */
    public function __construct(Manager $jwt)
    {
        $this->jwt = $jwt;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next, $audience)
    {
        $token = $this->jwt->validatedToken($request);
        if (is_null($token) || !$token->isPermittedFor($audience)) {
            throw new JWTException('The token is not allowed to be used by this audience', 403);
        }
        return $next($request);
    }
}
