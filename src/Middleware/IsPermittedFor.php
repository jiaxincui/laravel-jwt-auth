<?php

namespace Jiaxincui\JWTAuth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Jiaxincui\JWTAuth\JWTAuth;
use Jiaxincui\JWTAuth\Exceptions\JWTException;

class IsPermittedFor
{
    protected $jwt;

    /**
     * Create a new bindings substitutor.
     *
     * @return void
     */
    public function __construct(JWTAuth $jwt)
    {
        $this->jwt = $jwt;
    }

    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure $next
     * @param $audience
     * @return mixed
     * @throws JWTException
     */
    public function handle(Request $request, Closure $next, $audience)
    {
        $token = $this->jwt->validatedToken($request);
        if (is_null($token) || !$token->isPermittedFor($audience)) {
            throw new JWTException('The token is not allowed to be used by this audience', 403);
        }
        return $next($request);
    }
}
