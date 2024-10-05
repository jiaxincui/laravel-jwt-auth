<?php

namespace Jiaxincui\JWTAuth;

use DateInterval;
use DateTimeImmutable;
use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Psr\Clock\ClockInterface;

class JWTAuth
{
    protected Configuration $jwtConfig;
    protected Repository $config;
    protected UserMapper $userMapper;
    protected ?UnencryptedToken $token;

    public function __construct(Configuration $configuration, Repository $config, UserMapper $userMapper)
    {
        $this->jwtConfig = $configuration;
        $this->config = $config;
        $this->userMapper = $userMapper;
        $this->token = null;
    }

    /**
     * @param JWTSubject $subject
     * @return UnencryptedToken
     * @throws Exception
     */
    public function forSubject(JWTSubject $subject): UnencryptedToken
    {
        $builder = $this->jwtConfig->builder();

        $iss = $this->config->get('jwtauth.issue_by') ?: $this->config->get('app.url');
        $jti = Str::random();
        $iat = new DateTimeImmutable();
        $exp = $iat->add(new DateInterval('PT' . $this->config->get('jwtauth.access_token_ttl', 300) . 'S'));

        $builder
            ->issuedBy($iss)
            ->identifiedBy($jti)
            ->relatedTo($subject->getJWTIdentifier())
            ->issuedAt($iat)
            ->expiresAt($exp);

        $customClaims = $subject->getJWTCustomClaims();

        foreach ($customClaims as $key => $value) {
            $builder->withClaim($key, $value);
        }

        return $builder->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());
    }

    public function user(Request $request): ?Authenticatable
    {
        $userMapper = $this->userMapper;
        $token = $this->validatedToken($request);
        return $token ? $userMapper->user($token->claims()) : null;
    }

    /**
     * @param Request $request
     * @return UnencryptedToken|null
     */
    public function validatedToken(Request $request): ?UnencryptedToken
    {
        if (!is_null($this->token)) {
            return $this->token;
        }

        if (is_null($request->bearerToken())) {
            return null;
        }

        try {
            $token = $this->jwtConfig->parser()->parse($request->bearerToken());
        } catch (CannotDecodeContent|InvalidTokenStructure|UnsupportedHeaderFound $e) {
            return null;
        }

        if (empty($this->jwtConfig->validationConstraints())) {
            $this->jwtConfig->setValidationConstraints(
                new SignedWith($this->jwtConfig->signer(), $this->jwtConfig->verificationKey()),
                new LooseValidAt(new class implements ClockInterface {
                    public function now(): DateTimeImmutable
                    {
                        return new DateTimeImmutable();
                    }
                })
            );
        }

        if ($this->jwtConfig->validator()->validate($token, ...$this->jwtConfig->validationConstraints())) {
            return $this->token = $token;
        }
        return null;
    }

    public function getJwtConfig(): Configuration
    {
        return $this->jwtConfig;
    }

    public function setJwtConfig(Configuration $jwtConfig): void
    {
        $this->jwtConfig = $jwtConfig;
    }

    public function getConfig(): Repository
    {
        return $this->config;
    }
}