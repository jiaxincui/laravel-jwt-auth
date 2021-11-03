<?php

namespace Jiaxincui\JWTAuth;

use DateInterval;
use DateTimeImmutable;
use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Jiaxincui\JWTAuth\Exceptions\JWTException;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

class Manager
{
    /**
     * @var Configuration
     */
    protected Configuration $jwtConfig;
    /**
     * @var Repository
     */
    protected Repository $config;
    /**
     * @var Signer
     */
    protected Signer $signer;
    /**
     * @var UserMapper
     */
    protected UserMapper $userMapper;
    /**
     * @var Key
     */
    protected Key $verificationKey;
    /**
     * @var Key
     */
    protected Key $signingKey;
    /**
     * @var Builder
     */
    protected Builder $builder;
    /**
     * @var array
     */
    protected array $staticConstraints;
    /**
     * @var UnencryptedToken
     */
    protected UnencryptedToken $token;

    /**
     * @param Configuration $jwtConfig
     * @param Signer $signer
     * @param Repository $config
     */
    public function __construct(Configuration $jwtConfig, Signer $signer, Repository $config)
    {
        $this->jwtConfig = $jwtConfig;
        $this->signer = $signer;
        $this->config = $config;
    }

    /**
     * @return Configuration
     */
    public function getJwtConfig(): Configuration
    {
        return $this->jwtConfig;
    }

    /**
     * @param Configuration $jwtConfig
     */
    public function setJwtConfig(Configuration $jwtConfig): void
    {
        $this->jwtConfig = $jwtConfig;
    }

    /**
     * @return Repository
     */
    public function getConfig(): Repository
    {
        return $this->config;
    }

    /**
     * @param Repository $config
     */
    public function setConfig(Repository $config): void
    {
        $this->config = $config;
    }

    /**
     * @return Signer
     */
    public function getSigner(): Signer
    {
        return $this->signer;
    }

    /**
     * @param Signer $signer
     */
    public function setSigner(Signer $signer): void
    {
        $this->signer = $signer;
    }

    /**
     * @return Key
     */
    public function getSigningKey(): Key
    {
        if (!isset($this->signingKey)) {
            $this->signingKey = InMemory::file($this->config->get('jwt-auth.key.private'));
        }
        return $this->signingKey;
    }

    /**
     * @param Key $signingKey
     */
    public function setSigningKey(Key $signingKey): void
    {
        $this->signingKey = $signingKey;
    }


    /**
     * @return GenericUserMapper|UserMapper
     */
    public function getUserMapper()
    {
        if (!isset($this->userMapper)) {
            $userMapper = $this->config->get('jwt-auth.user_mapper');
            if (class_exists($userMapper)) {
                $userMapper = new $userMapper;
            }
            $this->userMapper = $userMapper instanceof UserMapper ? $userMapper : new GenericUserMapper;
        }

        return $this->userMapper;
    }

    /**
     * @param UserMapper $userMapper
     */
    public function setUserMapper(UserMapper $userMapper)
    {
        $this->userMapper = $userMapper;
    }

    /**
     * @return Builder
     */
    public function getBuilder(): Builder
    {
        return $this->builder;
    }

    /**
     * @throws Exception
     */
    protected function newBuilder(): Builder
    {
        $builder = $this->getJwtConfig()->builder();

        $iss = $this->config->get('jwt-auth.issue_by') ?: $this->config->get('app.url');
        $jti = Str::random();
        $iat = new DateTimeImmutable();
        $exp = $iat->add(new DateInterval('PT' . $this->config->get('jwt-auth.expire', 300) . 'S'));

        $builder
            ->issuedBy($iss)
            ->identifiedBy($jti)
            ->issuedAt($iat)
            ->expiresAt($exp);

        return $builder;
    }

    /**
     * @return Key|InMemory
     */
    public function getVerificationKey(): Key
    {
        if (!isset($this->verificationKey)) {
            $this->verificationKey = InMemory::file($this->config->get('jwt-auth.key.public'));
        }
        return $this->verificationKey;
    }

    /**
     * @return array
     */
    public function getConstrains(): array
    {
        if (empty($this->staticConstraints)) {
            $constraints[] = new SignedWith($this->signer, $this->getVerificationKey());

            if ($permittedFor = $this->config->get('jwt-auth.permitted')) {
                $constraints[] = new PermittedFor($permittedFor);
            }

            $this->staticConstraints = $constraints;
        }
        return $this->staticConstraints;
    }

    /**
     * @param string $bearerToken
     * @return UnencryptedToken
     */
    public function parse(string $bearerToken): UnencryptedToken
    {
        return $this->getJwtConfig()->parser()->parse($bearerToken);
    }

    /**
     * @throws Exception
     */
    public function forSubject(JWTSubject $subject): Manager
    {
        $builder = $this->newBuilder();

        $builder->relatedTo($subject->getJWTIdentifier());

        $customClaims = $subject->getJWTCustomClaims();

        foreach ($customClaims as $key => $value) {
            $builder->withClaim($key, $value);
        }

        $this->builder = $builder;

        return $this;
    }

    /**
     * @throws Exception
     */
    public function forUser(JWTSubject $user): Manager
    {
        return $this->forSubject($user);
    }

    /**
     * @throws JWTException
     */
    public function getToken(): UnencryptedToken
    {
        if (!isset($this->builder)) {
            throw new JWTException('None Builder');
        }
        return $this->builder->getToken($this->getSigner(), $this->getSigningKey());
    }

    /**
     * @param Request $request
     * @return UnencryptedToken|null
     */
    protected function validatedToken(Request $request): ?UnencryptedToken
    {
        if (is_null($request->bearerToken())) {
            return null;
        }

        try {
            $token = $this->parse($request->bearerToken());
        } catch (Exception $e) {
            return null;
        }

        $now = new SystemClock(new \DateTimeZone($this->config->get('app.timezone')));
        $constraints = $this->getConstrains();

        $constraints[] = new LooseValidAt($now);

        if (($token instanceof UnencryptedToken) &&
            $this->jwtConfig->validator()->validate($token, ...$constraints)
        ) {
            return $this->token = $token;
        }

        return null;
    }

    /**
     * @param Request $request
     * @return Authenticatable|null
     */
    public function getUser(Request $request): ?Authenticatable
    {
        $userMapper = $this->getUserMapper();
        if (isset($this->token)) {
            return $userMapper->user($this->token->claims());
        }
        if (!is_null($token = $this->validatedToken($request))) {
            return $userMapper->user($token->claims());
        }

        return null;
    }

    /**
     * @param $method
     * @param $args
     * @return $this
     */
    public function __call($method, $args)
    {
        if (
            isset($this->builder)
            && in_array($method, ['permittedFor', 'expiresAt', 'identifiedBy', 'issuedAt', 'issuedBy', 'canOnlyBeUsedAfter', 'relatedTo', 'withHeader', 'withClaim'])
        ) {
            $this->builder->$method(...$args);
            return $this;
        }
        throw new \BadMethodCallException(sprintf(
            'Call to undefined method %s()',
            $method
        ));
    }
}
