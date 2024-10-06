<?php

namespace Jiaxincui\JWTAuth;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Jiaxincui\JWTAuth\Console\MakeRSAKeyCommand;
use Jiaxincui\JWTAuth\JWTAuth;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class JWTAuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        if ($this->app->runningInConsole()) {

            $this->publishes([
                __DIR__ . '/../config/jwtauth.php' => config_path('jwtauth.php')
            ], 'jwtauth');

            $this->commands([
                MakeRSAKeyCommand::class,
            ]);
        }

        Auth::viaRequest('jwt', function ($request) {
            return $this->app->make('jwtauth')->user($request);
        });
    }

    public function register()
    {
        $this->app->singleton('jwtauth', function ($app) {
            $config = $app['config'];
            $jwtConfig = Configuration::forAsymmetricSigner(
                new Sha256(),
                InMemory::file($config->get('jwtauth.key.private')),
                InMemory::file($config->get('jwtauth.key.public'))
            );
            $userMapper = $config->get('jwtauth.user_mapper');
            if (class_exists($userMapper)) {
                $userMapper = new $userMapper;
            }
            $userMapper = $userMapper instanceof UserMapper ? $userMapper : new GenericUserMapper;
            return new JWTAuth($jwtConfig, $config, $userMapper);
        });
    }
}
