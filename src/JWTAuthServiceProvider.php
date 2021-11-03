<?php

namespace Jiaxincui\JWTAuth;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Jiaxincui\JWTAuth\Console\MakeRSAKeyCommand;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class JWTAuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        if ($this->app->runningInConsole()) {

            $this->publishes([
                __DIR__ . '/../config/jwt-auth.php' => config_path('jwt-auth.php')
            ], 'jwt-auth');

            $this->commands([
                MakeRSAKeyCommand::class,
            ]);
        }

        Auth::viaRequest('jwt', function ($request) {
            return $this->app->make(Manager::class)->getUser($request);
        });
    }

    public function register()
    {
        $this->app->singleton(Manager::class, function ($app) {
             return new Manager(Configuration::forUnsecuredSigner(), new Sha256(), $app['config']);
        });
    }
}
