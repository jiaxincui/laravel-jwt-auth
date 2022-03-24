## RSA JWT auth package for laravel

### Install

#### composer install

`composer require jiaxincui/laravel-jwt-auth`

In your `config/app.php` add `Jiaxincui\JWTAuth\JWTAuthServiceProvider::class` to the end of the providers array:

```
'providers' => [
    ...
    Jiaxincui\JWTAuth\JWTAuthServiceProvider::class,
],

```

Publish Configuration

`php artisan vendor:publish --provider "Jiaxincui\JWTAuth\JWTAuthServiceProvider"`

###
