# Silex JWT Provider

Silex provider for JWT.

## :warning: Deprecation notice

Silex has reached its end of life in June 2018 [[ref](https://symfony.com/blog/the-end-of-silex)].

We will only maintain this package for internal use only. Contributions are no longer accepted.

You are encouraged to use Symfony 4+ and alternatives like [lexik/LexikJWTAuthenticationBundle](https://github.com/lexik/LexikJWTAuthenticationBundle) or a [custom authenticator](https://symfony.com/doc/current/security/authenticator_manager.html).

## Usage

```php
<?php
  
use Evaneos\JWT\Silex\Provider\SecurityJWTServiceProvider;
use Silex\Provider\SecurityServiceProvider;
  
$app->register(new SecurityServiceProvider(), [
    'security.firewalls' => [
        'all' => [
            'stateless' => true,
            'pattern' => '^.*$',
            'jwt' => [
                'secret_key' => 'secret',
                'allowed_algorithms' => ['HS256'],
                'retrieval_strategy' => 'chain',
            ],
        ],
    ],
]);
  
$app->register(new SecurityJWTServiceProvider());
```
