# Silex JWT Provider
Silex provider for JWT

[![Build Status](https://secure.travis-ci.org/Evaneos/silex-jwt-provider.png?branch=master)](http://travis-ci.org/Evaneos/silex-jwt-provider)

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
