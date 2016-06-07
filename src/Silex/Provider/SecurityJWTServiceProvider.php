<?php

namespace Evaneos\JWT\Silex\Provider;

use Evaneos\JWT\JWTRetrieval\AuthorizationBearerStrategy;
use Evaneos\JWT\JWTRetrieval\ChainStrategy;
use Evaneos\JWT\JWTRetrieval\QueryParameterStrategy;
use Evaneos\JWT\SymfonySecurity\JWTAuthenticationEntryPoint;
use Evaneos\JWT\SymfonySecurity\JWTAuthenticationProvider;
use Evaneos\JWT\SymfonySecurity\JWTListener;
use Evaneos\JWT\Util\JWTDecoder;
use Evaneos\JWT\Util\JWTEncoder;
use Evaneos\JWT\Util\JWTUserBuilder;
use Evaneos\JWT\Util\SecurityUserConverter;
use Silex\Application;
use Silex\ServiceProviderInterface;

class SecurityJWTServiceProvider implements ServiceProviderInterface
{
    /**
     * Registers services on the given app.
     *
     * This method should only be used to configure services and parameters.
     * It should not get services.
     */
    public function register(Application $app)
    {
        $app['security.jwt_retrieval.authorization_bearer.strategy'] = $app->share(function () {
            return new AuthorizationBearerStrategy();
        });

        $app['security.jwt_retrieval.query_parameter.strategy'] = $app->share(function () {
            return new QueryParameterStrategy();
        });

        $app['security.jwt_retrieval.chain.strategy'] = $app->share(function () use ($app) {
            return new ChainStrategy([
                $app['security.jwt_retrieval.authorization_bearer.strategy'],
                $app['security.jwt_retrieval.query_parameter.strategy'],
            ]);
        });

        $app['security.entry_point.jwt._proto'] = $app->protect(function () use ($app) {
            return $app->share(function () {
                return new JWTAuthenticationEntryPoint();
            });
        });

        $app['security.authentication_listener.factory.jwt'] = $app->protect(function ($name, $options) use ($app) {

            $app['security.authentication_provider.' . $name . '.jwt'] = $app->share(function () use ($app, $options) {
                $encoder = new JWTEncoder($options['secret_key'], reset($options['allowed_algorithms']));
                $decoder = new JWTDecoder($options['secret_key'], $options['allowed_algorithms']);
                $converter = new SecurityUserConverter();
                $userBuilder = new JWTUserBuilder($decoder, $encoder, $converter);

                return new JWTAuthenticationProvider($userBuilder);
            });

            $app['security.authentication_listener.' . $name . '.jwt'] = $app->share(function () use ($app, $name, $options) {
                $strategyName = isset($options['retrieval_strategy'])
                    ? $options['retrieval_strategy']
                    : 'authorization_bearer';

                return new JWTListener(
                    $app['security.token_storage'],
                    $app['security.authentication_manager'],
                    $app['security.jwt_retrieval.' . $strategyName . '.strategy']
                );
            });

            $app['security.entry_point.' . $name . '.jwt'] = $app['security.entry_point.jwt._proto']($name, $options);

            return array(
                'security.authentication_provider.' . $name . '.jwt',
                'security.authentication_listener.' . $name . '.jwt',
                'security.entry_point.' . $name . '.jwt',
                'pre_auth',
            );
        });
    }

    /**
     * Bootstraps the application.
     *
     * This method is called after all services are registered
     * and should be used for "dynamic" configuration (whenever
     * a service must be requested).
     */
    public function boot(Application $app)
    {
    }
}
