<?php

namespace tests\Evaneos\JWT\Silex\Provider;

use Evaneos\JWT\JWTRetrieval\AuthorizationBearerStrategy;
use Evaneos\JWT\JWTRetrieval\ChainStrategy;
use Evaneos\JWT\JWTRetrieval\QueryParameterStrategy;
use Evaneos\JWT\SymfonySecurity\JWTListener;
use Evaneos\JWT\Silex\Provider\SecurityJWTServiceProvider;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Silex\Application;
use Silex\Provider\SecurityServiceProvider;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Client;

class SecurityJWTServiceProviderTest extends TestCase
{
    /**
     * @var Application
     */
    private $app;

    protected function setUp()
    {
        $this->app = new Application(['debug' => 'true']);

        $this->app->get('/', function () {
            return new Response('', 200);
        });
    }

    private function register($strategy = null)
    {
        $options = [
            'security.firewalls' => [
                'all' => [
                    'stateless' => true,
                    'pattern' => '^.*$',
                    'jwt' => [
                        'secret_key' => 'secret',
                        'allowed_algorithms' => ['HS256'],
                    ],
                ],
            ],
        ];

        if ($strategy !== null) {
            $options['security.firewalls']['all']['jwt']['retrieval_strategy'] = $strategy;
        }

        $this->app->register(new SecurityServiceProvider(), $options);
        $this->app->register(new SecurityJWTServiceProvider());
    }

    public function testReturns401IffNoToken()
    {
        $this->register('chain');

        $client = new Client($this->app);
        $client->request('GET', '/');

        $response = $client->getResponse();

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testReturns401IfInvalidToken()
    {
        $this->register('chain');

        $client = new Client($this->app);
        $client->request('GET', '/?jwt=thisIsAnInvalidToken');

        $response = $client->getResponse();

        $this->assertEquals(401, $response->getStatusCode());
    }


    public function testDoesNotReturn401IfValidToken()
    {
        $this->register('chain');

        $jwt = JWT::encode(['sub' => 'John'], 'secret', 'HS256');

        $client = new Client($this->app);
        $client->request('GET', '/?jwt=' . $jwt);

        $response = $client->getResponse();

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testChainRetrievalStrategyService()
    {
        $this->register();

        $strategy = $this->app->offsetGet('security.jwt_retrieval.chain.strategy');
        $this->assertInstanceOf(ChainStrategy::class, $strategy);

        $expected = new ChainStrategy([
            new AuthorizationBearerStrategy(),
            new QueryParameterStrategy(),
        ]);

        $this->assertEquals($expected, $strategy);
    }

    public function testAuthorizationBearerRetrievalStrategyService()
    {
        $this->register();

        $strategy = $this->app->offsetGet('security.jwt_retrieval.authorization_bearer.strategy');
        $this->assertInstanceOf(AuthorizationBearerStrategy::class, $strategy);
    }

    public function testQueryParameterRetrievalStrategyService()
    {
        $this->register();

        $strategy = $this->app->offsetGet('security.jwt_retrieval.query_parameter.strategy');
        $this->assertInstanceOf(QueryParameterStrategy::class, $strategy);
    }

    public function testJWTListenerService()
    {
        $this->register();
        $this->app->boot();

        $jwtListener = $this->app->offsetGet('security.authentication_listener.all.jwt');
        $this->assertInstanceOf(JWTListener::class, $jwtListener);
    }
}
