<?php

namespace spec\Evaneos\JWT\SymfonySecurity;

use Evaneos\JWT\JWTRetrieval\JWTNotFoundException;
use Evaneos\JWT\JWTRetrieval\JWTRetrievalStrategyInterface;
use Evaneos\JWT\SymfonySecurity\JWTToken;
use Evaneos\JWT\SymfonySecurity\JWTListener;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class JWTListenerSpec extends ObjectBehavior
{
    function let(AuthenticationManagerInterface $authenticationManager, TokenStorageInterface $tokenStorage, JWTRetrievalStrategyInterface $jwtRetrievalStrategy)
    {
        $this->beConstructedWith($tokenStorage, $authenticationManager, $jwtRetrievalStrategy);
    }
    function it_is_initializable()
    {
        $this->shouldHaveType(JWTListener::class);
    }

    function it_implements_ListenerInterface()
    {
        $this->shouldImplement(ListenerInterface::class);
    }

    function it_doesnt_authenticate_if_no_token_is_found(
        AuthenticationManagerInterface $authenticationManager,
        JWTRetrievalStrategyInterface $jwtRetrievalStrategy,
        GetResponseEvent $event
    ) {
        $request = new Request();
        $event->getRequest()->willReturn($request);

        $jwtRetrievalStrategy->getToken($request)->willThrow(JWTNotFoundException::class);

        $this->handle($event);
        $authenticationManager->authenticate(Argument::any())->shouldNotBeCalled();
    }

    function it_authenticates_if_a_token_is_found(
        AuthenticationManagerInterface $authenticationManager,
        JWTRetrievalStrategyInterface $jwtRetrievalStrategy,
        GetResponseEvent $event
    ) {
        $request = new Request();
        $event->getRequest()->willReturn($request);

        $jwtRetrievalStrategy->getToken($request)->willReturn('JWTToken');

        $jwtToken = new JWTToken();
        $jwtToken->setToken('JWTToken');

        $this->handle($event);
        $authenticationManager->authenticate($jwtToken)->shouldBeCalled();
    }

    function it_stores_the_token_returned_by_AuthenticationManager(
        AuthenticationManagerInterface $authenticationManager,
        TokenStorageInterface $tokenStorage,
        GetResponseEvent $event
    ) {
        $request = new Request();
        $event->getRequest()->willReturn($request);

        $authToken = new JWTToken();

        $authenticationManager->authenticate(Argument::any())->willReturn($authToken);

        $this->handle($event);
        $tokenStorage->setToken($authToken)->shouldBeCalled();
    }
}
