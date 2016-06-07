<?php

namespace Evaneos\JWT\SymfonySecurity;

use Evaneos\JWT\JWTRetrieval\JWTNotFoundException;
use Evaneos\JWT\JWTRetrieval\JWTRetrievalStrategyInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class JWTListener implements ListenerInterface
{
    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var AuthenticationManagerInterface
     */
    private $authenticationManager;

    /**
     * @var JWTRetrievalStrategyInterface
     */
    private $jwtRetrievalStrategy;

    /**
     * Constructor.
     *
     * @param TokenStorageInterface          $tokenStorage
     * @param AuthenticationManagerInterface $authenticationManager
     * @param JWTRetrievalStrategyInterface  $jwtRetrievalStrategy
     */
    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthenticationManagerInterface $authenticationManager,
        JWTRetrievalStrategyInterface $jwtRetrievalStrategy
    ) {
        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->jwtRetrievalStrategy = $jwtRetrievalStrategy;
    }

    /**
     * This interface must be implemented by firewall listeners.
     *
     * @param GetResponseEvent $event
     */
    public function handle(GetResponseEvent $event)
    {
        try {
            $jwtTokenValue = $this->jwtRetrievalStrategy->getToken($event->getRequest());
        } catch (JWTNotFoundException $e) {
            return;
        }

        $jwtToken = new JWTToken();
        $jwtToken->setToken($jwtTokenValue);

        $authToken = $this->authenticationManager->authenticate($jwtToken);

        $this->tokenStorage->setToken($authToken);
    }
}
