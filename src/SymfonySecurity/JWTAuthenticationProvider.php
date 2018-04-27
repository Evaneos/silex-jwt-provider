<?php

namespace Evaneos\JWT\SymfonySecurity;

use Evaneos\JWT\Util\JWTDecodeUnexpectedValueException;
use Evaneos\JWT\Util\JWTUserBuilder;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class JWTAuthenticationProvider implements AuthenticationProviderInterface
{
    /**
     * @var JWTUserBuilder
     */
    private $userBuilder;

    /**
     * Constructor.
     *
     * @param JWTUserBuilder $userBuilder
     */
    public function __construct(JWTUserBuilder $userBuilder)
    {
        $this->userBuilder = $userBuilder;
    }

    /**
     * Attempts to authenticate a TokenInterface object.
     *
     * @param TokenInterface $token The TokenInterface instance to authenticate
     *
     * @throws AuthenticationException if the authentication fails
     * @return TokenInterface An authenticated TokenInterface instance, never null
     *
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$token instanceof JWTToken) {
            throw new AuthenticationException(sprintf('%s works only for JWTToken', __CLASS__));
        }

        if (!$token->getCredentials()) {
            throw new AuthenticationException('JWTToken must contain a token in order to authenticate.');
        }

        try {
            $user = $this->userBuilder->buildUserFromToken($token->getCredentials());
        } catch (JWTDecodeUnexpectedValueException $e) {
            throw new AuthenticationException('Failed to decode the JWT', 0, $e);
        }

        $token->setUser($user);

        return $token;
    }

    /**
     * Checks whether this provider supports the given token.
     *
     * @param TokenInterface $token A TokenInterface instance
     *
     * @return bool true if the implementation supports the Token, false otherwise
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof JWTToken;
    }
}
