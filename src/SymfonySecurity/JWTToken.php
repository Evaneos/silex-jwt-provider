<?php

namespace Evaneos\JWT\SymfonySecurity;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class JWTToken extends AbstractToken
{
    /** @var string */
    private $token;

    /**
     * Returns the user credentials.
     *
     * @return mixed The user credentials
     */
    public function getCredentials()
    {
        return $this->token;
    }

    /**
     * @param string $token
     */
    public function setToken($token)
    {
        $this->token = $token;
    }
}
