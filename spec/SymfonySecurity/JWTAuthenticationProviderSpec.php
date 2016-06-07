<?php

namespace spec\Evaneos\JWT\SymfonySecurity;

use Evaneos\JWT\SymfonySecurity\JWTAuthenticationProvider;
use Evaneos\JWT\SymfonySecurity\JWTToken;
use Evaneos\JWT\Util\JWTUserBuilder;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class JWTAuthenticationProviderSpec extends ObjectBehavior
{
    function let(JWTUserBuilder $JWTUserBuilder)
    {
        $this->beConstructedWith($JWTUserBuilder);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(JWTAuthenticationProvider::class);
    }

    function it_implements_AuthenticationProviderInterface()
    {
        $this->shouldImplement(AuthenticationProviderInterface::class);
    }

    function it_supports_JWTToken()
    {
        $this->supports(new JWTToken())->shouldReturn(true);
    }

    function it_doesnt_support_a_random_TokenInterface(TokenInterface $token)
    {
        $this->supports($token)->shouldReturn(false);
    }

    function it_throws_an_AuthenticationException_the_JWTToken_doesnt_contain_credentials()
    {
        $jwtToken = new JWTToken();
        $this->shouldThrow(AuthenticationException::class)->during('authenticate', [$jwtToken]);
    }

    function it_throws_an_AuthenticationException_if_passed_token_is_not_a_JWTToken(TokenInterface $token)
    {
        $this->shouldThrow(AuthenticationException::class)->during('authenticate', [$token]);
    }

    function it_throws_an_AuthenticationException_if_buildUserFromToken_fails(TokenInterface $token, JWTUserBuilder $JWTUserBuilder)
    {
        $JWTUserBuilder->buildUserFromToken(Argument::any())->willThrow(\Exception::class);

        $this->shouldThrow(AuthenticationException::class)->duringAuthenticate($token);
    }

    function it_enriches_the_JWTToken_with_the_user_returned_by_user_convert(JWTUserBuilder $JWTUserBuilder, JWTToken $jwtToken)
    {
        $jwtToken->getCredentials()->willReturn('credentials');

        $JWTUserBuilder->buildUserFromToken('credentials')->willReturn('user');

        $jwtToken->setUser('user')->shouldBeCalled();

        $this->authenticate($jwtToken);
    }

    function it_returns_the_provided_JWTToken(JWTUserBuilder $JWTUserBuilder)
    {
        $jwtToken = new JWTToken();
        $jwtToken->setToken('JWTToken');

        $JWTUserBuilder->buildUserFromToken('JWTToken')->willReturn('AUser');

        $this->authenticate($jwtToken)->shouldReturn($jwtToken);
    }
}
