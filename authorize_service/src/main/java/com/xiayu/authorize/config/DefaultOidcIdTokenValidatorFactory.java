package com.xiayu.authorize.config;

import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;

import java.util.function.Function;

/**
 * @author xuhongyu
 * @create 2023-03-08 15:23
 */
public class DefaultOidcIdTokenValidatorFactory implements Function<ClientRegistration, OAuth2TokenValidator<Jwt>> {

    @Override
    public OAuth2TokenValidator<Jwt> apply(ClientRegistration clientRegistration) {
        return new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(),
                new OidcIdTokenValidator(clientRegistration));
    }

}
