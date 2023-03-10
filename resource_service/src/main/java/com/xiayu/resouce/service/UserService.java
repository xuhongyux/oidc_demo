package com.xiayu.resouce.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;

/**
 * @author xiayu
 */
@Service
public class UserService {

    public Map<String, Object> getUserClaims() {
        Authentication authentication = SecurityContextHolder.getContext()
            .getAuthentication();
        if (authentication.getPrincipal() instanceof DefaultOidcUser) {
            OidcUser principal = ((OidcUser) authentication.getPrincipal());
            return principal.getClaims();
        }
        if (authentication.getPrincipal() instanceof DefaultOAuth2User) {
            DefaultOAuth2User principal = ((DefaultOAuth2User) authentication.getPrincipal());
            return principal.getAttributes();
        }
        return Collections.emptyMap();
    }
}
