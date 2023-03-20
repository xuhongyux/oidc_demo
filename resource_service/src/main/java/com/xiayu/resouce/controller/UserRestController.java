package com.xiayu.resouce.controller;

import com.xiayu.resouce.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserRestController {

    private UserService service;

    public UserRestController(UserService service) {
        this.service = service;
    }


    @GetMapping("/principal")
    public String currentUserName(Principal principal) {
        return principal.getName();
    }

    @GetMapping("/oidc-principal")
    public OidcUser getOidcUserPrincipal(@AuthenticationPrincipal OidcUser principal) {
        return principal;
    }

    @GetMapping("/oidc-claims")
    public Map<String, Object> getClaimsFromBean() {
        return service.getUserClaims();
    }

    @GetMapping("/userInfo")
    public String index(Model model,
                        @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
                        @AuthenticationPrincipal OAuth2User oauth2User,
                        Authentication authentication) {
        model.addAttribute("userName", oauth2User.getName());
        model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
        model.addAttribute("userAttributes", oauth2User.getAttributes());
        authentication.isAuthenticated();
        return model.toString();
    }


    @GetMapping("/{name}")
    public String helloWorld(@PathVariable String name) {
        return "hello" + name + "!";
    }


    @PostMapping("/helloWorldPost")
    public String helloWorldPost() {
        return "hello" + "name" + "!";
    }
}
