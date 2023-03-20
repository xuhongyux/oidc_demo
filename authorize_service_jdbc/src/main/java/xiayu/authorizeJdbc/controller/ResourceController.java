package xiayu.authorizeJdbc.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/oauth/userinfo")
    public CustomerUserDetails user(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CustomerUserDetails principal = (CustomerUserDetails) authentication.getPrincipal();
        return principal;
    }
}
