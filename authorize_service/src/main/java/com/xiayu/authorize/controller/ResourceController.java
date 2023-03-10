package com.xiayu.authorize.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/oauth/userinfo")
    public UserInfoRes user(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return new UserInfoRes(authentication.getName(),  "hongyu@foxmail.com");
    }
}
